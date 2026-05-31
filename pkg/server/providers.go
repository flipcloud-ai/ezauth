package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/gorilla/mux"
	"golang.org/x/sync/singleflight"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezcache "github.com/flipcloud-ai/ezauth/pkg/cache"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	ezproviders "github.com/flipcloud-ai/ezauth/pkg/providers"
	ezdto "github.com/flipcloud-ai/ezauth/pkg/server/dto"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
)

const providerPath = "/provider"

// providerRegistry manages the lifecycle of Provider instances: in-process
// caching, lazy DB loading with singleflight coalescing, periodic sync, and
// post-write cache refresh. It is an internal implementation detail of Server.
type providerRegistry struct {
	cache        ezcache.Cache[string, ezproviders.Provider] // nil when size=0
	sfGroup      singleflight.Group
	db           database.DatabaseInterface
	sessionStore sessions.SessionStore
	logger       ezlog.Logger
	// staticCfgs is built once at construction and never mutated.
	// map key is ProviderName; used for O(1) isStatic checks and iteration.
	staticCfgs map[string]*ezcfg.ProviderConfig
	// adminGroups holds a pointer to an immutable snapshot map. Readers load
	// the pointer and read from the snapshot; writers build a new map and store
	// a fresh pointer. The map must never be mutated after Store.
	adminGroups atomic.Pointer[map[string]bool]
}

// newProviderRegistry constructs a registry. When size=0 the cache is nil and
// every resolve() call falls through to a DB+OIDC fetch (no caching).
func newProviderRegistry(
	size int,
	db database.DatabaseInterface,
	sessionStore sessions.SessionStore,
	logger ezlog.Logger,
	staticCfgs []*ezcfg.ProviderConfig,
) *providerRegistry {
	r := &providerRegistry{
		db:           db,
		sessionStore: sessionStore,
		logger:       logger,
		staticCfgs:   make(map[string]*ezcfg.ProviderConfig, len(staticCfgs)),
	}
	m := make(map[string]bool)
	for _, cfg := range staticCfgs {
		if cfg != nil {
			r.staticCfgs[cfg.ProviderName] = cfg
			if cfg.AdminGroup != "" {
				m[cfg.AdminGroup] = true
			}
		}
	}
	r.adminGroups.Store(&m)
	if size > 0 {
		// TTL=0: entries never expire automatically; managed explicitly by sync/del.
		r.cache = ezcache.NewRingCache[string, ezproviders.Provider](size, 0)
	}
	return r
}

// rebuildAdminGroups scans all cached providers and builds the admin group lookup set.
func (r *providerRegistry) rebuildAdminGroups(ctx context.Context) {
	m := make(map[string]bool)
	r.rangeAll(ctx, func(key string, p ezproviders.Provider) bool {
		if p != nil && p.Opts().AdminGroup != "" {
			m[p.Opts().AdminGroup] = true
		}
		return true
	})
	r.adminGroups.Store(&m)
}

// isStatic reports whether name is a statically configured provider.
func (r *providerRegistry) isStatic(name string) bool {
	_, ok := r.staticCfgs[name]
	return ok
}

// instantiate loads a single provider from the database and initialises it.
// Returns nil when the provider is not found, is disabled, or fails to init.
// ctx must already be detached from any request deadline before calling.
func (r *providerRegistry) instantiate(ctx context.Context, name string) ezproviders.Provider {
	cfg, err := r.db.GetProvider(ctx, name)
	if err != nil {
		if !errors.Is(err, database.ErrNoRecord) {
			r.logger.Warn("error loading provider from database", ezlog.Str("provider", name), ezlog.Err(err))
		}
		return nil
	}
	if !cfg.Enabled {
		r.logger.Debug("provider is disabled, skipping", ezlog.Str("provider", name))
		return nil
	}
	loaded, err := ezproviders.NewProvider([]*ezcfg.ProviderConfig{cfg}, r.sessionStore, ctx) //nolint:contextcheck
	if err != nil {
		r.logger.Error("error initialising provider", ezlog.Str("provider", name), ezlog.Err(err))
		return nil
	}
	p, ok := loaded[name]
	if !ok {
		return nil
	}
	return p
}

// resolve satisfies ezproviders.ResolveFunc. Cache is consulted first; on miss
// the provider is loaded from the database under a singleflight group so that
// concurrent misses for the same name share a single DB+OIDC-discovery fetch.
// Disabled providers are never returned or cached. Returns nil when the name
// is empty, the provider is disabled, or nothing is found.
func (r *providerRegistry) resolve(ctx context.Context, name string) ezproviders.Provider {
	if name == "" {
		return nil
	}

	// Fast path: cache hit.
	if r.cache != nil {
		if val, err := r.cache.Get(ctx, name); err == nil {
			r.logger.Debug("loaded provider from cache", ezlog.Str("provider", name))
			return val
		}
	}

	if r.db == nil {
		return nil
	}

	// Slow path: DB load, coalesced via singleflight.
	// WithoutCancel is applied inside the Do func so only the single executing
	// goroutine pays the allocation; the N-1 waiters share the result for free.
	type result struct{ p ezproviders.Provider }
	v, err, _ := r.sfGroup.Do(name, func() (any, error) {
		r.logger.Debug("searching provider from database", ezlog.Str("provider", name))
		p := r.instantiate(context.WithoutCancel(ctx), name)
		if p != nil && r.cache != nil {
			if err := r.cache.Set(context.WithoutCancel(ctx), name, p, 0); err != nil {
				r.logger.Error("error saving provider to cache", ezlog.Str("provider", name), ezlog.Err(err))
			}
		}
		return result{p: p}, nil
	})
	if err != nil {
		return nil
	}
	return v.(result).p
}

// get returns the provider config for name, checking the cache first then
// falling back to the database. It returns (nil, false) when not found.
// Unlike resolve() it does not use singleflight, does not check Enabled, and
// does not populate the cache (the cache holds Provider instances, not raw
// configs). It is intended for the admin GET /provider/{name} handler, which
// intentionally returns disabled providers so admins can inspect them.
func (r *providerRegistry) get(ctx context.Context, name string) (*ezcfg.ProviderConfig, bool) {
	if r.cache != nil {
		if p, err := r.cache.Get(ctx, name); err == nil {
			opts := p.Opts()
			return &opts, true
		}
	}
	if r.db == nil {
		return nil, false
	}
	cfg, err := r.db.GetProvider(ctx, name)
	if err != nil {
		if !errors.Is(err, database.ErrNoRecord) {
			r.logger.Warn("error fetching provider from database", ezlog.Str("provider", name), ezlog.Err(err))
		}
		return nil, false
	}
	return cfg, true
}

// del removes a provider from the cache. No-op when cache is nil.
func (r *providerRegistry) del(ctx context.Context, name string) error {
	if r.cache == nil {
		return nil
	}
	return r.cache.Del(ctx, name)
}

// refresh loads a provider from the database and stores it in the cache.
// It is a no-op when the provider is disabled, the cache is nil, or no DB is
// configured. It detaches from the caller's context so a client disconnect
// cannot abort the cache update after the DB write has already committed.
// Failures are logged but not propagated.
func (r *providerRegistry) refresh(ctx context.Context, name string) {
	if r.cache == nil || r.db == nil {
		return
	}
	// Detach: the DB write already succeeded; must not abandon cache update
	// just because the request client disconnected.
	detached := context.WithoutCancel(ctx)
	p := r.instantiate(detached, name)
	if p == nil {
		r.logger.Debug("provider not refreshed (disabled or not found)", ezlog.Str("provider", name))
		return
	}
	if err := r.cache.Set(detached, name, p, 0); err != nil {
		r.logger.Warn("failed to cache provider after write", ezlog.Str("provider", name), ezlog.Err(err))
	}
}

// rangeAll calls fn for every provider currently in the cache. No-op when
// the cache does not implement Ranger or is nil.
func (r *providerRegistry) rangeAll(ctx context.Context, fn func(string, ezproviders.Provider) bool) {
	if r.cache == nil {
		return
	}
	if ranger, ok := r.cache.(ezcache.Ranger[string, ezproviders.Provider]); ok {
		ranger.Range(ctx, fn)
	}
}

// sync initialises and refreshes cached provider instances from static config
// and database. On each call it:
//  1. Builds the desired set: static configs + up to (size - len(static)) from DB.
//  2. For each desired provider: adds if absent; reloads only when DB UpdatedAt
//     is newer than the cached instance, avoiding unnecessary OIDC discovery fetches.
//  3. Evicts cache entries that have disappeared from the desired set
//     (deleted/disabled in DB), while leaving static-config providers untouched.
func (r *providerRegistry) sync(ctx context.Context, size int) error {
	if r.cache == nil {
		return nil
	}

	// Build desired set starting from static configs.
	pcfgs := make([]*ezcfg.ProviderConfig, 0, len(r.staticCfgs))
	for _, cfg := range r.staticCfgs {
		pcfgs = append(pcfgs, cfg)
	}

	remaining := size - len(pcfgs)
	if r.db != nil && remaining > 0 {
		r.logger.Info("have database configuration, loading oauth providers from database")
		newpcfgs, err := r.db.ScanProviders(ctx, remaining)
		if err != nil {
			r.logger.Error("error in loading providers from database, quitting", ezlog.Err(err))
			return err
		}
		pcfgs = append(pcfgs, newpcfgs...)
	}

	if len(pcfgs) == 0 {
		return nil
	}

	// Partition: which configs need (re)loading vs which are already up to date.
	var toLoad []*ezcfg.ProviderConfig
	for _, cfg := range pcfgs {
		if cfg == nil {
			continue
		}
		key := cfg.ProviderName
		cached, err := r.cache.Get(ctx, key)
		if err != nil {
			toLoad = append(toLoad, cfg)
			continue
		}
		// In cache: reload only when DB record is newer.
		if !cfg.UpdatedAt.IsZero() && cfg.UpdatedAt.After(cached.Opts().UpdatedAt) {
			r.logger.Debug("provider config updated, scheduling reload", ezlog.Str("provider", key))
			_ = r.cache.Del(ctx, key)
			toLoad = append(toLoad, cfg)
		}
	}

	if len(toLoad) > 0 {
		providers, err := ezproviders.NewProvider(toLoad, r.sessionStore, ctx) //nolint:contextcheck
		if err != nil {
			// Partial failures (e.g. unreachable OIDC discovery) are non-fatal;
			// the periodic refresh will retry.
			r.logger.Warn("one or more providers failed to initialise; they will be retried on the next refresh", ezlog.Err(err))
		}
		for n, p := range providers {
			if err := r.cache.Set(ctx, n, p, 0); err != nil {
				r.logger.Warn("failed to cache provider", ezlog.Str("provider", n), ezlog.Err(err))
			}
		}
	}

	// Evict cache entries that no longer appear in the desired set.
	// Static-config providers are exempt.
	desired := make(map[string]struct{}, len(pcfgs))
	for _, cfg := range pcfgs {
		if cfg != nil {
			desired[cfg.ProviderName] = struct{}{}
		}
	}
	r.rangeAll(ctx, func(key string, _ ezproviders.Provider) bool {
		if _, want := desired[key]; !want && !r.isStatic(key) {
			r.logger.Debug("evicting stale provider from cache", ezlog.Str("provider", key))
			_ = r.cache.Del(ctx, key)
		}
		return true
	})

	r.rebuildAdminGroups(ctx)
	return nil
}

// --- Server methods that delegate to registry ---

// ensureRegistry initializes s.registry from the current Server fields if it
// has not been set yet. It is safe to call from any handler: Start() always
// calls Providers() — which calls ensureRegistry() — before the HTTP server
// begins accepting connections, so s.registry is non-nil for all concurrent
// request goroutines. The nil guard here exists only for tests that construct
// a bare Server{} without calling Start() or Providers().
func (s *Server) ensureRegistry() *providerRegistry {
	if s.registry == nil {
		s.registry = newProviderRegistry(
			s.AuthCfg.ProviderCache.Size,
			s.DB,
			s.sessionStore,
			s.Logger,
			s.AuthCfg.Provider,
		)
	}
	return s.registry
}

// Providers initializes the registry on first call and syncs provider state.
func (s *Server) Providers(ctx context.Context) error {
	s.ensureRegistry()
	return s.registry.sync(ctx, s.AuthCfg.ProviderCache.Size)
}

func (s *Server) providerRouter(r *mux.Router) {
	r.HandleFunc("/", s.ListProviders).Methods("GET").Name("ipc::provider::list")
	r.HandleFunc("/{name}", s.GetProvider).Methods("GET").Name("ipc::provider::get")
	r.HandleFunc("/{name}", s.UpdateProvider).Methods("PUT").Name("ipc::provider::update")
	r.HandleFunc("/{name}", s.DeleteProvider).Methods("DELETE").Name("ipc::provider::delete")
	r.HandleFunc("/", s.AddProvider).Methods("POST").Name("ipc::provider::create")
}

// ListProviders returns all known provider configurations.
//
// @Summary      List providers
// @Description  Returns all OIDC/OAuth2 provider configurations from the database.
// @Tags         Provider Management
// @Produce      json
// @Param        limit query int false "Max results (default 100)"
// @Param        offset query int false "Offset for pagination (default 0)"
// @Success      200 {array} models.ProviderDB "Provider list"
// @Failure      404 {object} dto.ErrorResponse "Database not available"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/provider/ [get]
func (s *Server) ListProviders(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)

	items := make([]*ezdto.ProviderListItem, 0)

	// Static providers from config come first.
	for _, cfg := range s.AuthCfg.Provider {
		items = append(items, ezdto.StaticProviderListItem(cfg))
	}

	// Database providers (only when DB is available).
	if s.DB != nil {
		limit, offset, err := pagination(r)
		if err != nil {
			s.writeJSONError(rw, http.StatusBadRequest, "invalid pagination parameters")
			return
		}
		if limit <= 0 {
			limit = 100
		}
		dbProviders, err := s.DB.ListProviders(r.Context(), limit, offset)
		if err != nil {
			logger.Error("error listing providers", ezlog.Err(err))
			s.writeGeneralError(rw, err)
			return
		}
		for _, p := range dbProviders {
			items = append(items, ezdto.ProviderListItemFromDB(p))
		}
	}

	s.writeJSONResponse(rw, http.StatusOK, "providers retrieved", items)
}

// GetProvider returns the provider configuration for the given name.
//
// @Summary      Get a provider by name
// @Description  Returns the OIDC/OAuth2 provider configuration.
// @Tags         Provider Management
// @Produce      json
// @Param        name path string true "Provider name"
// @Success      200 {object} ezcfg.ProviderConfig "Provider configuration"
// @Failure      404 {object} dto.ErrorResponse "Provider not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/provider/{name} [get]
func (s *Server) GetProvider(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	vars := mux.Vars(r)
	name := vars["name"]

	p, ok := s.ensureRegistry().get(r.Context(), name)
	if !ok {
		s.writeJSONError(rw, http.StatusNotFound, "provider not found")
		return
	}
	logger.Debug("loaded provider from cache or database", ezlog.Str("provider", name))

	s.writeJSONResponse(rw, http.StatusOK, "provider retrieved", p)
}

// UpdateProvider updates the configuration for an existing provider.
//
// @Summary      Update a provider
// @Description  Updates an existing OIDC/OAuth2 provider configuration in the database. The provider name is fixed and cannot be changed via this API.
// @Tags         Provider Management
// @Accept       json
// @Produce      json
// @Param        name path string true "Provider name"
// @Param        body body ezdto.UpdateProviderRequest true "Updated provider fields"
// @Success      200 "Provider updated"
// @Failure      400 {object} dto.ErrorResponse "Invalid request body"
// @Failure      404 {object} dto.ErrorResponse "Provider not found"
// @Failure      409 {object} dto.ErrorResponse "Conflicts with a static provider"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/provider/{name} [put]
func (s *Server) UpdateProvider(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}
	vars := mux.Vars(r)
	name := vars["name"]
	if s.ensureRegistry().isStatic(name) {
		s.writeJSONError(rw, http.StatusConflict, "provider is statically configured and cannot be modified via API")
		return
	}
	decoder := json.NewDecoder(r.Body)
	var req ezdto.UpdateProviderRequest
	if err := decoder.Decode(&req); err != nil {
		logger.Error("error decoding JSON request body for updating provider", ezlog.Str("provider", name), ezlog.Err(err))
		code := http.StatusBadRequest
		s.writeJSONError(rw, code, fmt.Sprintf("%s, please check your request data.", http.StatusText(code)))
		return
	}
	req.ProviderName = name
	p, err := req.ConvertToDB()
	if err != nil {
		logger.Error("error in converting provider request to model", ezlog.Err(err))
		code := http.StatusBadRequest
		s.writeJSONError(rw, code, fmt.Sprintf("%s, please check your request data.", http.StatusText(code)))
		return
	}
	logger.Info("updating provider in database", ezlog.Str("provider", name))
	if err = s.DB.UpdateProvider(r.Context(), p); err != nil {
		if err == database.ErrNoRecord {
			s.writeJSONError(rw, http.StatusNotFound, "provider not found")
			return
		}
		logger.Error("error updating provider in database", ezlog.Str("provider", name), ezlog.Err(err))
		code := http.StatusInternalServerError
		s.writeJSONError(rw, code, fmt.Sprintf("%s, please contact admin.", http.StatusText(code)))
		return
	}
	// DB write succeeded: evict stale entry then repopulate.
	// refresh() skips disabled providers automatically.
	reg := s.ensureRegistry()
	_ = reg.del(r.Context(), name)
	reg.refresh(r.Context(), name)
	logger.Info("provider updated successfully", ezlog.Str("provider", name))
	s.writeJSONResponse(rw, http.StatusOK, "provider updated", nil)
}

// DeleteProvider removes the provider with the given name.
//
// @Summary      Delete a provider
// @Description  Removes an OIDC/OAuth2 provider from the database and clears it from the cache.
// @Tags         Provider Management
// @Produce      json
// @Param        name path string true "Provider name to delete"
// @Success      200 "Provider deleted"
// @Failure      404 {object} dto.ErrorResponse "Provider not found"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/provider/{name} [delete]
func (s *Server) DeleteProvider(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}
	vars := mux.Vars(r)
	name := vars["name"]
	if err := s.DB.DeleteProvider(r.Context(), name); err != nil {
		if err == database.ErrNoRecord {
			s.writeJSONError(rw, http.StatusNotFound, "provider not found")
			return
		}
		code := http.StatusInternalServerError
		s.writeJSONError(rw, code, fmt.Sprintf("%s, please contact admin.", http.StatusText(code)))
		return
	}
	if err := s.ensureRegistry().del(r.Context(), name); err != nil {
		logger.Warn("failed to evict provider from cache after delete", ezlog.Str("provider", name), ezlog.Err(err))
	}
	logger.Info("provider deleted successfully", ezlog.Str("provider", name))
	s.writeJSONResponse(rw, http.StatusOK, "provider deleted", nil)
}

// AddProvider creates a new provider configuration.
//
// @Summary      Create a provider
// @Description  Adds a new OIDC/OAuth2 provider configuration to the database.
// @Tags         Provider Management
// @Accept       json
// @Produce      json
// @Param        body body models.ProviderDB true "Provider configuration"
// @Success      200 "Provider created"
// @Failure      400 {object} dto.ErrorResponse "Invalid request body"
// @Failure      409 {object} dto.ErrorResponse "Conflicts with a static provider"
// @Failure      500 {object} dto.ErrorResponse "Internal server error"
// @Router       /ezauth/provider/ [post]
func (s *Server) AddProvider(rw http.ResponseWriter, r *http.Request) {
	logger := s.requestLogger(r)
	if s.DB == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}
	decoder := json.NewDecoder(r.Body)
	var p models.ProviderDB
	if err := decoder.Decode(&p); err != nil {
		logger.Error("error decoding JSON request body for new provider", ezlog.Err(err))
		code := http.StatusBadRequest
		s.writeJSONError(rw, code, fmt.Sprintf("%s, please check your request data.", http.StatusText(code)))
		return
	}
	reg := s.ensureRegistry()
	if reg.isStatic(p.ProviderName) {
		s.writeJSONError(rw, http.StatusConflict, "provider name conflicts with a statically configured provider")
		return
	}
	if err := s.DB.AddProvider(r.Context(), &p); err != nil {
		logger.Error("error in adding provider", ezlog.Str("provider", p.ProviderName), ezlog.Err(err))
		s.writeGeneralError(rw, err)
		return
	}
	reg.refresh(r.Context(), p.ProviderName)
	logger.Info("provider added successfully", ezlog.Str("provider", p.ProviderName))
	s.writeJSONResponse(rw, http.StatusCreated, "provider created", map[string]any{"provider_name": p.ProviderName})
}
