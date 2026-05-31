package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"strings"

	"github.com/gorilla/mux"
	httpSwagger "github.com/swaggo/http-swagger/v2"
	"golang.org/x/sync/errgroup"

	_ "net/http/pprof" //nolint:gosec // register pprof handlers on http.DefaultServeMux

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/bootstrap"
	ezcache "github.com/flipcloud-ai/ezauth/pkg/cache"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm"
	ezerror "github.com/flipcloud-ai/ezauth/pkg/error"
	ezmetrics "github.com/flipcloud-ai/ezauth/pkg/metrics"
	middleware "github.com/flipcloud-ai/ezauth/pkg/middleware"
	dto "github.com/flipcloud-ai/ezauth/pkg/server/dto"
	"github.com/flipcloud-ai/ezauth/pkg/server/rbac"
	eztmpl "github.com/flipcloud-ai/ezauth/pkg/server/templates"
	"github.com/flipcloud-ai/ezauth/pkg/sessions"
	_ "github.com/flipcloud-ai/ezauth/swagger" // swaggo generated docs

	"net/http"
	"net/url"
	"slices"
	"time"
)

const (
	robotsPath           = "/robots.txt"
	healthzPath          = "/healthz"
	signInPath           = "/login"
	signOutPath          = "/logout"
	startPath            = "/start"
	callBackPath         = "/callback"
	verifyPath           = "/verify"
	portalPath           = "/portal"
	defaultRefreshPeriod = 30 * time.Second
	fallbackAdminUser    = "root"
)

// Server is the main HTTP server that handles authentication, proxying, and admin API requests.
type Server struct {
	ServeMux         *mux.Router
	ServeCfg         ezcfg.ServerConfig
	AuthCfg          ezcfg.AuthConfig
	Logger           ezlog.Logger
	DB               database.DatabaseInterface
	sessionStore     sessions.SessionStore
	registry         *providerRegistry
	rbacController   rbac.Controller
	revProxy         *proxy
	systemAdminGroup string
	adminUsername    string
	globalCache      ezcache.Cache[string, []byte]
	auditCore        *auditCore
	renderer         *eztmpl.Renderer
}

var noCacheHeaders = map[string]string{
	"Expires":         time.Unix(0, 0).Format(time.RFC1123),
	"Cache-Control":   "no-cache, no-store, must-revalidate, max-age=0",
	"X-Accel-Expires": "0", // https://www.nginx.com/resources/wiki/start/topics/examples/x-accel/
}

// prepares headers for preventing browser caching.
func noCacheHeader(rw http.ResponseWriter) {
	// Set NoCache headers
	for k, v := range noCacheHeaders {
		rw.Header().Set(k, v)
	}
}

// writeJSONError writes a JSON-shaped error body for a 4xx/5xx status. It is
// intended for admin/API handlers and the JSON branch of respondError — not a
// general-purpose response writer. Use http.Redirect or the template renderers
// for success and 2xx/3xx responses.
func (s *Server) writeJSONError(rw http.ResponseWriter, code int, message string, authenticated ...bool) {
	resp := dto.ErrorResponse{
		Code:  code,
		Error: message,
	}
	if len(authenticated) > 0 {
		resp.Authenticated = &authenticated[0]
	}
	body, err := json.Marshal(resp)
	if err != nil {
		body = []byte("{}")
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	if _, err := rw.Write(body); err != nil {
		s.Logger.Error("error writing JSON error response", ezlog.Int("code", code), ezlog.Err(err))
	}
}

// writeGeneralError unwraps err to *ezerror.GeneralError (or its subtypes like
// DatabaseErr, RBACErr) and writes the unified dto.ErrorResponse as JSON.
// Falls back to a 500 if unwrapping fails.
func (s *Server) writeGeneralError(rw http.ResponseWriter, err error) {
	var ge *ezerror.GeneralError
	if !errors.As(err, &ge) {
		s.Logger.Error("unexpected error type in writeGeneralError", ezlog.Err(err))
		s.writeJSONError(rw, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
		return
	}
	s.writeJSONError(rw, ge.Code, ge.Err)
}

// writeJSONResponse writes a unified JSON response with message and data.
// All CRUD handlers use this to keep the response format consistent.
func (s *Server) writeJSONResponse(rw http.ResponseWriter, code int, message string, data any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	_ = json.NewEncoder(rw).Encode(dto.SuccessResponse{
		Message: message,
		Data:    data,
	})
}

// respondError is the unified error responder for the proxy/auth flows. It
// returns JSON when the deployment is configured for JSON errors or when the
// client clearly isn't a browser, and renders the HTML error page otherwise.
func (s *Server) respondError(rw http.ResponseWriter, req *http.Request, code int, errmsg string) {
	if s.AuthCfg.Proxy.JSONResponse || !wantsHTML(req) {
		s.requestLogger(req).Debug("returning error in json format")
		s.writeJSONError(rw, code, errmsg)
		return
	}
	s.ErrorPage(rw, req, code, errmsg)
}

// redirectToLogin sends the client to the sign-in page, preserving the
// current request URI as a `redirect` query parameter so the user lands back
// where they started after auth. Use this for every "no session" branch so
// the behavior is consistent across the proxy, middleware, and handlers.
func (s *Server) redirectToLogin(rw http.ResponseWriter, req *http.Request) {
	loginURL := s.ServeCfg.AuthPrefix + signInPath + "?redirect=" + url.QueryEscape(req.URL.RequestURI())
	http.Redirect(rw, req, loginURL, http.StatusFound)
}

// Start initializes routes and begins serving HTTP requests using opts.
func (s *Server) Start(ctx context.Context, opts ezcfg.Options) error {
	var err error
	g, groupCtx := errgroup.WithContext(ctx)

	if s.ServeCfg.Hostname == "" || s.ServeCfg.Hostname == "-" {
		s.ServeCfg.Hostname = "localhost"
	}

	// When TLS is not enabled, a Secure cookie makes the browser silently
	// drop the session cookie over plain HTTP, breaking authentication.
	// Correct the default before it propagates into the session store and the
	// server's own auth-config copy, and warn so the operator notices.
	if !s.ServeCfg.TLS.Enabled && opts.Auth.Session.Cookie.Secure {
		opts.Auth.Session.Cookie.Secure = false
		s.Logger.Warn("TLS is not enabled, automatically setting cookie.secure=false " +
			"so that browsers will accept the session cookie over plain HTTP. " +
			"Enable TLS and set force-https=true in production.")
	}

	s.AuthCfg = opts.Auth
	secretFile := opts.Access.Bootstrap.SecretFile
	s.systemAdminGroup = opts.Access.SystemAdminGroup

	metrics := ezmetrics.New()

	if *opts.Audit.Enabled {
		s.Logger, s.auditCore = newAuditLogger(s.Logger, opts.Audit.BufferSize)
	}

	sessionStore, err := sessions.NewSessionStore(&opts.Auth.Session)

	if err != nil {
		s.Logger.Error("error in initializing session store", ezlog.Err(err))
		return err
	}
	if sessionStore == nil {
		err = errors.New("session store is nil")
		s.Logger.Error("error in initializing session store", ezlog.Err(err))
		return err
	}
	s.sessionStore = sessionStore

	errorLog, err := ezlog.StdLogger(s.Logger, ezcfg.LogConfig{
		Level: "error",
	})
	if err != nil {
		s.Logger.Error("error in initializing http error logger", ezlog.Err(err))
		return err
	}

	ctx = ezlog.ServerContext(ctx, s.Logger)

	if opts.Database.Driver == "" || opts.Database.User == "" {
		s.Logger.Warn("no database configured, skip database initialization.")
		s.DB = nil
	} else {
		if opts.Database.SkipInit {
			s.Logger.Warn("database initialization skipped, make sure the database is properly initialized and migrated before starting the server.")
		} else {
			s.Logger.Info("initializing database and running migrations.")
			if err = orm.Init(opts.Database.Driver, opts.Database.Name, orm.DSN(opts.Database), opts.Log.Level != "debug"); err != nil { //nolint:contextcheck // orm.Init does not accept context
				s.Logger.Error("error in initializing database", ezlog.Err(err))
				return err
			}
		}
		db, err := orm.NewDB(ctx, opts.Database)
		if err != nil {
			s.Logger.Error("error in initializing database", ezlog.Err(err))
			return err
		}
		s.DB = db
	}

	if s.DB != nil {
		if len(s.AuthCfg.Static) > 0 {
			s.Logger.Warn("database is configured; static user credentials are ignored for admin-API access — DB mode takes precedence")
		}
		s.Bootstrap(groupCtx, secretFile)
	}

	// Resolve the admin credentials for AdminGate and static login.
	// In DB mode Bootstrap guarantees the user exists in the DB.
	// In static mode we read the bootstrap secret file so the operator can
	// configure the admin account without hard-coding it. When the secret
	// file is successfully read, the admin credentials are also registered
	// into the static auth list for login.
	s.adminUsername = loadAdminUsername(s.Logger, secretFile)

	if s.DB == nil {
		if user, pass, ok := readBootstrapSecret(s.Logger, secretFile); ok {
			s.adminUsername = user
			s.AuthCfg.Static = append(s.AuthCfg.Static, ezcfg.PasswordConfig{
				User:     user,
				Password: pass,
			})
		}
	}

	s.Logger.Info("initializing global cache.")
	// Route cache-internal warnings (shard floor, budget collapse) through
	// the app's structured zap logger so operators see them alongside
	// everything else.
	s.globalCache, err = ezcache.NewFromConfig(opts.Cache, ezcache.WithLogger(s.Logger)) //nolint:contextcheck // NewFromConfig creates its own short-lived ping context internally
	if err != nil {
		return err
	}

	if err = s.Providers(ctx); err != nil {
		// Providers() only returns an error for fatal configuration problems
		// (e.g. DB unreachable). Transient per-provider failures are already
		// handled inside Providers() with a Warn log.
		s.Logger.Error("error in initializing providers", ezlog.Err(err))
		return err
	}

	if s.DB != nil {
		// Add refresh provider cache goroutine for db flush.
		interval := opts.Auth.ProviderCache.RefreshInterval
		if interval <= 0 {
			interval = defaultRefreshPeriod
		}
		g.Go(func() error {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-groupCtx.Done():
					return nil
				case <-ticker.C:
					s.Logger.Info("refreshing provider cache", ezlog.Str("interval", interval.String()))
					if refreshErr := s.Providers(groupCtx); refreshErr != nil {
						s.Logger.Error("provider cache refresh failed", ezlog.Err(refreshErr))
					}
				}
			}
		})

		// Init RBAC controller
		if opts.Access.RBAC.Enabled {
			s.Logger.Info("initializing RBAC controller and loading permissions from routes and database.")
			groupName := s.systemAdminGroup
			s.rbacController, err = rbac.NewController(ctx, &opts.Access.RBAC, s.DB, s.globalCache, s.ServeCfg.AuthPrefix, groupName)
			if err != nil {
				s.Logger.Error("error in initializing RBAC controller", ezlog.Err(err))
				return err
			}
		}
	}

	if s.AuthCfg.Proxy.IsEnabled() {
		s.Logger.Info("reverse proxy is enabled")
		s.revProxy = newProxy(s.buildProxy(), s.AuthCfg.Proxy.SkipAuthPaths)
	} else {
		s.Logger.Info("reverse proxy is disabled, running in auth-only mode")
	}

	if s.auditCore != nil {
		flusher := &auditFlusher{
			core:   s.auditCore,
			db:     s.DB,
			cfg:    opts.Audit,
			logger: s.Logger,
		}
		g.Go(func() error {
			flusher.Start(groupCtx)
			return nil
		})
	}

	rend, tmplWarnings, err := eztmpl.New(opts.Server.TemplatePath, opts.Server.LogoPath)
	if err != nil {
		s.Logger.Error("error loading templates and assets", ezlog.Err(err))
		return err
	}
	for _, w := range tmplWarnings {
		s.Logger.Warn(w)
	}
	s.renderer = rend

	s.buildServeMux()
	if s.rbacController != nil {
		err = s.rbacController.RouteWalk(s.ServeMux)
		if err != nil {
			s.Logger.Error("fail to build permissions for admin routes", ezlog.Err(err))
			return err
		}
		if err = s.rbacController.SeedDefaults(); err != nil {
			s.Logger.Error("fail to seed default policies and roles", ezlog.Err(err))
			return err
		}
	}
	metrics.SetReady()
	globalChain := middleware.NewChain(middleware.Recovery(s.Logger), s.wrapSkipAuth)
	s.Logger.Debug("starting server.")
	srv := &http.Server{
		Handler:           globalChain.Then(s.ServeMux),
		WriteTimeout:      time.Second * time.Duration(s.ServeCfg.WriteTimeout),
		ReadTimeout:       time.Second * time.Duration(s.ServeCfg.ReadTimeout),
		IdleTimeout:       time.Second * time.Duration(s.ServeCfg.IdleTimeout),
		ErrorLog:          errorLog,
		ReadHeaderTimeout: time.Second * time.Duration(s.ServeCfg.ReadHeaderTimeout),
	}

	var metricsServer *http.Server
	var pprofServer *http.Server

	g.Go(func() error {
		<-groupCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		var errs []error
		if err := cleanupServer(shutdownCtx, srv, s.globalCache, s.Logger); err != nil {
			errs = append(errs, err)
		}
		if metricsServer != nil {
			if err := metricsServer.Shutdown(shutdownCtx); err != nil {
				s.Logger.Error("error shutting down metrics server", ezlog.Err(err))
				errs = append(errs, fmt.Errorf("metrics shutdown: %w", err))
			}
		}
		if pprofServer != nil {
			if err := pprofServer.Shutdown(shutdownCtx); err != nil {
				s.Logger.Error("error shutting down pprof server", ezlog.Err(err))
				errs = append(errs, fmt.Errorf("pprof shutdown: %w", err))
			}
		}
		return errors.Join(errs...)
	})

	if s.ServeCfg.TLS.Enabled {
		if err := s.setupTLS(srv); err != nil {
			s.Logger.Error("could not start https server", ezlog.Err(err))
			return err
		}
		srv.Addr = fmt.Sprintf("%s:%d", s.ServeCfg.Hostname, s.ServeCfg.Port)
		g.Go(func() error {
			s.Logger.Info("starting https proxy service", ezlog.Str("address", srv.Addr))
			httpErr := srv.ListenAndServeTLS(s.ServeCfg.TLS.CertPath, s.ServeCfg.TLS.KeyPath)
			if httpErr != nil && !errors.Is(httpErr, http.ErrServerClosed) {
				s.Logger.Error("could not start https server", ezlog.Err(httpErr))
			}
			if httpErr != nil {
				return fmt.Errorf("https server: %w", httpErr)
			}
			return nil
		})
	} else {
		if s.ServeCfg.Port <= 0 {
			s.ServeCfg.Port = 8080
		}
		srv.Addr = fmt.Sprintf("%s:%d", s.ServeCfg.Hostname, s.ServeCfg.Port)
		g.Go(func() error {
			s.Logger.Info("starting http proxy service", ezlog.Str("address", srv.Addr))
			httpErr := srv.ListenAndServe()
			if httpErr != nil && !errors.Is(httpErr, http.ErrServerClosed) {
				s.Logger.Error("could not start http server", ezlog.Err(httpErr))
			}
			if httpErr != nil {
				return fmt.Errorf("http server: %w", httpErr)
			}
			return nil
		})
	}

	if s.ServeCfg.Metrics.Enabled {
		metricsMux := http.NewServeMux()
		metricsMux.Handle(s.ServeCfg.Metrics.Path, metrics.Handler())
		metricsSrv := &http.Server{
			Handler:           metricsMux,
			Addr:              fmt.Sprintf("%s:%d", s.ServeCfg.Metrics.Host, s.ServeCfg.Metrics.Port),
			WriteTimeout:      10 * time.Second,
			ReadTimeout:       10 * time.Second,
			IdleTimeout:       60 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			ErrorLog:          errorLog,
		}
		metricsServer = metricsSrv
		g.Go(func() error {
			s.Logger.Info("starting metrics server",
				ezlog.Str("address", metricsSrv.Addr),
				ezlog.Str("path", s.ServeCfg.Metrics.Path))
			httpErr := metricsSrv.ListenAndServe()
			if httpErr != nil && !errors.Is(httpErr, http.ErrServerClosed) {
				s.Logger.Error("could not start metrics server", ezlog.Err(httpErr))
			}
			if httpErr != nil {
				return fmt.Errorf("metrics server: %w", httpErr)
			}
			return nil
		})
	}

	if s.ServeCfg.Pprof.Enabled {
		pprofSrv := &http.Server{
			Handler:           http.DefaultServeMux,
			Addr:              "127.0.0.1:6060",
			WriteTimeout:      10 * time.Second,
			ReadTimeout:       10 * time.Second,
			IdleTimeout:       60 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			ErrorLog:          errorLog,
		}
		pprofServer = pprofSrv
		g.Go(func() error {
			s.Logger.Info("starting pprof server", ezlog.Str("address", pprofSrv.Addr))
			httpErr := pprofSrv.ListenAndServe()
			if httpErr != nil && !errors.Is(httpErr, http.ErrServerClosed) {
				s.Logger.Warn("can't launch pprof server", ezlog.Err(httpErr))
				return nil
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("server group: %w", err)
	}
	return nil
}

// Bootstrap delegates to the package-level bootstrap.Bootstrap.
func (s *Server) Bootstrap(ctx context.Context, secretFile string) {
	bootstrap.Bootstrap(ctx, s.DB, s.Logger, bootstrap.Config{
		SecretFile:       secretFile,
		SystemAdminGroup: s.systemAdminGroup,
	})
}

// loadAdminUsername reads the admin username from the bootstrap secret file.
// Falls back to fallbackAdminUser if the file is missing or malformed.
func loadAdminUsername(logger ezlog.Logger, secretFile string) string {
	u, _, ok := readBootstrapSecret(logger, secretFile)
	if !ok {
		return fallbackAdminUser
	}
	return u
}

// readBootstrapSecret reads and decodes the bootstrap secret file.
// Returns (username, password, true) on success, ("", "", false) on failure.
func readBootstrapSecret(logger ezlog.Logger, secretFile string) (string, string, bool) {
	raw, err := os.ReadFile(secretFile) //nolint:gosec
	if err != nil {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		logger.Warn("bootstrap secret file is not valid base64",
			ezlog.Str("file", secretFile), ezlog.Err(err))
		return "", "", false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok || username == "" || password == "" {
		logger.Warn("bootstrap secret file must contain user:password",
			ezlog.Str("file", secretFile))
		return "", "", false
	}
	return username, password, true
}

// cleanupServer shuts down the HTTP server and closes the cache, logging any
// errors. Shutdown is called before Close so the cache remains available to
// in-flight requests during graceful shutdown. It returns the first non-nil
// error so the caller (typically an errgroup goroutine) can propagate it.
func cleanupServer(
	ctx context.Context,
	srv interface{ Shutdown(context.Context) error },
	cache interface{ Close() error },
	logger ezlog.Logger,
) error {
	shutdownErr := srv.Shutdown(ctx)
	if shutdownErr != nil {
		logger.Error("error shutting down server", ezlog.Err(shutdownErr))
	}
	closeErr := cache.Close()
	if closeErr != nil {
		logger.Error("error closing global cache", ezlog.Err(closeErr))
	}
	if shutdownErr != nil {
		return shutdownErr
	}
	return closeErr
}

func (s *Server) buildPreAuthMiddlewares() middleware.Chain {
	chain := middleware.NewChain()

	if s.ServeCfg.ForceHTTPS && s.ServeCfg.TLS.Enabled {
		chain.Append(middleware.RedirectToHTTPS(fmt.Sprintf("%d", s.ServeCfg.Port)))
	}

	chain.Append(middleware.InitSession(*s.ServeCfg.TrustForwardedHeaders))
	chain.Append(middleware.RequestLogger(s.Logger, *s.ServeCfg.TrustForwardedHeaders))
	if s.ServeCfg.Metrics.Enabled {
		chain.Append(middleware.MetricsMiddleware)
	}
	if s.AuthCfg.Session.CSRF.Enabled {
		// Copy by value so we can append StaticPrefix without mutating the
		// shared AuthCfg — append may allocate a new backing array only when
		// the slice is nil/zero-capacity, but the intent is explicit.
		csrfCfg := s.AuthCfg.Session.CSRF
		if !slices.Contains(csrfCfg.ExcludePrefixes, s.ServeCfg.StaticPrefix) {
			csrfCfg.ExcludePrefixes = append(csrfCfg.ExcludePrefixes, s.ServeCfg.StaticPrefix)
		}
		csrfErrorHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			reason := middleware.FailureReason(req)
			msg := "Forbidden"
			if reason != nil {
				msg = reason.Error()
			}
			s.respondError(rw, req, http.StatusForbidden, msg)
		})
		chain.Append(middleware.CSRF(&csrfCfg, s.sessionStore, csrfErrorHandler))
	}

	return chain
}

func (s *Server) buildSessionMiddlewares() middleware.Chain {
	chain := middleware.NewChain()

	chain.Append(middleware.Favicon(s.ServeCfg.StaticPrefix + "/favicon.svg"))
	// Pass authenticatePAT so LoadSession resolves Bearer tokens before Gate runs.
	// When DB is nil (static mode) PAT is not supported — pass nil to disable.
	var patAuth middleware.PATAuthFunc
	if s.DB != nil {
		patAuth = s.authenticatePAT
	}
	chain.Append(middleware.LoadSession(s.registry.resolve, s.sessionStore, patAuth))
	chain.Append(s.Gate)

	return chain
}

// buildSkipAuthChain builds a minimal middleware chain for skip-auth requests.
// It includes only InitSession (request ID) and RequestLogger. CSRF,
// LoadSession, and Authorization are excluded so that external webhooks pass
// through without authentication.
func (s *Server) buildSkipAuthChain() http.Handler {
	chain := middleware.NewChain()
	chain.Append(middleware.InitSession(*s.ServeCfg.TrustForwardedHeaders))
	chain.Append(middleware.RequestLogger(s.Logger, *s.ServeCfg.TrustForwardedHeaders))
	return chain.ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
		if s.revProxy == nil {
			s.respondError(rw, req, http.StatusInternalServerError,
				"reverse proxy is not initialized")
			return
		}
		s.requestLogger(req).Info("skip-auth path",
			ezlog.Str("path", req.URL.Path),
			ezlog.Str("method", req.Method))
		stripIdentityHeaders(req, s.AuthCfg.Proxy.IdentityHeaders)
		s.revProxy.rp.ServeHTTP(rw, req)
	})
}

// wrapSkipAuth returns an http.Handler that intercepts skip-auth requests
// before they reach the main mux router. When the request matches a configured
// skip-auth path it runs through the minimal skip-auth chain (no CSRF, no
// session check). Otherwise the main mux handles the request normally.
// When no skip-auth paths are configured or the proxy is nil, next is returned
// unchanged so there is zero overhead for the common case.
func (s *Server) wrapSkipAuth(next http.Handler) http.Handler {
	if s.revProxy == nil || len(s.revProxy.skipPaths) == 0 {
		return next
	}
	skipChain := s.buildSkipAuthChain()
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if s.isSkipAuthPath(req) {
			skipChain.ServeHTTP(rw, req)
			return
		}
		next.ServeHTTP(rw, req)
	})
}

// requestLogger returns a per-request logger from the context.
// Falls back to the server's base logger if no request context is found.
func (s *Server) requestLogger(r *http.Request) ezlog.Logger {
	if r != nil {
		return ezlog.FromContext(r.Context())
	}
	return s.Logger
}

func noCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		noCacheHeader(rw)
		next.ServeHTTP(rw, req)
	})
}

func (s *Server) buildServeMux() {
	r := mux.NewRouter().UseEncodedPath()

	preAuthChain := s.buildPreAuthMiddlewares()
	sessionChain := s.buildSessionMiddlewares()

	// Admin middleware chain: Favicon → LoadSession → Gate → AdminGate → Authorization (if RBAC enabled).
	// A separate chain instance is built here so that Append (AdminGate, Authorization)
	// does not mutate sessionChain, which is shared with non-admin routes.
	adminChain := s.buildSessionMiddlewares()
	adminChain.Append(s.AdminGate)
	if s.rbacController != nil {
		adminChain.Append(s.Authorization)
	}

	r.Use(preAuthChain.Then)

	r.Path(robotsPath).HandlerFunc(s.GetRobots)
	r.Path(s.ServeCfg.StaticPrefix + "/logo").HandlerFunc(s.renderer.Handler("logo.svg"))
	r.Path(s.ServeCfg.StaticPrefix + "/favicon.svg").HandlerFunc(s.renderer.Handler("favicon.svg"))

	r.PathPrefix(s.ServeCfg.StaticPrefix).Handler(http.FileServer(http.FS(eztmpl.StaticFiles)))

	s.oauthSubrouter(r.PathPrefix(s.ServeCfg.AuthPrefix).Subrouter())

	// Admin resource subrouters directly under AuthPrefix.
	authPrefix := s.ServeCfg.AuthPrefix

	providerSub := r.PathPrefix(authPrefix + providerPath).Subrouter()
	providerSub.Use(adminChain.Then)
	s.providerRouter(providerSub)

	userSub := r.PathPrefix(authPrefix + userPath).Subrouter()
	userSub.Use(adminChain.Then)
	s.userRouter(userSub)

	s.meSelfRouter(r, authPrefix, sessionChain)

	groupSub := r.PathPrefix(authPrefix + groupPath).Subrouter()
	groupSub.Use(adminChain.Then)
	s.groupRouter(groupSub)

	if s.rbacController != nil {
		authSub := r.PathPrefix(authPrefix + authPath).Subrouter()
		authSub.Use(adminChain.Then)
		s.rbacRouter(authSub)
	}

	if s.auditCore != nil {
		auditSub := r.PathPrefix(authPrefix + auditPath).Subrouter()
		auditSub.Use(adminChain.Then)
		s.auditRouter(auditSub)
	}

	if s.ServeCfg.Portal.Enabled {
		// Self-service pages must be registered before the admin PathPrefix
		// subrouter, otherwise portalRouter's catch-all redirect intercepts them.
		s.selfPortalRouter(r, authPrefix, sessionChain)

		portalSub := r.PathPrefix(authPrefix + portalPath).Subrouter()
		portalSub.Use(adminChain.Then)
		s.portalRouter(portalSub)
	}

	r.Path(healthzPath).HandlerFunc(middleware.Healthz)

	// Swagger UI — served without auth so it is always discoverable.
	r.PathPrefix("/swagger").Handler(httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	if s.revProxy != nil {
		r.PathPrefix("/").Handler(sessionChain.ThenFunc(s.Proxy))
	} else {
		r.PathPrefix("/").HandlerFunc(http.NotFound)
	}

	s.ServeMux = r
}

// GetRobots serves the robots.txt file.
// @Summary      Robots.txt
// @Description  Returns the robots.txt file for web crawler directives.
// @Tags         System
// @Produce      plain
// @Success      200 {string} string "Robots.txt content"
// @Router       /robots.txt [get]
func (s *Server) GetRobots(rw http.ResponseWriter, req *http.Request) {
	s.renderer.Handler("robots.txt")(rw, req)
}

func (s *Server) oauthSubrouter(r *mux.Router) {
	r.Use(noCacheMiddleware)

	// /start and /callback get request-rate limiting to prevent IdP flooding
	// and state brute-forcing respectively.
	var startHandler, callbackHandler http.Handler
	startHandler = http.HandlerFunc(s.OAuthStart)
	callbackHandler = http.HandlerFunc(s.OAuthCallback)
	if s.AuthCfg.OAuthRateLimit.Enabled && s.globalCache != nil {
		rl := middleware.RateLimit("rl:oauth", &s.AuthCfg.OAuthRateLimit, s.globalCache, *s.ServeCfg.TrustForwardedHeaders)
		startHandler = rl(startHandler)
		callbackHandler = rl(callbackHandler)
	}
	r.Path(startPath).Handler(startHandler)
	r.Path(callBackPath).Handler(callbackHandler)

	loginHandler := http.Handler(http.HandlerFunc(s.Login))
	if s.AuthCfg.LoginRateLimit.Enabled && s.globalCache != nil {
		loginHandler = middleware.RateLimit("rl:login", &s.AuthCfg.LoginRateLimit, s.globalCache, *s.ServeCfg.TrustForwardedHeaders)(loginHandler)
	}
	r.Path(signInPath).Handler(loginHandler)
	// /logout needs the session loaded so Revoke can run against the right
	// tokens; wrap just this path with LoadSession instead of adding another
	// middleware to the whole oauth subrouter (callback/login don't need it).
	var patAuth middleware.PATAuthFunc
	if s.DB != nil {
		patAuth = s.authenticatePAT
	}
	r.Path(signOutPath).Handler(middleware.LoadSession(s.registry.resolve, s.sessionStore, patAuth)(http.HandlerFunc(s.Logout)))
	// /verify loads the session and returns a JSON body designed for
	// external gateway auth_request integration (nginx, Kong, Envoy).
	r.Path(verifyPath).Handler(middleware.LoadSession(s.registry.resolve, s.sessionStore, patAuth)(http.HandlerFunc(s.Verify)))
}

func (s *Server) setupTLS(srv *http.Server) error {
	protos := []string{"http/1.1"}
	if s.ServeCfg.Http2 {
		protos = append(protos, "h2")
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS12, // default, override below
		MaxVersion: tls.VersionTLS13,
		NextProtos: protos,
	}

	if s.ServeCfg.Port <= 0 {
		s.ServeCfg.Port = 8443
	}

	cert, err := tls.LoadX509KeyPair(s.ServeCfg.TLS.CertPath, s.ServeCfg.TLS.KeyPath)
	if err != nil {
		s.Logger.Error("could not load certificate", ezlog.Err(err))
		return fmt.Errorf("load x509 key pair: %w", err)
	}
	config.Certificates = []tls.Certificate{cert}

	if len(s.ServeCfg.TLS.CipherSuites) > 0 {
		cipherSuites, err := parseCipherSuites(s.ServeCfg.TLS.CipherSuites)
		if err != nil {
			s.Logger.Error("could not parse cipher suites", ezlog.Err(err))
			return err
		}
		config.CipherSuites = cipherSuites
	}

	switch s.ServeCfg.TLS.Version {
	case "TLS1.2":
		config.MinVersion = tls.VersionTLS12
	case "TLS1.3":
		config.MinVersion = tls.VersionTLS13
	default:
		return fmt.Errorf("unsupported TLS version %q, use TLS1.2 or TLS1.3", s.ServeCfg.TLS.Version)
	}

	srv.TLSConfig = config
	return nil
}

func parseCipherSuites(names []string) ([]uint16, error) {
	cipherNameMap := make(map[string]uint16)

	for _, cipherSuite := range tls.CipherSuites() {
		cipherNameMap[cipherSuite.Name] = cipherSuite.ID
	}
	for _, cipherSuite := range tls.InsecureCipherSuites() {
		cipherNameMap[cipherSuite.Name] = cipherSuite.ID
	}

	result := make([]uint16, len(names))
	for i, name := range names {
		id, present := cipherNameMap[name]
		if !present {
			return nil, fmt.Errorf("unknown TLS cipher suite name specified %q", name)
		}
		result[i] = id
	}
	return result, nil
}

// portalPageData holds template data shared across all admin portal pages.
type portalPageData struct {
	AppName      string
	HideAppName  bool
	LogoData     template.HTML
	LogoURL      string
	AuthPrefix   string
	StaticPrefix string
	ActivePage   string
	CSRFToken    string
	RBACEnabled  bool
	AuditEnabled bool
	DBEnabled    bool
	Username     string
	UserInitials string
}

func (s *Server) newPortalData(req *http.Request, activePage string) portalPageData {
	var username string
	if ri := ezapi.GetRequest(req); ri != nil && ri.Session != nil {
		username = ri.Session.User
		if username == "" {
			username = ri.Session.PreferredUsername
		}
	}
	initials := "?"
	if len(username) >= 2 {
		initials = strings.ToUpper(username[:2])
	} else if len(username) == 1 {
		initials = strings.ToUpper(username[:1])
	}
	r := s.renderer
	var logoData template.HTML
	if r != nil {
		logoData = r.Logo()
	}
	return portalPageData{
		AppName:      s.ServeCfg.AppName,
		HideAppName:  s.ServeCfg.HideAppName,
		LogoData:     logoData,
		LogoURL:      s.ServeCfg.StaticPrefix + "/logo",
		AuthPrefix:   s.ServeCfg.AuthPrefix,
		StaticPrefix: s.ServeCfg.StaticPrefix,
		ActivePage:   activePage,
		CSRFToken:    middleware.Token(req),
		RBACEnabled:  s.rbacController != nil,
		AuditEnabled: s.auditCore != nil,
		DBEnabled:    s.DB != nil,
		Username:     username,
		UserInitials: initials,
	}
}

func (s *Server) renderPortalPage(rw http.ResponseWriter, req *http.Request, tmplName string, activePage string) {
	logger := s.requestLogger(req)
	r := s.renderer
	if r == nil {
		logger.Error("admin portal renderer not initialized")
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	out, err := r.Execute(tmplName, s.newPortalData(req, activePage))
	if err != nil {
		logger.Error("error rendering admin portal page", ezlog.Str("template", tmplName), ezlog.Err(err))
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	noCacheHeader(rw)
	_, _ = rw.Write(out) //nolint:gosec // out is html/template output, already sanitized
}

func (s *Server) portalRouter(r *mux.Router) {
	rend := s.renderer
	if rend != nil {
		r.Path("/overview").Name("admin::portal::overview").HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			s.renderPortalPage(rw, req, "admin/overview.html", "overview")
		})
		r.Path("/users").Name("admin::portal::users").HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			s.renderPortalPage(rw, req, "admin/users.html", "users")
		})
		r.Path("/groups").Name("admin::portal::groups").HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			s.renderPortalPage(rw, req, "admin/groups.html", "groups")
		})
		r.Path("/roles").Name("admin::portal::roles").HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if s.rbacController == nil {
				http.Redirect(rw, req, s.ServeCfg.AuthPrefix+portalPath+"/overview", http.StatusFound)
				return
			}
			s.renderPortalPage(rw, req, "admin/roles.html", "roles")
		})
		r.Path("/policies").Name("admin::portal::policies").HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if s.rbacController == nil {
				http.Redirect(rw, req, s.ServeCfg.AuthPrefix+portalPath+"/overview", http.StatusFound)
				return
			}
			s.renderPortalPage(rw, req, "admin/policies.html", "policies")
		})
		r.Path("/providers").Name("admin::portal::providers").HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			s.renderPortalPage(rw, req, "admin/providers.html", "providers")
		})
		r.Path("/audit").Name("admin::portal::audit").HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if s.auditCore == nil {
				http.Redirect(rw, req, s.ServeCfg.AuthPrefix+portalPath+"/overview", http.StatusFound)
				return
			}
			s.renderPortalPage(rw, req, "admin/audit.html", "audit")
		})
		// Default redirect to overview.
		r.PathPrefix("").HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			http.Redirect(rw, req, s.ServeCfg.AuthPrefix+portalPath+"/overview", http.StatusFound)
		})
	}
}

// selfPortalRouter registers the self-service portal pages (profile, tokens)
// on r using sessionChain — no AdminGate required. These routes are always
// visible to any authenticated user.
func (s *Server) selfPortalRouter(r *mux.Router, authPrefix string, chain middleware.Chain) {
	if s.renderer == nil {
		return
	}
	r.Path(authPrefix + portalPath + "/profile").Name("admin::portal::profile").Handler(chain.ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
		s.renderPortalPage(rw, req, "admin/profile.html", "profile")
	}))
	r.Path(authPrefix + portalPath + "/tokens").Name("admin::portal::tokens").Handler(chain.ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
		if s.DB == nil {
			http.Redirect(rw, req, authPrefix+portalPath+"/profile", http.StatusFound)
			return
		}
		s.renderPortalPage(rw, req, "admin/tokens.html", "tokens")
	}))
}
