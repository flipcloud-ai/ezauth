//go:build e2e

package providers_test

import (
	"net/http"

	e2eutils "github.com/flipcloud-ai/ezauth/test/e2e/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func providerBody(name, issuer, clientID, clientSecret string) map[string]any {
	return map[string]any{
		"provider_name": name,
		"type":          "oauth2",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"redirect_url":  "http://localhost/callback",
		"issuer":        issuer,
		"scope":         "openid profile email",
		"enabled":       true,
	}
}

// ── cache >= providers (shared server, cache=10) ──────────────────────────────
// Covered by the main suite server; just verify list works.

var _ = Describe("Provider cache >= providers (cache=10)", Ordered, func() {
	const providersPath = "/ezauth/provider/"

	It("should list providers after creation", func() {
		issuer := "https://accounts.google.com"
		name := randomName()
		resp := e2eutils.DoJSON(rootClient, env, http.MethodPost, providersPath,
			providerBody(name, issuer, "id-"+name, "secret-"+name))
		Expect(resp.StatusCode).To(Equal(http.StatusCreated))
		_ = resp.Body.Close()

		items := e2eutils.DecodeList(e2eutils.DoJSON(rootClient, env, http.MethodGet, providersPath, nil))
		Expect(items).ToNot(BeEmpty())
	})
})

// ── cache=0 ───────────────────────────────────────────────────────────────────

var _ = Describe("Provider cache=0", Ordered, func() {
	var (
		cacheEnv    *e2eutils.TestEnv
		cacheClient *http.Client
		localPgStop = e2eutils.NoopFunc
		localPgSkip = e2eutils.NoopFunc
	)

	const providersPath = "/ezauth/provider/"
	const numProviders = 4

	BeforeAll(func() {
		if e2eutils.ClusterMode() {
			Skip("cache scenarios require a local server")
		}
		localPgDB, stop, skip := e2eutils.NewPostgresContainer()
		localPgStop = stop
		localPgSkip = skip
		localPgSkip()

		opts := providersConfig(localPgDB, 0)
		cacheEnv = e2eutils.StartServer(opts, "providers-cache-0", e2eutils.DefaultStartTimeout)
		cacheClient = e2eutils.LoginAsRoot(cacheEnv, opts.Access.Bootstrap.SecretFile)

		issuer := "https://accounts.google.com"
		for i := 0; i < numProviders; i++ {
			name := randomName()
			resp := e2eutils.DoJSON(cacheClient, cacheEnv, http.MethodPost, providersPath,
				providerBody(name, issuer, "id-"+name, "secret-"+name))
			Expect(resp.StatusCode).To(Equal(http.StatusCreated))
			_ = resp.Body.Close()
		}
	})

	AfterAll(func() {
		if cacheEnv != nil {
			cacheEnv.Stop()
		}
		localPgStop()
	})

	It("should list all providers when cache is disabled", func() {
		items := e2eutils.DecodeList(e2eutils.DoJSON(cacheClient, cacheEnv, http.MethodGet, providersPath, nil))
		Expect(items).To(HaveLen(numProviders))
	})
})

// ── cache < providers ─────────────────────────────────────────────────────────

var _ = Describe("Provider cache < providers (cache=2)", Ordered, func() {
	var (
		cacheEnv    *e2eutils.TestEnv
		cacheClient *http.Client
		localPgStop = e2eutils.NoopFunc
		localPgSkip = e2eutils.NoopFunc
	)

	const providersPath = "/ezauth/provider/"
	const numProviders = 5

	BeforeAll(func() {
		if e2eutils.ClusterMode() {
			Skip("cache scenarios require a local server")
		}
		localPgDB, stop, skip := e2eutils.NewPostgresContainer()
		localPgStop = stop
		localPgSkip = skip
		localPgSkip()

		opts := providersConfig(localPgDB, 2)
		cacheEnv = e2eutils.StartServer(opts, "providers-cache-2", e2eutils.DefaultStartTimeout)
		cacheClient = e2eutils.LoginAsRoot(cacheEnv, opts.Access.Bootstrap.SecretFile)

		issuer := "https://accounts.google.com"
		for i := 0; i < numProviders; i++ {
			name := randomName()
			resp := e2eutils.DoJSON(cacheClient, cacheEnv, http.MethodPost, providersPath,
				providerBody(name, issuer, "id-"+name, "secret-"+name))
			Expect(resp.StatusCode).To(Equal(http.StatusCreated))
			_ = resp.Body.Close()
		}
	})

	AfterAll(func() {
		if cacheEnv != nil {
			cacheEnv.Stop()
		}
		localPgStop()
	})

	It("should list all providers even though cache only holds 2", func() {
		items := e2eutils.DecodeList(e2eutils.DoJSON(cacheClient, cacheEnv, http.MethodGet, providersPath, nil))
		Expect(items).To(HaveLen(numProviders))
	})

	It("should get any provider (cache miss falls back to DB)", func() {
		items := e2eutils.DecodeList(e2eutils.DoJSON(cacheClient, cacheEnv, http.MethodGet, providersPath, nil))
		for _, item := range items {
			name := item["provider_name"].(string)
			resp := e2eutils.DoJSON(cacheClient, cacheEnv, http.MethodGet, providersPath+name, nil)
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			_ = resp.Body.Close()
		}
	})
})
