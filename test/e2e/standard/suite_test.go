//go:build e2e

package standard_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	"github.com/flipcloud-ai/ezauth/test/e2e/shared"
	e2eutils "github.com/flipcloud-ai/ezauth/test/e2e/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	env        *e2eutils.TestEnv
	rootClient *http.Client

	normalUsername = "stduser"
	normalPassword = "StdPass123"

	pgDB   ezcfg.DatabaseConfig
	pgStop = e2eutils.NoopFunc
	pgSkip = e2eutils.NoopFunc
)

func TestStandard(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Standard Suite")
}

var _ = BeforeSuite(func() {
	pgDB, pgStop, pgSkip = e2eutils.NewPostgresContainer()
	pgSkip()

	opts := shared.EmptyConfig()
	opts = shared.WithMemoryCache(opts, "10m")
	opts = shared.WithTLS(opts)
	opts = shared.WithCSRF(opts)
	opts = shared.WithDatabase(opts, pgDB)
	opts = shared.WithBootstrap(opts, GinkgoT().TempDir())
	opts.Access.SystemAdminGroup = "system-admins"

	env = e2eutils.StartServer(opts, "standard", e2eutils.DefaultStartTimeout)
	rootClient = e2eutils.LoginAsRoot(env, opts.Access.Bootstrap.SecretFile)
	e2eutils.CreateDBUser(rootClient, env, normalUsername, normalPassword, normalUsername+"@test.local")
})

var _ = AfterSuite(func() {
	if env != nil {
		env.Stop()
	}
	pgStop()
})

var _ = Describe("Standard config", func() {
	Describe("Health", func() {
		shared.HealthBehaviors(func() *e2eutils.TestEnv { return env })
	})
	Describe("Auth flow", func() {
		shared.AuthFlowBehaviors(
			func() *e2eutils.TestEnv { return env },
			func() (string, string) { return normalUsername, normalPassword },
		)
	})
	Describe("Session", func() {
		shared.SessionBehaviors(func() *e2eutils.TestEnv { return env },
			func() (string, string) { return normalUsername, normalPassword })
	})
	Describe("Error pages", func() {
		shared.ErrorPageBehaviors(func() *e2eutils.TestEnv { return env })
	})
	Describe("Cookie", func() {
		// TLS enabled — session cookie must carry Secure flag.
		shared.CookieBehaviors(func() *e2eutils.TestEnv { return env }, true,
			func() (string, string) { return normalUsername, normalPassword })
	})
	Describe("CSRF enforced", func() {
		// TLS + CSRF enabled — missing token must be rejected with 403.
		shared.CSRFBehaviors(func() *e2eutils.TestEnv { return env }, true)
	})
	Describe("Static user rejected in DB mode", func() {
		shared.StaticUserRejectedBehaviors(func() *e2eutils.TestEnv { return env },
			func() (string, string) { return "test", "test1234" })
	})
	Describe("Me API (DB user)", func() {
		// DB users have email in session.
		shared.MeBehaviors(func() *e2eutils.TestEnv { return env },
			func() (string, string) { return normalUsername, normalPassword }, true)
	})
	Describe("Admin gate", func() {
		shared.AdminGateBehaviors(
			func() *e2eutils.TestEnv { return env },
			func() (string, string) {
				return "root", e2eutils.ReadBootstrapSecret(env.Opts.Access.Bootstrap.SecretFile)
			},
			func() (string, string) { return normalUsername, normalPassword },
		)
	})
	Describe("Portal", func() {
		shared.PortalBehaviors(func() *e2eutils.TestEnv { return env }, false)
	})
})

var _ = Describe("Standard upstream proxy", Ordered, func() {
	var (
		upstreamEnv *e2eutils.TestEnv
		upstreamSrv *httptest.Server
		getHeaders  func() http.Header
	)

	BeforeAll(func() {
		upstreamSrv, getHeaders = e2eutils.CapturingUpstream()
		u, err := url.Parse(upstreamSrv.URL)
		Expect(err).ToNot(HaveOccurred())

		opts := shared.EmptyConfig()
		opts = shared.WithMemoryCache(opts, "10m")
		opts = shared.WithTLS(opts)
		opts = shared.WithStaticUser(opts, "test", "test1234")
		opts.Server.Upstream = u
		upstreamEnv = e2eutils.StartServer(opts, "standard-upstream", e2eutils.DefaultStartTimeout)
	})

	AfterAll(func() {
		upstreamEnv.Stop()
		upstreamSrv.Close()
	})

	shared.UpstreamBehaviors(
		func() *e2eutils.TestEnv { return upstreamEnv },
		func() (string, string) { return "test", "test1234" },
		func() http.Header { return getHeaders() },
	)
})
