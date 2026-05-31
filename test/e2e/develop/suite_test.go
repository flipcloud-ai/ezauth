//go:build e2e

package develop_test

import (
	"net/http"
	"testing"
	"time"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	"github.com/flipcloud-ai/ezauth/test/e2e/shared"
	e2eutils "github.com/flipcloud-ai/ezauth/test/e2e/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	env        *e2eutils.TestEnv
	rootClient *http.Client

	normalUsername = "devuser"
	normalPassword = "DevPass123"

	pgDB   ezcfg.DatabaseConfig
	pgStop = e2eutils.NoopFunc
	pgSkip = e2eutils.NoopFunc

	rateLimitEnv *e2eutils.TestEnv
)

func TestDevelop(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Develop Suite")
}

var _ = BeforeSuite(func() {
	pgDB, pgStop, pgSkip = e2eutils.NewPostgresContainer()
	pgSkip()

	opts := shared.EmptyConfig()
	opts = shared.WithMemoryCache(opts, "10m")
	opts = shared.WithTLS(opts)
	opts = shared.WithDatabase(opts, pgDB)
	opts = shared.WithBootstrap(opts, GinkgoT().TempDir())
	opts.Auth.Static = nil
	opts = shared.WithPortal(opts)
	opts = shared.WithDebugLog(opts)
	opts.Server.Pprof.Enabled = true
	opts.Access.SystemAdminGroup = "system-admins"

	env = e2eutils.StartServer(opts, "develop", e2eutils.DefaultStartTimeout)
	rootClient = e2eutils.LoginAsRoot(env, opts.Access.Bootstrap.SecretFile)
	e2eutils.CreateDBUser(rootClient, env, normalUsername, normalPassword, normalUsername+"@test.local")
})

var _ = AfterSuite(func() {
	if env != nil {
		env.Stop()
	}
	pgStop()
})

var _ = Describe("Develop config", func() {
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
		shared.CookieBehaviors(func() *e2eutils.TestEnv { return env }, true,
			func() (string, string) { return normalUsername, normalPassword })
	})
	Describe("CSRF disabled", func() {
		shared.CSRFBehaviors(func() *e2eutils.TestEnv { return env }, false)
	})
	Describe("Static user rejected in DB mode", func() {
		shared.StaticUserRejectedBehaviors(func() *e2eutils.TestEnv { return env },
			func() (string, string) { return "test", "test1234" })
	})
	Describe("Me API (DB user)", func() {
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
		shared.PortalBehaviors(func() *e2eutils.TestEnv { return env }, true,
			func() (string, string) { return normalUsername, normalPassword })
	})

})

var _ = Describe("Rate limit test", Ordered, func() {
	BeforeAll(func() {
		rlOpts := shared.EmptyConfig()
		rlOpts = shared.WithMemoryCache(rlOpts, "10m")
		rlOpts = shared.WithTLS(rlOpts)
		rlOpts = shared.WithDatabase(rlOpts, pgDB)
		// Reuse the main env's bootstrap secret file so the root user password
		// matches what is already in the shared postgres container.
		rlOpts.Access.Bootstrap.SecretFile = env.Opts.Access.Bootstrap.SecretFile
		rlOpts.Auth.Static = nil
		rlOpts = shared.WithDebugLog(rlOpts)
		rlOpts = shared.WithLoginRateLimitCustom(rlOpts, 3, 30*time.Second, 5*time.Second)
		rlOpts.Access.SystemAdminGroup = "system-admins"

		rateLimitEnv = e2eutils.StartServer(rlOpts, "develop-ratelimit", e2eutils.DefaultStartTimeout)
	})
	AfterAll(func() {
		if rateLimitEnv != nil {
			rateLimitEnv.Stop()
		}
	})
	shared.RateLimitBehaviors(func() *e2eutils.TestEnv { return rateLimitEnv }, 3,
		5*time.Second,
		func() (string, string) { return normalUsername, normalPassword })
})
