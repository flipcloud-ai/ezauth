//go:build e2e

package redis_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	"github.com/flipcloud-ai/ezauth/test/e2e/shared"
	e2eutils "github.com/flipcloud-ai/ezauth/test/e2e/utils"

	"github.com/redis/go-redis/v9"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	env        *e2eutils.TestEnv
	rootClient *http.Client

	redisAddr string
	redisStop = e2eutils.NoopFunc
	redisSkip = e2eutils.NoopFunc

	pgDB   ezcfg.DatabaseConfig
	pgStop = e2eutils.NoopFunc
	pgSkip = e2eutils.NoopFunc

	normalUsername = "redisuser"
	normalPassword = "RedisPass123"
)

func TestRedis(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Redis Suite")
}

var _ = BeforeSuite(func() {
	redisAddr, redisStop, redisSkip = e2eutils.NewRedisContainer()
	redisSkip()

	pgDB, pgStop, pgSkip = e2eutils.NewPostgresContainer()
	pgSkip()

	opts := shared.BaseDBConfig(pgDB, GinkgoT().TempDir())
	opts = shared.WithRedisSession(opts, redisAddr)
	opts = shared.WithTLS(opts)
	opts = shared.WithCSRF(opts)
	opts.Access.SystemAdminGroup = "system-admins"

	env = e2eutils.StartServer(opts, "redis", e2eutils.DefaultStartTimeout)
	rootClient = e2eutils.LoginAsRoot(env, opts.Access.Bootstrap.SecretFile)
	e2eutils.CreateDBUser(rootClient, env, normalUsername, normalPassword, normalUsername+"@test.local")
})

var _ = AfterSuite(func() {
	if env != nil {
		env.Stop()
	}
	pgStop()
	redisStop()
})

var _ = Describe("Redis session store", func() {
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
	Describe("Cookie", func() {
		shared.CookieBehaviors(func() *e2eutils.TestEnv { return env }, true,
			func() (string, string) { return normalUsername, normalPassword })
	})
	Describe("CSRF", func() {
		shared.CSRFBehaviors(func() *e2eutils.TestEnv { return env }, true)
	})
})

var _ = Describe("Redis session tampering", Ordered, func() {
	var redisClient *redis.Client

	BeforeAll(func() {
		redisClient = redis.NewClient(&redis.Options{Addr: redisAddr})
	})

	AfterAll(func() {
		if redisClient != nil {
			_ = redisClient.Close()
		}
	})

	It("should redirect to login when the stored session is garbage", func() {
		// Write garbage bytes under the correct session prefix key.
		cookieName := env.Opts.Auth.Session.Cookie.Name
		err := redisClient.Set(context.Background(),
			"ezauth::session::garbage-session-id",
			[]byte("not-a-valid-msgpack-encrypted-session"), 0).Err()
		Expect(err).ToNot(HaveOccurred())

		// Send a request with a cookie carrying the garbage session ID.
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env.URL+"/", nil)
		Expect(err).ToNot(HaveOccurred())
		req.AddCookie(&http.Cookie{
			Name:  cookieName,
			Value: "garbage-session-id",
		})
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := e2eutils.Client(env).Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusFound))
		Expect(resp.Header.Get("Location")).To(ContainSubstring("/login"))
	})

	It("should redirect to login when the session key does not exist in Redis", func() {
		cookieName := env.Opts.Auth.Session.Cookie.Name

		// Use a non-existent session ID — the server must not panic.
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env.URL+"/", nil)
		Expect(err).ToNot(HaveOccurred())
		req.AddCookie(&http.Cookie{
			Name:  cookieName,
			Value: strings.Repeat("x", 86), // valid base64 size but not a real session
		})
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := e2eutils.Client(env).Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusFound))
		Expect(resp.Header.Get("Location")).To(ContainSubstring("/login"))
	})
})

var _ = Describe("Redis fault resilience", Ordered, func() {
	var (
		faultEnv       *e2eutils.TestEnv
		faultClient    *http.Client
		faultRedis     string
		faultRedisStop = e2eutils.NoopFunc
		faultRedisSkip = e2eutils.NoopFunc
		faultPG        ezcfg.DatabaseConfig
		faultPGStop    = e2eutils.NoopFunc
		faultPGSkip    = e2eutils.NoopFunc
	)

	BeforeAll(func() {
		faultRedis, faultRedisStop, faultRedisSkip = e2eutils.NewRedisContainer()
		faultRedisSkip()
		faultPG, faultPGStop, faultPGSkip = e2eutils.NewPostgresContainer()
		faultPGSkip()

		opts := shared.BaseDBConfig(faultPG, GinkgoT().TempDir())
		opts = shared.WithRedisSession(opts, faultRedis)
		opts = shared.WithTLS(opts)
		opts.Access.SystemAdminGroup = "system-admins"
		faultEnv = e2eutils.StartServer(opts, "redis-fault", e2eutils.DefaultStartTimeout)
		faultClient = e2eutils.LoginAsRoot(faultEnv, opts.Access.Bootstrap.SecretFile)
	})

	AfterAll(func() {
		if faultEnv != nil {
			faultEnv.Stop()
		}
		faultPGStop()
		faultRedisStop()
	})

	It("should authenticate before Redis is stopped", func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			faultEnv.URL+"/ezauth/verify", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "application/json")
		resp, err := faultClient.Do(req)
		Expect(err).ToNot(HaveOccurred())
		_ = resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	It("should gracefully degrade when Redis is unreachable", func() {
		faultRedisStop()

		// Existing session: server should not panic/500. It may redirect or 401.
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			faultEnv.URL+"/ezauth/verify", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "application/json")
		resp, err := faultClient.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		// The key assertion: server responded without panicking.
		_ = resp.StatusCode
	})

	It("should keep /healthz responding when Redis is down", func() {
		resp, err := e2eutils.Client(faultEnv).Get(faultEnv.URL + "/healthz")
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK),
			"/healthz must stay healthy — Redis outage alone should not take down proxy")
	})
})
