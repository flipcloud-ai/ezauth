//go:build e2e

package admin_test

import (
	"fmt"
	"math/rand"
	"net/http"
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

	pgDB   ezcfg.DatabaseConfig
	pgStop = e2eutils.NoopFunc
	pgSkip = e2eutils.NoopFunc
)

func TestAdmin(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Admin Suite")
}

var _ = BeforeSuite(func() {
	pgDB, pgStop, pgSkip = e2eutils.NewPostgresContainer()
	pgSkip()

	opts := adminConfig(pgDB)
	env = e2eutils.StartServer(opts, "admin", e2eutils.DefaultStartTimeout)
	rootClient = e2eutils.LoginAsRoot(env, opts.Access.Bootstrap.SecretFile)
})

var _ = AfterSuite(func() {
	if env != nil {
		env.Stop()
	}
	pgStop()
})

// adminConfig builds from EmptyConfig and layers on admin-specific requirements.
func adminConfig(db ezcfg.DatabaseConfig) ezcfg.Options {
	opts := shared.EmptyConfig()
	opts = shared.WithMemoryCache(opts, "10m")
	opts = shared.WithDatabase(opts, db)
	opts = shared.WithBootstrap(opts, GinkgoT().TempDir())
	opts = shared.WithRBAC(opts)
	opts = shared.WithPortal(opts)
	opts = shared.WithProviderCache(opts, 10)
	return opts
}

// ── Thin wrappers binding the shared env to e2eutils helpers ─────────────────

func doJSON(c *http.Client, method, path string, body any) *http.Response {
	return e2eutils.DoJSON(c, env, method, path, body)
}
func get(c *http.Client, path string) *http.Response         { return e2eutils.Get(c, env, path) }
func post(c *http.Client, path string, b any) *http.Response { return e2eutils.Post(c, env, path, b) }
func put(c *http.Client, path string, b any) *http.Response  { return e2eutils.Put(c, env, path, b) }
func del(c *http.Client, path string, b any) *http.Response  { return e2eutils.Del(c, env, path, b) }
func decodeData(resp *http.Response) map[string]any          { return e2eutils.DecodeData(resp) }
func decodeList(resp *http.Response) []map[string]any        { return e2eutils.DecodeList(resp) }

func randomName() string {
	return fmt.Sprintf("p-%x", rand.Int31()) //nolint:gosec
}
