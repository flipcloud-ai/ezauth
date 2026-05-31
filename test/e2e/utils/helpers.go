//go:build e2e

package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	_ "github.com/jackc/pgx/v5/stdlib"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"gopkg.in/yaml.v3"

	ezcfg "github.com/flipcloud-ai/ezauth/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// ── Environment ───────────────────────────────────────────────────────────────

// TestEnv holds a running server and its resolved configuration.
type TestEnv struct {
	URL  string
	Opts ezcfg.Options
	Stop func()
}

// ClusterMode returns true when tests run against a live cluster.
func ClusterMode() bool { return os.Getenv("EZAUTH_E2E_HOST") != "" }

// ClusterNamespace returns the Kubernetes namespace for the deployed instance.
func ClusterNamespace() string {
	ns := os.Getenv("EZAUTH_E2E_NAMESPACE")
	if ns == "" {
		ns = "ezauth"
	}
	return ns
}

// ClusterDexURL returns the external Dex issuer URL.
func ClusterDexURL() string {
	if u := os.Getenv("EZAUTH_E2E_DEX_URL"); u != "" {
		return u
	}
	return "https://dex.dev.flipcloud.ai"
}

// ── Client ────────────────────────────────────────────────────────────────────

// Client returns an *http.Client that does not follow redirects.
// For HTTPS environments it skips certificate verification (self-signed cert).
// In cluster mode it routes through the NLB with the correct virtual Host header.
func Client(env *TestEnv) *http.Client {
	if ClusterMode() {
		u, err := url.Parse(env.URL)
		Expect(err).ToNot(HaveOccurred())
		return &http.Client{
			Transport: &clusterTransport{
				virtualHost: u.Hostname(),
				inner: &http.Transport{
					TLSClientConfig: &tls.Config{
						ServerName:         u.Hostname(),
						InsecureSkipVerify: true, //nolint:gosec // NLB has no matching cert for its own hostname
					},
					DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, network, os.Getenv("EZAUTH_E2E_HOST")+":443")
					},
				},
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	var transport http.RoundTripper
	if env.Opts.Server.TLS.Enabled {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed cert in tests
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				if host == "localhost" {
					addr = net.JoinHostPort("127.0.0.1", port)
				}
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		}
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ClientWithJar returns an *http.Client with a cookie jar so cookies (including
// CSRF session cookies) are carried automatically across requests.
func ClientWithJar(env *TestEnv) *http.Client {
	c := Client(env)
	jar, err := cookiejar.New(nil)
	Expect(err).ToNot(HaveOccurred())
	c.Jar = jar
	return c
}

type clusterTransport struct {
	virtualHost string
	inner       http.RoundTripper
}

func (t *clusterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if h := req.URL.Hostname(); h == "127.0.0.1" || h == "localhost" {
		return http.DefaultTransport.RoundTrip(req)
	}
	r := req.Clone(req.Context())
	r.Host = t.virtualHost
	r.URL.Host = t.virtualHost
	r.URL.Scheme = "https"
	return t.inner.RoundTrip(r)
}

// ── Config rendering ──────────────────────────────────────────────────────────

// RenderConfig renders opts into a temporary config file using the e2e template.
// If label is non-empty and not in cluster mode, a copy is written to
// test/e2e/config/<label>.yaml for post-run inspection.
func RenderConfig(opts ezcfg.Options, label string) string {
	tmplPath := filepath.Join(RepoRoot(), "test", "config", "template", "e2e.yaml.tmpl")
	raw, err := os.ReadFile(tmplPath) //nolint:gosec
	Expect(err).ToNot(HaveOccurred())

	funcMap := template.FuncMap{
		"urlStr": func(u *url.URL) string {
			if u == nil {
				return ""
			}
			return u.String()
		},
	}
	tmpl, err := template.New("e2e").Funcs(funcMap).Parse(string(raw))
	Expect(err).ToNot(HaveOccurred())

	var buf bytes.Buffer
	Expect(tmpl.Execute(&buf, opts)).To(Succeed())

	if !ClusterMode() && label != "" {
		outDir := filepath.Join(RepoRoot(), "test", "e2e", "config")
		_ = os.MkdirAll(outDir, 0755) //nolint:gosec
		_ = os.WriteFile(filepath.Join(outDir, label+".yaml"), buf.Bytes(), 0600)
	}

	cfgFile := filepath.Join(GinkgoT().TempDir(), "config.yaml")
	Expect(os.WriteFile(cfgFile, buf.Bytes(), 0600)).To(Succeed())
	return cfgFile
}

// MergeHelmValues deep-merges opts on top of a Helm values YAML file and
// writes the result to a temp file, returning its path.
func MergeHelmValues(source string, opts ezcfg.Options) string {
	if !filepath.IsAbs(source) {
		source = filepath.Join(RepoRoot(), source)
	}
	raw, err := os.ReadFile(source) //nolint:gosec
	Expect(err).ToNot(HaveOccurred())

	var vals map[string]any
	Expect(yaml.Unmarshal(raw, &vals)).To(Succeed())
	if vals == nil {
		vals = map[string]any{}
	}

	optsBytes, err := yaml.Marshal(opts)
	Expect(err).ToNot(HaveOccurred())
	var optsMap map[string]any
	Expect(yaml.Unmarshal(optsBytes, &optsMap)).To(Succeed())
	delete(optsMap, "database")
	// Remove local-only server fields that would conflict with the cluster
	// deployment, but preserve sub-configs like portal, metrics, and pprof.
	if srv, ok := optsMap["server"].(map[string]any); ok {
		delete(srv, "port")
		delete(srv, "hostname")
		delete(srv, "upstream")
		delete(srv, "tls")
		delete(srv, "auth_prefix")
		delete(srv, "static_prefix")
	}

	baseCfg, _ := vals["config"].(map[string]any)
	if baseCfg == nil {
		baseCfg = map[string]any{}
	}
	vals["config"] = deepMerge(baseCfg, optsMap)
	vals["secrets"] = map[string]any{
		"jwtSecret":    string(opts.Auth.JWT.SecretKey.Bytes()),
		"cookieSecret": string(opts.Auth.Session.Cookie.Secret.Bytes()),
	}

	merged, err := yaml.Marshal(vals)
	Expect(err).ToNot(HaveOccurred())

	f := filepath.Join(GinkgoT().TempDir(), "values.yaml")
	Expect(os.WriteFile(f, merged, 0600)).To(Succeed())
	return f
}

func deepMerge(base, overlay map[string]any) map[string]any {
	for k, ov := range overlay {
		if ovm, ok := ov.(map[string]any); ok {
			if bm, ok := base[k].(map[string]any); ok {
				base[k] = deepMerge(bm, ovm)
			} else {
				base[k] = ovm
			}
		} else if ov != nil && ov != "" && ov != 0 && ov != false {
			base[k] = ov
		}
	}
	return base
}

// ── Runner ────────────────────────────────────────────────────────────────────

// StartServer starts a server from opts and blocks until /healthz returns 200.
// label is used to dump the rendered config for inspection (non-cluster only).
// When opts.Server.Upstream is nil, a simple httptest.Server is automatically
// started and wired as the upstream so tests are not affected by whatever may
// be listening on the default port (127.0.0.1:8080).
func StartServer(opts ezcfg.Options, label string, timeout time.Duration) *TestEnv {
	if ClusterMode() {
		return startCluster(opts, timeout)
	}

	// Auto-provision a throwaway upstream when none is specified.
	var autoUpstream *httptest.Server
	if opts.Server.Upstream == nil {
		autoUpstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		u, err := url.Parse(autoUpstream.URL)
		Expect(err).ToNot(HaveOccurred())
		opts.Server.Upstream = u
	}

	scheme := "http"
	if opts.Server.TLS.Enabled {
		scheme = "https"
	}
	srvURL := fmt.Sprintf("%s://localhost:%d", scheme, opts.Server.Port)
	cfgFile := RenderConfig(opts, label)

	bin := filepath.Join(RepoRoot(), "ezauth")
	cmd := exec.Command(bin, "-f", cfgFile) //nolint:gosec
	// Use GinkgoWriter so Ginkgo's output interceptor can safely close the pipe
	// between specs without blocking. Assigning os.Stderr directly would keep
	// the interceptor's pipe open for the lifetime of the server process and
	// cause the "output interception is getting stuck" warning.
	cmd.Stdout = GinkgoWriter
	cmd.Stderr = GinkgoWriter
	Expect(cmd.Start()).To(Succeed())

	env := &TestEnv{
		URL:  srvURL,
		Opts: opts,
		Stop: func() {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(syscall.SIGTERM)
				_ = cmd.Wait()
			}
			if autoUpstream != nil {
				autoUpstream.Close()
			}
		},
	}

	healthClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	Eventually(func() error {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srvURL+"/healthz", nil)
		if err != nil {
			return err
		}
		resp, err := healthClient.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("healthz: %d", resp.StatusCode)
		}
		return nil
	}).WithTimeout(timeout).WithPolling(200 * time.Millisecond).Should(Succeed())

	return env
}

func startCluster(opts ezcfg.Options, timeout time.Duration) *TestEnv {
	ns := ClusterNamespace()
	for _, v := range []string{"AWS_REGION", "SECRET_NAME", "REDIS_SECRET_NAME", "GHCR_TOKEN"} {
		Expect(os.Getenv(v)).ToNot(BeEmpty(), "%s must be set in cluster mode", v)
	}

	source := os.Getenv("EZAUTH_E2E_HELM_VALUES")
	Expect(source).ToNot(BeEmpty(), "EZAUTH_E2E_HELM_VALUES must be set in cluster mode")

	release := os.Getenv("EZAUTH_E2E_RELEASE")
	if release == "" {
		release = "ezauth"
	}
	os.Setenv("DEPLOY_DEX", "true")

	valuesFile := MergeHelmValues(source, opts)
	script := filepath.Join(RepoRoot(), "scripts", "helm-deploy.sh")
	cmd := exec.Command(script, release, ns, valuesFile) //nolint:gosec
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	Expect(cmd.Run()).To(Succeed(), "helm-deploy.sh %s failed", release)

	virtualHost := os.Getenv("EZAUTH_E2E_HOST")
	Expect(virtualHost).ToNot(BeEmpty())
	srvURL := "https://" + virtualHost
	env := &TestEnv{URL: srvURL, Opts: opts, Stop: func() {}}

	g := NewGomega(func(msg string, _ ...int) {
		AbortSuite(fmt.Sprintf("cluster healthz not ready within %s: %s", timeout, msg))
	})
	g.Eventually(func() error {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srvURL+"/healthz", nil)
		if err != nil {
			return err
		}
		resp, err := Client(env).Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("healthz: %d", resp.StatusCode)
		}
		return nil
	}).WithTimeout(timeout).WithPolling(5 * time.Second).Should(Succeed())

	return env
}

// ── PostgreSQL container ──────────────────────────────────────────────────────

// NewPostgresContainer starts a PostgreSQL testcontainer and returns a ready
// DatabaseConfig, a stop function, and a skip function (called if Docker is unavailable).
func NewPostgresContainer() (ezcfg.DatabaseConfig, func(), func()) {
	ctx := context.Background()
	pg, err := tcpostgres.Run(ctx, "postgres:15-alpine",
		tcpostgres.WithDatabase("ezauth"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("password"),
	)
	stop := func() {
		if pg != nil {
			_ = pg.Terminate(context.Background())
		}
	}
	if err != nil {
		return ezcfg.DatabaseConfig{}, stop, func() {
			Skip(fmt.Sprintf("PostgreSQL container unavailable (Docker required): %v", err))
		}
	}

	connStr, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		stop()
		return ezcfg.DatabaseConfig{}, stop, func() {
			Skip(fmt.Sprintf("Failed to get connection string: %v", err))
		}
	}

	ready := false
	for range 20 {
		db, err := sql.Open("pgx", connStr)
		if err == nil {
			if err := db.Ping(); err == nil {
				db.Close()
				ready = true
				break
			}
			db.Close()
		}
		time.Sleep(2 * time.Second)
	}
	if !ready {
		stop()
		return ezcfg.DatabaseConfig{}, stop, func() {
			Skip("PostgreSQL not ready after 40 seconds")
		}
	}

	host, err := pg.Host(ctx)
	Expect(err).ToNot(HaveOccurred())
	mappedPort, err := pg.MappedPort(ctx, "5432")
	Expect(err).ToNot(HaveOccurred())

	dbCfg := ezcfg.DatabaseConfig{
		Driver:         "pgx",
		Hostname:       host,
		Port:           int(mappedPort.Num()),
		Name:           "ezauth",
		User:           "postgres",
		Password:       ezcfg.NewResolvedSecretRef([]byte("password")),
		SSL:            ezcfg.DatabaseTLSConfig{Mode: "disable"},
		ConnectTimeout: 10 * time.Second,
	}
	return dbCfg, stop, func() {}
}

// ── Redis container ────────────────────────────────────────────────────────────

// NewRedisContainer starts a Redis 7 testcontainer and returns the address,
// a stop function, and a skip function (called if Docker is unavailable).
func NewRedisContainer() (string, func(), func()) {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "redis:7-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	stop := func() {
		if c != nil {
			_ = c.Terminate(context.Background())
		}
	}
	if err != nil {
		return "", stop, func() {
			Skip(fmt.Sprintf("Redis container unavailable (Docker required): %v", err))
		}
	}

	host, err := c.Host(ctx)
	Expect(err).ToNot(HaveOccurred())
	mappedPort, err := c.MappedPort(ctx, "6379")
	Expect(err).ToNot(HaveOccurred())

	return fmt.Sprintf("%s:%s", host, mappedPort.Port()), stop, func() {}
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

// LoginAs performs a real login and returns an authenticated *http.Client.
func LoginAs(env *TestEnv, username, password string) *http.Client {
	jar, err := cookiejar.New(nil)
	Expect(err).ToNot(HaveOccurred())

	base := Client(env)
	base.Jar = jar

	loginURL := env.URL + env.Opts.Server.AuthPrefix + "/login"

	getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
	Expect(err).ToNot(HaveOccurred())
	getResp, err := base.Do(getReq)
	Expect(err).ToNot(HaveOccurred())
	body, err := io.ReadAll(getResp.Body)
	_ = getResp.Body.Close()
	Expect(err).ToNot(HaveOccurred())

	csrfToken := ExtractCSRFToken(body)

	form := url.Values{
		"username":   {username},
		"password":   {password},
		"csrf_token": {csrfToken},
	}
	postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, loginURL,
		strings.NewReader(form.Encode()))
	Expect(err).ToNot(HaveOccurred())
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Origin", env.URL)

	resp, err := base.Do(postReq)
	Expect(err).ToNot(HaveOccurred())
	_ = resp.Body.Close()
	Expect(resp.StatusCode).To(BeElementOf(http.StatusOK, http.StatusFound),
		"login as %q failed with %d", username, resp.StatusCode)

	inner := base.Transport
	if inner == nil {
		inner = http.DefaultTransport
	}
	base.Transport = &CSRFTransport{Base: inner, Token: csrfToken}
	return base
}

// ExtractCSRFToken parses the CSRF token from a login page HTML response.
func ExtractCSRFToken(body []byte) string {
	const needle = `name="csrf_token" value="`
	_, after, found := bytes.Cut(body, []byte(needle))
	if !found {
		return ""
	}
	token, _, _ := bytes.Cut(after, []byte(`"`))
	result := html.UnescapeString(string(token))
	return result
}

// CSRFTransport injects X-CSRF-Token on all mutating requests.
type CSRFTransport struct {
	Base  http.RoundTripper
	Token string
}

func (t *CSRFTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
	default:
		if t.Token != "" {
			req = req.Clone(req.Context())
			req.Header.Set("X-CSRF-Token", t.Token)
			req.Header.Set("Origin", req.URL.Scheme+"://"+req.URL.Host)
		}
	}
	return t.Base.RoundTrip(req)
}

// ReadBootstrapSecret reads the base64-encoded "user:password" bootstrap file
// and returns the password.
func ReadBootstrapSecret(path string) string {
	if ClusterMode() {
		return ClusterRootPassword()
	}
	raw, err := os.ReadFile(path) //nolint:gosec
	Expect(err).ToNot(HaveOccurred(), "bootstrap secret file %q not found", path)
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	Expect(err).ToNot(HaveOccurred())
	_, password, ok := strings.Cut(string(decoded), ":")
	Expect(ok).To(BeTrue(), "bootstrap secret must be user:password")
	return password
}

// ClusterRootPassword returns the root password from the cluster bootstrap secret.
var ClusterRootPassword = sync.OnceValue(func() string {
	ns := ClusterNamespace()
	raw, err := exec.Command(
		"kubectl", "get", "secret", "ezauth-bootstrap-secret",
		"-n", ns, "-o", "jsonpath={.data.root_secret}",
	).Output()
	Expect(err).ToNot(HaveOccurred())
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	Expect(err).ToNot(HaveOccurred())
	_, password, ok := strings.Cut(string(decoded), ":")
	Expect(ok).To(BeTrue())
	return password
})

// ── Browser ───────────────────────────────────────────────────────────────────

// NewBrowser launches a headless Chrome browser for use in tests.
func NewBrowser() *rod.Browser {
	l := launcher.New().Headless(true).NoSandbox(true).
		Set("disable-gpu", "").
		Set("disable-dev-shm-usage", "").
		Set("ignore-certificate-errors")
	if path, ok := launcher.LookPath(); ok {
		l = l.Bin(path)
	}
	u, err := l.Launch()
	Expect(err).ToNot(HaveOccurred())
	return rod.New().ControlURL(u).MustConnect()
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

// DoJSON sends a JSON request to env.URL+path using client c.
func DoJSON(c *http.Client, env *TestEnv, method, path string, body any) *http.Response {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		Expect(err).ToNot(HaveOccurred())
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, env.URL+path, r)
	Expect(err).ToNot(HaveOccurred())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	Expect(err).ToNot(HaveOccurred())
	return resp
}

func Get(c *http.Client, env *TestEnv, path string) *http.Response {
	return DoJSON(c, env, http.MethodGet, path, nil)
}
func Post(c *http.Client, env *TestEnv, path string, b any) *http.Response {
	return DoJSON(c, env, http.MethodPost, path, b)
}
func Put(c *http.Client, env *TestEnv, path string, b any) *http.Response {
	return DoJSON(c, env, http.MethodPut, path, b)
}
func Del(c *http.Client, env *TestEnv, path string, b any) *http.Response {
	return DoJSON(c, env, http.MethodDelete, path, b)
}

// DecodeData decodes a {"data":{…}} response body.
func DecodeData(resp *http.Response) map[string]any {
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Data map[string]any `json:"data"`
	}
	Expect(json.NewDecoder(resp.Body).Decode(&body)).To(Succeed())
	return body.Data
}

// DecodeList decodes a {"data":[…]} response body.
func DecodeList(resp *http.Response) []map[string]any {
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Data []map[string]any `json:"data"`
	}
	Expect(json.NewDecoder(resp.Body).Decode(&body)).To(Succeed())
	return body.Data
}

// ── Misc ──────────────────────────────────────────────────────────────────────

// NoopFunc is a convenience no-op for stop/skip callbacks.
func NoopFunc() {}

// FreePort returns an available TCP port on localhost.
func FreePort() int {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Sprintf("freePort: %v", err))
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// RepoRoot returns the absolute path to the repository root.
func RepoRoot() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "../../..")
}

// DefaultStartTimeout is the standard server startup deadline used across all suites.
const DefaultStartTimeout = 30 * time.Second

// LoginAsRoot reads the bootstrap secret file and logs in as root, returning
// an authenticated client. Shorthand for ReadBootstrapSecret + LoginAs.
func LoginAsRoot(env *TestEnv, bootstrapSecretFile string) *http.Client {
	return LoginAs(env, "root", ReadBootstrapSecret(bootstrapSecretFile))
}

// CreateDBUser creates a DB user via the admin API and returns the new user's UUID.
// In cluster mode, any existing user with the same username is deleted first so
// the call is idempotent across test runs sharing a persistent database.
func CreateDBUser(c *http.Client, env *TestEnv, username, password, email string) string {
	if ClusterMode() {
		resp := Get(c, env, "/ezauth/users/")
		if resp.StatusCode == http.StatusOK {
			for _, u := range DecodeList(resp) {
				if fmt.Sprint(u["username"]) == username {
					Del(c, env, "/ezauth/users/", map[string]any{"id": u["id"]})
					break
				}
			}
		} else {
			_ = resp.Body.Close()
		}
	}

	resp := Post(c, env, "/ezauth/users/", map[string]any{
		"username":   username,
		"password":   password,
		"email":      email,
		"birth_date": "1990-01-01T00:00:00Z",
		"address":    map[string]string{"country": "US"},
	})
	defer func() { _ = resp.Body.Close() }()
	Expect(resp.StatusCode).To(Equal(http.StatusCreated), "create user %q failed", username)
	body := DecodeData(resp)
	if id, ok := body["id"]; ok {
		return fmt.Sprint(id)
	}
	return ""
}

// CapturingUpstream starts an httptest.Server that records the last request's
// headers. The returned getter is safe to call concurrently with the handler.
func CapturingUpstream() (*httptest.Server, func() http.Header) {
	var mu sync.Mutex
	var last http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	return srv, func() http.Header {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}
