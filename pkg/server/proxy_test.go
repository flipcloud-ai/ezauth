package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/middleware"
	eztmpl "github.com/flipcloud-ai/ezauth/pkg/server/templates"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("proxy", func() {
	Describe("newProxy", func() {
		It("pre-computes cleanedPath via path.Clean", func() {
			cfgs := []ezcfg.SkipAuthConfig{
				{Path: "/api/", Method: "get", Match: "Prefix"},
			}
			pr := newProxy(nil, cfgs)
			Expect(pr.skipPaths).To(HaveLen(1))
			Expect(pr.skipPaths[0].cleanedPath).To(Equal("/api"))
		})

		It("uppercases method", func() {
			cfgs := []ezcfg.SkipAuthConfig{
				{Path: "/hook", Method: "post", Match: "exact"},
			}
			pr := newProxy(nil, cfgs)
			Expect(pr.skipPaths[0].method).To(Equal("POST"))
		})

		It("lowercases match", func() {
			cfgs := []ezcfg.SkipAuthConfig{
				{Path: "/hook", Method: "", Match: "PREFIX"},
			}
			pr := newProxy(nil, cfgs)
			Expect(pr.skipPaths[0].match).To(Equal("prefix"))
		})

		It("returns empty skipPaths for nil config slice", func() {
			pr := newProxy(nil, nil)
			Expect(pr.skipPaths).To(BeEmpty())
		})
	})

	Describe("matchSkipAuth", func() {
		DescribeTable("path matching",
			func(path, method string, skipConfigs []ezcfg.SkipAuthConfig, expected bool) {
				pr := newProxy(nil, skipConfigs)
				req := httptest.NewRequest(method, path, nil)
				Expect(pr.matchSkipAuth(req)).To(Equal(expected))
			},
			Entry("empty config returns false", "/webhook", "POST", nil, false),
			Entry("exact match, same method",
				"/webhook", "POST",
				[]ezcfg.SkipAuthConfig{{Path: "/webhook", Method: "POST", Match: "exact"}},
				true),
			Entry("exact match, wrong method",
				"/webhook", "GET",
				[]ezcfg.SkipAuthConfig{{Path: "/webhook", Method: "POST", Match: "exact"}},
				false),
			Entry("exact match, empty method matches GET",
				"/webhook", "GET",
				[]ezcfg.SkipAuthConfig{{Path: "/webhook", Method: "", Match: "exact"}},
				true),
			Entry("exact match, empty method matches POST",
				"/webhook", "POST",
				[]ezcfg.SkipAuthConfig{{Path: "/webhook", Method: "", Match: "exact"}},
				true),
			Entry("exact mismatch, different path",
				"/other", "POST",
				[]ezcfg.SkipAuthConfig{{Path: "/webhook", Method: "POST", Match: "exact"}},
				false),
			Entry("prefix match, sub-path",
				"/api/webhook", "POST",
				[]ezcfg.SkipAuthConfig{{Path: "/api", Method: "", Match: "prefix"}},
				true),
			Entry("prefix match, exact path",
				"/api", "GET",
				[]ezcfg.SkipAuthConfig{{Path: "/api", Method: "", Match: "prefix"}},
				true),
			Entry("prefix match, no boundary crossing",
				"/apiwebhook", "GET",
				[]ezcfg.SkipAuthConfig{{Path: "/api", Method: "", Match: "prefix"}},
				false),
			Entry("prefix match with trailing slash in config",
				"/api/webhook", "POST",
				[]ezcfg.SkipAuthConfig{{Path: "/api/", Method: "", Match: "prefix"}},
				true),
			Entry("path normalization, double slash",
				"/api//webhook", "POST",
				[]ezcfg.SkipAuthConfig{{Path: "/api/webhook", Method: "", Match: "exact"}},
				true),
			Entry("path traversal does not bypass matching",
				"/public/../admin/secret", "GET",
				[]ezcfg.SkipAuthConfig{{Path: "/public", Method: "", Match: "prefix"}},
				false),
			Entry("method case insensitive",
				"/webhook", "post",
				[]ezcfg.SkipAuthConfig{{Path: "/webhook", Method: "POST", Match: "exact"}},
				true),
			Entry("multiple entries, second matches",
				"/webhook", "POST",
				[]ezcfg.SkipAuthConfig{
					{Path: "/health", Method: "", Match: "exact"},
					{Path: "/webhook", Method: "POST", Match: "exact"},
				},
				true),
			Entry("multiple entries, no match",
				"/webhook", "PUT",
				[]ezcfg.SkipAuthConfig{
					{Path: "/health", Method: "", Match: "exact"},
					{Path: "/webhook", Method: "POST", Match: "exact"},
				},
				false),
			Entry("default match type is exact",
				"/webhook", "POST",
				[]ezcfg.SkipAuthConfig{{Path: "/webhook", Method: "POST"}},
				true),
			Entry("default match type, prefix does not match sub-path",
				"/api/webhook", "POST",
				[]ezcfg.SkipAuthConfig{{Path: "/api", Method: ""}},
				false),
			Entry("match field is case-insensitive (Prefix)",
				"/api/webhook", "POST",
				[]ezcfg.SkipAuthConfig{{Path: "/api", Method: "", Match: "Prefix"}},
				true),
			Entry("match field is case-insensitive (PREFIX)",
				"/api/webhook", "POST",
				[]ezcfg.SkipAuthConfig{{Path: "/api", Method: "", Match: "PREFIX"}},
				true),
		)

		It("is safe for concurrent reads", func() {
			cfgs := []ezcfg.SkipAuthConfig{
				{Path: "/public", Method: "", Match: "prefix"},
				{Path: "/webhook", Method: "POST", Match: "exact"},
			}
			pr := newProxy(nil, cfgs)

			const goroutines = 50
			var wg sync.WaitGroup
			wg.Add(goroutines)
			for i := 0; i < goroutines; i++ {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					req := httptest.NewRequest("GET", "/public/health", nil)
					Expect(pr.matchSkipAuth(req)).To(BeTrue())
				}()
			}
			wg.Wait()
		})
	})
})

// ---------------------------------------------------------------------------
// Proxy handler – covers nil revProxy branch
// ---------------------------------------------------------------------------

var _ = Describe("Proxy handler", func() {
	It("returns 500 when revProxy is nil", func() {
		logger, _ := testutils.SetupTestLogger()
		upstream, _ := url.Parse("http://upstream.example.com")
		s := &Server{
			Logger:   logger,
			revProxy: nil,
			AuthCfg:  ezcfg.AuthConfig{},
			ServeCfg: ezcfg.ServerConfig{Upstream: upstream, TrustForwardedHeaders: testutils.BoolPtr(true)},
		}
		req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
		req = ezapi.AddRequestInfo(req, &ezapi.AuthRequest{
			Session: &ezapi.Session{Profile: ezapi.Profile{User: "alice"}},
		})
		rw := httptest.NewRecorder()
		s.Proxy(rw, req)
		Expect(rw.Code).To(Equal(http.StatusInternalServerError))
	})
})

// ---------------------------------------------------------------------------
// buildSkipAuthChain – covers the nil revProxy branch inside the handler
// ---------------------------------------------------------------------------

var _ = Describe("buildSkipAuthChain nil revProxy", func() {
	It("returns 500 when skipChain handler is invoked with nil revProxy", func() {
		logger, _ := testutils.SetupTestLogger()
		rend, _, _ := eztmpl.New("", "")
		s := &Server{
			Logger:   logger,
			renderer: rend,
			ServeCfg: ezcfg.ServerConfig{AuthPrefix: "/ezauth", TrustForwardedHeaders: testutils.BoolPtr(true)},
			AuthCfg: ezcfg.AuthConfig{
				Proxy: ezcfg.AuthProxyConfig{JSONResponse: true},
			},
			revProxy: nil,
		}
		handler := s.buildSkipAuthChain()
		// Inject minimal session middleware context.
		h := middleware.InitSession(true)(handler)
		req := httptest.NewRequest(http.MethodGet, "/webhook", nil)
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, req)
		Expect(rw.Code).To(Equal(http.StatusInternalServerError))
	})
})
