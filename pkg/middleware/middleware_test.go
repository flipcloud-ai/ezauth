package middleware

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type customError struct {
	code    int
	message string
}

func (e *customError) Error() string {
	return fmt.Sprintf("%d - %s", e.code, e.message)
}

var _ = Describe("Middleware Module Test Suite", func() {
	When("middleware test", func() {
		type requestTableInput struct {
			url                   string
			useTLS                bool
			headers               map[string]string
			trustForwardedHeaders bool
			status                int
			body                  string
			location              string
		}
		var permanentRedirectBody = func(url string) string {
			return fmt.Sprintf("<a href=\"%s\">Permanent Redirect</a>.\n\n", url)
		}
		It("healthz test", func(ctx SpecContext) {
			fn := func(h http.Handler) http.Handler {
				return http.HandlerFunc(Healthz)
			}
			chain := NewChain(fn).Then(nil)
			rec := httptest.NewRecorder()

			r, err := http.NewRequest("GET", "/", nil)
			chain.ServeHTTP(rec, r)
			Expect(err).To(BeNil())
			Expect(rec.Body.String()).To(Equal("XW Proxy is Healthy"))
		})
		It("favicon test", func(ctx SpecContext) {
			chain := NewChain(Favicon("test/path")).Then(nil)
			rec := httptest.NewRecorder()

			r, err := http.NewRequest("GET", "/favicon.ico", nil)
			chain.ServeHTTP(rec, r)
			Expect(err).To(BeNil())
			Expect(rec.Code).To(Equal(302))
			Expect(rec.Header().Get("Location")).To(Equal("/test/path"))
		})
		It("favicon passthrough for non-favicon path", func(ctx SpecContext) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("passthrough"))
			})
			chain := NewChain(Favicon("test/path")).Then(next)
			rec := httptest.NewRecorder()

			r, err := http.NewRequest("GET", "/some/other/path", nil)
			Expect(err).To(BeNil())
			chain.ServeHTTP(rec, r)
			Expect(rec.Code).To(Equal(http.StatusOK))
			Expect(rec.Body.String()).To(Equal("passthrough"))
		})
		It("proxy err test", func(ctx SpecContext) {
			err := &customError{
				code:    401,
				message: "test",
			}
			fn := func(h http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ProxyErrorHandler(w, r, err)
				})
			}
			chain := NewChain(fn).ThenFunc(nil)
			rec := httptest.NewRecorder()

			r, e := http.NewRequest("GET", "/", nil)
			chain.ServeHTTP(rec, r)
			Expect(e).To(BeNil())
			Expect(rec.Code).To(Equal(502))
			Expect(rec.Body.String()).To(Equal("The upstream service is temporarily unavailable. Please try again later."))
		})
		DescribeTable("redirect test", func(in *requestTableInput) {
			reqInfo := &ezapi.AuthRequest{
				TrustForwardedHeaders: in.trustForwardedHeaders,
			}

			req, _ := http.NewRequest("GET", in.url, nil)
			for k, v := range in.headers {
				req.Header.Add(k, v)
			}
			if in.useTLS {
				req.TLS = &tls.ConnectionState{}
			}
			req = ezapi.AddRequestInfo(req, reqInfo)

			fn := func(h http.Handler) http.Handler {
				return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(200)
					_, _ = rw.Write([]byte("test"))
				})
			}

			chain := NewChain(RedirectToHTTPS("8888"), fn).Then(nil)
			rec := httptest.NewRecorder()
			chain.ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(in.status))
			Expect(rec.Body.String()).To(Equal(in.body))

			if in.location != "" {
				Expect(rec.Header().Values("Location")).To(ConsistOf(in.location))
			}
		},
			Entry("without TLS", &requestTableInput{
				url:                   "http://www.randomcloud123.com",
				useTLS:                false,
				headers:               map[string]string{},
				trustForwardedHeaders: false,
				status:                308,
				body:                  permanentRedirectBody("https://www.randomcloud123.com"),
				location:              "https://www.randomcloud123.com",
			}),
			Entry("with TLS", &requestTableInput{
				url:                   "https://www.randomcloud123.com",
				useTLS:                true,
				headers:               map[string]string{},
				trustForwardedHeaders: false,
				status:                200,
				body:                  "test",
			}),
			Entry("without TLS and X-Forwarded-Proto=HTTPS", &requestTableInput{
				url:    "http://example.com",
				useTLS: false,
				headers: map[string]string{
					"X-Forwarded-Proto": "HTTPS",
				},
				trustForwardedHeaders: true,
				status:                200,
				body:                  "test",
			}),
			Entry("without TLS and X-Forwarded-Proto=HTTPS but TrustForwardedHeaders not set", &requestTableInput{
				url:    "http://www.randomcloud123.com",
				useTLS: false,
				headers: map[string]string{
					"X-Forwarded-Proto": "HTTPS",
				},
				trustForwardedHeaders: false,
				status:                308,
				body:                  permanentRedirectBody("https://www.randomcloud123.com"),
				location:              "https://www.randomcloud123.com",
			}),
			Entry("with TLS and X-Forwarded-Proto=HTTPS", &requestTableInput{
				url:    "https://www.randomcloud123.com",
				useTLS: true,
				headers: map[string]string{
					"X-Forwarded-Proto": "HTTPS",
				},
				trustForwardedHeaders: true,
				status:                200,
				body:                  "test",
			}),
			Entry("without TLS and X-Forwarded-Proto=https", &requestTableInput{
				url:    "http://www.randomcloud123.com",
				useTLS: false,
				headers: map[string]string{
					"X-Forwarded-Proto": "https",
				},
				trustForwardedHeaders: true,
				status:                200,
				body:                  "test",
			}),
			Entry("with TLS and X-Forwarded-Proto=https", &requestTableInput{
				url:    "https://www.randomcloud123.com",
				useTLS: true,
				headers: map[string]string{
					"X-Forwarded-Proto": "https",
				},
				trustForwardedHeaders: true,
				status:                200,
				body:                  "test",
			}),
			Entry("without TLS and X-Forwarded-Proto=HTTP", &requestTableInput{
				url:    "http://www.randomcloud123.com",
				useTLS: false,
				headers: map[string]string{
					"X-Forwarded-Proto": "HTTP",
				},
				trustForwardedHeaders: true,
				status:                308,
				body:                  permanentRedirectBody("https://www.randomcloud123.com"),
				location:              "https://www.randomcloud123.com",
			}),
			Entry("with TLS and X-Forwarded-Proto=HTTP", &requestTableInput{
				url:    "https://www.randomcloud123.com",
				useTLS: true,
				headers: map[string]string{
					"X-Forwarded-Proto": "HTTP",
				},
				trustForwardedHeaders: true,
				status:                308,
				body:                  permanentRedirectBody("https://www.randomcloud123.com"),
				location:              "https://www.randomcloud123.com",
			}),
			Entry("without TLS and X-Forwarded-Proto=http", &requestTableInput{
				url:    "https://www.randomcloud123.com",
				useTLS: false,
				headers: map[string]string{
					"X-Forwarded-Proto": "http",
				},
				trustForwardedHeaders: true,
				status:                308,
				body:                  permanentRedirectBody("https://www.randomcloud123.com"),
				location:              "https://www.randomcloud123.com",
			}),
			Entry("with TLS and X-Forwarded-Proto=http", &requestTableInput{
				url:    "https://www.randomcloud123.com",
				useTLS: true,
				headers: map[string]string{
					"X-Forwarded-Proto": "http",
				},
				trustForwardedHeaders: true,
				status:                308,
				body:                  permanentRedirectBody("https://www.randomcloud123.com"),
				location:              "https://www.randomcloud123.com",
			}),
			Entry("without TLS on a non-standard port", &requestTableInput{
				url:                   "http://www.randomcloud123.com:8000",
				useTLS:                false,
				headers:               map[string]string{},
				trustForwardedHeaders: false,
				status:                308,
				body:                  permanentRedirectBody("https://www.randomcloud123.com:8888"),
				location:              "https://www.randomcloud123.com:8888",
			}),
			Entry("with TLS on a non-standard port", &requestTableInput{
				url:                   "https://www.randomcloud123.com:8443",
				useTLS:                true,
				headers:               map[string]string{},
				trustForwardedHeaders: false,
				status:                200,
				body:                  "test",
			}),
			Entry("without TLS with an X-Forwarded-Host header", &requestTableInput{
				url:    "http://internal.randomcloud123.com",
				useTLS: false,
				headers: map[string]string{
					"X-Forwarded-Proto": "HTTP",
					"X-Forwarded-Host":  "external.randomcloud123.com",
				},
				trustForwardedHeaders: true,
				status:                308,
				body:                  permanentRedirectBody("https://external.randomcloud123.com"),
				location:              "https://external.randomcloud123.com",
			}),
		)
	})

	Describe("RequestLogger middleware", func() {
		It("stores a logger with request_id in the request context", func(ctx SpecContext) {
			testRequestID := "test-request-id-12345"
			reqInfo := &ezapi.AuthRequest{
				RequestID: testRequestID,
			}

			req, _ := http.NewRequest("GET", "/test", nil)
			req = ezapi.AddRequestInfo(req, reqInfo)

			var capturedLogger ezlog.Logger
			var capturedRequestID string

			fn := func(h http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					capturedLogger = ezlog.FromContext(r.Context())
					capturedRequestID = ezlog.RequestIDFromContext(r.Context())
					w.WriteHeader(http.StatusOK)
				})
			}

			chain := NewChain(RequestLogger(ezlog.NewNop(), false), fn).Then(nil)
			rec := httptest.NewRecorder()
			chain.ServeHTTP(rec, req)

			Expect(rec.Code).To(Equal(http.StatusOK))
			Expect(capturedLogger).NotTo(BeNil())
			Expect(capturedRequestID).To(Equal(testRequestID))
		})

		It("uses empty request ID when no request ID is set in request info", func(ctx SpecContext) {
			reqInfo := &ezapi.AuthRequest{}

			req, _ := http.NewRequest("GET", "/test", nil)
			req = ezapi.AddRequestInfo(req, reqInfo)

			var capturedRequestID string

			fn := func(h http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					capturedRequestID = ezlog.RequestIDFromContext(r.Context())
					w.WriteHeader(http.StatusOK)
				})
			}

			chain := NewChain(RequestLogger(ezlog.NewNop(), false), fn).Then(nil)
			rec := httptest.NewRecorder()
			chain.ServeHTTP(rec, req)

			Expect(rec.Code).To(Equal(http.StatusOK))
			Expect(capturedRequestID).To(Equal(""))
		})
	})
})
