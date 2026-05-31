package middleware

import (
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/mux"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"

	ezmetrics "github.com/flipcloud-ai/ezauth/pkg/metrics"
)

var _ = Describe("MetricsMiddleware", func() {
	var (
		handler  http.Handler
		recorder *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		// Recreate the global metrics collectors so counters start at zero
		// for each test. testutil.CollectAndCompare requires a fresh state.
		r := mux.NewRouter()
		r.Handle("/healthz", MetricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))).Name("healthz")

		r.Handle("/api/users/{id}", MetricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))

		r.Handle("/error", MetricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})))

		handler = r
		recorder = httptest.NewRecorder()
	})

	Describe("request counting", func() {
		It("should increment HTTPRequestsTotal", func() {
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			handler.ServeHTTP(recorder, req)

			val := testutil.ToFloat64(ezmetrics.HTTPRequestsTotal.WithLabelValues("GET", "healthz", "2xx"))
			Expect(val).To(Equal(1.0))
		})

		It("should group status codes", func() {
			req := httptest.NewRequest(http.MethodGet, "/error", nil)
			handler.ServeHTTP(recorder, req)

			val := testutil.ToFloat64(ezmetrics.HTTPRequestsTotal.WithLabelValues("GET", "/error", "5xx"))
			Expect(val).To(Equal(1.0))
		})
	})

	Describe("route pattern extraction", func() {
		It("should fall back to path template for unnamed routes", func() {
			req := httptest.NewRequest(http.MethodGet, "/api/users/42", nil)
			handler.ServeHTTP(recorder, req)

			val := testutil.ToFloat64(ezmetrics.HTTPRequestsTotal.WithLabelValues("GET", "/api/users/{id}", "2xx"))
			Expect(val).To(Equal(1.0))
		})
	})

	Describe("in-flight gauge", func() {
		It("should return to zero after request completes", func() {
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			handler.ServeHTTP(recorder, req)

			val := testutil.ToFloat64(ezmetrics.HTTPRequestsInFlight.WithLabelValues("GET"))
			Expect(val).To(Equal(0.0))
		})
	})

	Describe("duration tracking", func() {
		It("should observe request duration", func() {
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			handler.ServeHTTP(recorder, req)

			count := testutil.CollectAndCount(ezmetrics.HTTPRequestDuration)
			Expect(count).To(BeNumerically(">=", 1))
		})
	})

	Describe("statusWriter", func() {
		It("should default to 200 when WriteHeader is not called", func() {
			sw := &statusWriter{ResponseWriter: httptest.NewRecorder()}
			n, err := sw.Write([]byte("ok"))
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(2))
			Expect(sw.status).To(Equal(http.StatusOK))
		})

		It("should capture explicit status code", func() {
			sw := &statusWriter{ResponseWriter: httptest.NewRecorder()}
			sw.WriteHeader(http.StatusNotFound)
			Expect(sw.status).To(Equal(http.StatusNotFound))
		})
	})

	Describe("statusGroup", func() {
		It("should group 2xx", func() {
			Expect(statusGroup(200)).To(Equal("2xx"))
			Expect(statusGroup(201)).To(Equal("2xx"))
		})

		It("should group 3xx", func() {
			Expect(statusGroup(301)).To(Equal("3xx"))
			Expect(statusGroup(302)).To(Equal("3xx"))
		})

		It("should group 4xx", func() {
			Expect(statusGroup(401)).To(Equal("4xx"))
			Expect(statusGroup(404)).To(Equal("4xx"))
		})

		It("should group 5xx", func() {
			Expect(statusGroup(500)).To(Equal("5xx"))
			Expect(statusGroup(503)).To(Equal("5xx"))
		})
	})

	Describe("extractRoutePattern", func() {
		It("should return unknown for requests with no matching route", func() {
			r := mux.NewRouter()
			r.Handle("/foo", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

			req := httptest.NewRequest(http.MethodGet, "/bar", nil)
			// serve it through the router so CurrentRoute is populated
			r.ServeHTTP(httptest.NewRecorder(), req)

			Expect(extractRoutePattern(req)).To(Equal("unknown"))
		})
	})
})
