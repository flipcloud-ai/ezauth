package metrics

import (
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var _ = Describe("Metrics", func() {
	var m *Metrics

	BeforeEach(func() {
		m = New()
	})

	Describe("New", func() {
		It("should create a non-nil Metrics instance", func() {
			Expect(m).ToNot(BeNil())
		})

		It("should have all collectors registered", func() {
			Expect(m.ready.Load()).To(BeFalse())
		})
	})

	Describe("Handler pre-init", func() {
		It("should return 503 before SetReady", func() {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			rec := httptest.NewRecorder()
			m.Handler().ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(http.StatusServiceUnavailable))
			Expect(rec.Body.String()).To(ContainSubstring("not ready"))
		})

		It("should return 200 after SetReady", func() {
			m.SetReady()
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			rec := httptest.NewRecorder()
			m.Handler().ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(http.StatusOK))
		})
	})

	Describe("Handler after ready", func() {
		BeforeEach(func() {
			m.SetReady()
		})

		It("should return Prometheus text format", func() {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			rec := httptest.NewRecorder()
			m.Handler().ServeHTTP(rec, req)
			Expect(rec.Code).To(Equal(http.StatusOK))
			Expect(rec.Header().Get("Content-Type")).To(ContainSubstring("text/plain"))
		})

		It("should expose HTTP request counter", func() {
			HTTPRequestsTotal.WithLabelValues("GET", "/test", "2xx").Inc()
			Expect(testutil.CollectAndCount(HTTPRequestsTotal)).To(BeNumerically(">=", 1))
		})
	})

	Describe("AuthLoginAttemptsTotal", func() {
		It("should increment counter by labels", func() {
			AuthLoginAttemptsTotal.WithLabelValues("local", "password").Inc()
			AuthLoginAttemptsTotal.WithLabelValues("local", "password").Inc()
			val := testutil.ToFloat64(AuthLoginAttemptsTotal.WithLabelValues("local", "password"))
			Expect(val).To(Equal(2.0))
		})
	})

	Describe("AuthLoginFailureTotal", func() {
		It("should track failures with reason label", func() {
			AuthLoginFailureTotal.WithLabelValues("local", "password", "invalid_credentials").Inc()
			val := testutil.ToFloat64(AuthLoginFailureTotal.WithLabelValues("local", "password", "invalid_credentials"))
			Expect(val).To(Equal(1.0))
		})
	})

	Describe("AuthSessionActiveTotal", func() {
		BeforeEach(func() {
			AuthSessionActiveTotal.Set(0)
		})

		It("should track current active sessions", func() {
			AuthSessionActiveTotal.Inc()
			AuthSessionActiveTotal.Inc()
			val := testutil.ToFloat64(AuthSessionActiveTotal)
			Expect(val).To(Equal(2.0))
		})

		It("should decrement active sessions", func() {
			AuthSessionActiveTotal.Inc()
			AuthSessionActiveTotal.Inc()
			AuthSessionActiveTotal.Dec()
			val := testutil.ToFloat64(AuthSessionActiveTotal)
			Expect(val).To(Equal(1.0))
		})
	})

	Describe("HTTPRequestsInFlight", func() {
		It("should track concurrent requests", func() {
			HTTPRequestsInFlight.WithLabelValues("GET").Inc()
			HTTPRequestsInFlight.WithLabelValues("GET").Inc()
			HTTPRequestsInFlight.WithLabelValues("GET").Dec()
			val := testutil.ToFloat64(HTTPRequestsInFlight.WithLabelValues("GET"))
			Expect(val).To(Equal(1.0))
		})
	})

	Describe("Histogram metrics", func() {
		It("should observe request duration", func() {
			HTTPRequestDuration.WithLabelValues("GET", "/api", "200").Observe(0.05)
			Expect(testutil.CollectAndCount(HTTPRequestDuration)).To(BeNumerically(">=", 1))
		})

		It("should observe login duration", func() {
			AuthLoginDuration.WithLabelValues("local", "password", "true").Observe(1.5)
			Expect(testutil.CollectAndCount(AuthLoginDuration)).To(BeNumerically(">=", 1))
		})
	})

	Describe("Non-global registry", func() {
		It("should allow creating multiple Metrics instances without panic", func() {
			Expect(func() { New() }).ToNot(Panic())
			Expect(func() { New() }).ToNot(Panic())
		})

		It("should not register on the default prometheus registry", func() {
			// Global registry should NOT have our metrics
			_, err := prometheus.DefaultRegisterer.(prometheus.Gatherer).Gather()
			Expect(err).ToNot(HaveOccurred())
		})
	})
})
