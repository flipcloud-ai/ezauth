package metrics

import (
	"net/http"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// HTTP request latency histogram buckets. Covers sub-millisecond cache
// checks up to multi-second OIDC provider round-trips.
var httpRequestBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Login flow latency buckets. OIDC redirects can take tens of seconds.
var authLoginBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}

// HTTP metrics
var (
	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ezauth_http_requests_total",
			Help: "Total number of HTTP requests handled, partitioned by method, route pattern and status code group.",
		},
		[]string{"method", "path", "status"},
	)

	HTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ezauth_http_request_duration_seconds",
			Help:    "HTTP request latency in seconds.",
			Buckets: httpRequestBuckets,
		},
		[]string{"method", "path", "status"},
	)

	HTTPRequestsInFlight = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ezauth_http_requests_in_flight",
			Help: "Current number of HTTP requests being handled.",
		},
		[]string{"method"},
	)
)

// Auth metrics
var (
	AuthLoginAttemptsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ezauth_auth_login_attempts_total",
			Help: "Total number of login attempts, partitioned by provider and source (password/oidc).",
		},
		[]string{"provider", "source"},
	)

	AuthLoginSuccessTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ezauth_auth_login_success_total",
			Help: "Total number of successful logins, partitioned by provider and source.",
		},
		[]string{"provider", "source"},
	)

	AuthLoginFailureTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ezauth_auth_login_failure_total",
			Help: "Total number of failed login attempts, partitioned by provider, source and failure reason.",
		},
		[]string{"provider", "source", "reason"},
	)

	AuthLoginDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ezauth_auth_login_duration_seconds",
			Help:    "Duration of login flows in seconds.",
			Buckets: authLoginBuckets,
		},
		[]string{"provider", "source", "success"},
	)

	AuthSessionActiveTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ezauth_auth_session_active_total",
			Help: "Current number of active sessions.",
		},
	)
)

// OIDC / Session / AuthZ metrics
var (
	AuthOIDCCallbackTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ezauth_auth_oidc_callback_total",
			Help: "Total OIDC callback outcomes, partitioned by provider and result.",
		},
		[]string{"provider", "result"},
	)

	AuthSessionCreationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ezauth_auth_session_creations_total",
			Help: "Total number of sessions created, partitioned by provider.",
		},
		[]string{"provider"},
	)

	AuthzAllowTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ezauth_authz_allow_total",
			Help: "Total number of authorized requests, partitioned by resource type.",
		},
		[]string{"resource_type"},
	)

	AuthzDenyTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ezauth_authz_deny_total",
			Help: "Total number of denied authorization requests, partitioned by resource type and reason.",
		},
		[]string{"resource_type", "reason"},
	)
)

// Metrics holds the Prometheus registry and readiness state for the /metrics endpoint.
type Metrics struct {
	registry *prometheus.Registry
	ready    atomic.Bool
}

// New creates a new Metrics instance with all collectors registered on a
// private prometheus.Registry. The metrics endpoint will return 503 until
// SetReady is called.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		HTTPRequestsTotal,
		HTTPRequestDuration,
		HTTPRequestsInFlight,
		AuthLoginAttemptsTotal,
		AuthLoginSuccessTotal,
		AuthLoginFailureTotal,
		AuthLoginDuration,
		AuthSessionActiveTotal,
		AuthOIDCCallbackTotal,
		AuthSessionCreationsTotal,
		AuthzAllowTotal,
		AuthzDenyTotal,
	)
	return &Metrics{registry: reg}
}

// SetReady marks the metrics endpoint as ready to serve. Until called,
// the handler returns 503.
func (m *Metrics) SetReady() {
	m.ready.Store(true)
}

// Handler returns an http.Handler for the /metrics endpoint. Returns 503
// until SetReady is called, then delegates to promhttp.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if !m.ready.Load() {
			rw.WriteHeader(http.StatusServiceUnavailable)
			_, _ = rw.Write([]byte("metrics not ready"))
			return
		}
		promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}).ServeHTTP(rw, req)
	})
}
