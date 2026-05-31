package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	ezmetrics "github.com/flipcloud-ai/ezauth/pkg/metrics"
)

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	if err != nil {
		return n, fmt.Errorf("metrics statusWriter: %w", err)
	}
	return n, nil
}

func statusGroup(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	default:
		return "5xx"
	}
}

// MetricsMiddleware tracks HTTP request counts, latency and in-flight
// concurrency for every request. It extracts the route pattern from
// gorilla/mux as the "path" label to avoid high cardinality.
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ezmetrics.HTTPRequestsInFlight.WithLabelValues(req.Method).Inc()
		defer ezmetrics.HTTPRequestsInFlight.WithLabelValues(req.Method).Dec()

		sw := &statusWriter{ResponseWriter: rw}
		start := time.Now()

		next.ServeHTTP(sw, req)

		dur := time.Since(start).Seconds()
		path := extractRoutePattern(req)
		status := fmt.Sprintf("%d", sw.status)
		group := statusGroup(sw.status)

		ezmetrics.HTTPRequestsTotal.WithLabelValues(req.Method, path, group).Inc()
		ezmetrics.HTTPRequestDuration.WithLabelValues(req.Method, path, status).Observe(dur)
	})
}

// extractRoutePattern extracts the gorilla/mux route template or name
// as a sanitized "path" label value. Falls back to "unknown" when no
// route is found.
func extractRoutePattern(req *http.Request) string {
	route := mux.CurrentRoute(req)
	if route == nil {
		return "unknown"
	}
	if name := route.GetName(); name != "" {
		return name
	}
	if tmpl, err := route.GetPathTemplate(); err == nil && tmpl != "" {
		return tmpl
	}
	return "unknown"
}
