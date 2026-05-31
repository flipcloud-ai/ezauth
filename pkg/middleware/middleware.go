package middleware

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezutils "github.com/flipcloud-ai/ezauth/pkg/utils"
)

// RequestLogger is a middleware that creates a child logger pre-populated with
// request_id and ip, and stores it in the request context for downstream handlers.
// Injecting ip here means any log entry written via the request logger automatically
// carries the client IP — including audit events captured by auditCore.
func RequestLogger(logger ezlog.Logger, trustHeaders bool) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			reqInfo := ezapi.GetRequest(req)
			reqLogger := logger.With(ezlog.Str("request_id", reqInfo.RequestID), ezlog.Str("ip", clientIP(req, trustHeaders)))
			ctx := ezlog.RequestContext(req.Context(), reqLogger)
			ctx = ezlog.WithRequestID(ctx, reqInfo.RequestID)
			next.ServeHTTP(rw, req.WithContext(ctx))
		})
	}
}

// Healthz returns a simple health check response.
// @Summary      Health check endpoint
// @Description  Returns 200 OK with a plain-text message indicating the service is healthy.
// @Tags         System
// @Produce      plain
// @Success      200 {string} string "XW Proxy is Healthy"
// @Router       /healthz [get]
func Healthz(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte("XW Proxy is Healthy"))
}

// Favicon redirects requests for favicon.ico to path.
func Favicon(path string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if strings.Contains(req.URL.Path, "favicon.ico") {
				http.Redirect(rw, req, path, http.StatusFound)
				return
			}
			next.ServeHTTP(rw, req)
		})
	}
}

// ProxyErrorHandler writes a 502 Bad Gateway response when the upstream proxy encounters an error.
func ProxyErrorHandler(rw http.ResponseWriter, req *http.Request, proxyErr error) {
	logger := ezlog.FromContext(req.Context())
	logger.Error("upstream proxy error", ezlog.Err(proxyErr))
	rw.WriteHeader(http.StatusBadGateway)
	_, _ = fmt.Fprint(rw, "The upstream service is temporarily unavailable. Please try again later.")
}

// RedirectToHTTPS is a redirectToHTTPS middleware that will redirect
// HTTP requests to HTTPS
func RedirectToHTTPS(httpsPort string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return redirectToHTTPS(httpsPort, next)
	}
}

func redirectToHTTPS(httpsPort string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		proto := ezutils.GetRequestProto(req)
		if strings.EqualFold(proto, "https") || (req.TLS != nil && proto == req.URL.Scheme) {
			// Only care about the connection to us being HTTPS if the proto wasn't
			// from a trusted `X-Forwarded-Proto` (proto == req.URL.Scheme).
			// Otherwise the proto is source of truth
			next.ServeHTTP(rw, req)
			return
		}

		// Copy the request URL
		targetURL, _ := url.Parse(req.URL.String())
		// Set the scheme to HTTPS
		targetURL.Scheme = "https"

		// Set the Host in case the targetURL still does not have one
		// or it isn't X-Forwarded-Host aware
		targetURL.Host = ezutils.GetRequestHost(req)

		// Overwrite the port if the original request was to a non-standard port
		if targetURL.Port() != "" {
			// If Port was not empty, this should be fine to ignore the error
			host, _, _ := net.SplitHostPort(targetURL.Host)
			targetURL.Host = net.JoinHostPort(host, httpsPort)
		}

		http.Redirect(rw, req, targetURL.String(), http.StatusPermanentRedirect) //nolint:gosec // redirect target is built from the incoming request's own host/path, not from user input
	})
}
