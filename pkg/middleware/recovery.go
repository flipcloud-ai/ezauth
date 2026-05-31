package middleware

import (
	"net/http"

	ezlog "github.com/flipcloud-ai/ezauth/log"
)

// Recovery returns a middleware that recovers from panics anywhere in the
// downstream handler chain, logs the panic with request context, and writes
// a 500 response.
//
// A sentinel bool is used so that the deferred function only calls recover()
// when a panic actually occurred; on the normal (non-panic) path the handler
// completes and sets panicked = false before returning. This also correctly
// handles panic(nil) on Go versions prior to 1.21 where recover() returned nil,
// making it impossible to distinguish "no panic" from "panic(nil)".
//
// Note: if the downstream handler has already called WriteHeader or written
// response bytes before panicking, the 500 status cannot be sent to the client
// (headers are already flushed). The log entry is still emitted.
func Recovery(logger ezlog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			panicked := true
			defer func() {
				if panicked {
					rec := recover()
					logger.Error("panic recovered in handler chain",
						ezlog.Any("panic", rec),
						ezlog.Str("method", req.Method),
						ezlog.Str("path", req.URL.Path),
					)
					http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(rw, req)
			panicked = false
		})
	}
}
