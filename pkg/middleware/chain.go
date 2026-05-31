package middleware

import (
	"net/http"

	"github.com/gorilla/mux"
)

// Chain holds an ordered list of middleware functions to be applied to an http.Handler.
type Chain struct {
	handlers []mux.MiddlewareFunc
}

// NewChain creates a Chain from the given middleware functions.
func NewChain(handlers ...mux.MiddlewareFunc) Chain {
	return Chain{append(([]mux.MiddlewareFunc)(nil), handlers...)}
}

// Append adds middleware functions to the end of the chain.
func (c *Chain) Append(handlers ...mux.MiddlewareFunc) {
	c.handlers = append(c.handlers, handlers...)
}

// Then applies the chain of middleware to h and returns the resulting handler.
func (c Chain) Then(h http.Handler) http.Handler {
	if h == nil {
		h = http.DefaultServeMux
	}

	for i := range c.handlers {
		h = c.handlers[len(c.handlers)-1-i](h)
	}

	return h
}

// ThenFunc applies the chain to fn, treating nil as http.DefaultServeMux.
func (c Chain) ThenFunc(fn http.HandlerFunc) http.Handler {
	// This nil check cannot be removed due to the "nil is not nil" common mistake in Go.
	// Required due to: https://stackoverflow.com/questions/33426977/how-to-golang-check-a-variable-is-nil
	if fn == nil {
		return c.Then(nil)
	}
	return c.Then(fn)
}
