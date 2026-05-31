package middleware_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	middleware "github.com/flipcloud-ai/ezauth/pkg/middleware"
)

var _ = Describe("Recovery middleware", func() {
	var logger ezlog.Logger

	BeforeEach(func() {
		logger = ezlog.NewNop()
	})

	It("passes through normal requests unchanged", func() {
		handler := middleware.Recovery(logger)(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte("ok"))
		}))

		rec := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/healthy", nil)
		handler.ServeHTTP(rec, req)

		Expect(rec.Code).To(Equal(http.StatusOK))
		Expect(rec.Body.String()).To(Equal("ok"))
	})

	It("returns 500 on panic with string value", func() {
		handler := middleware.Recovery(logger)(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			panic("something went wrong")
		}))

		rec := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/boom", nil)
		handler.ServeHTTP(rec, req)

		Expect(rec.Code).To(Equal(http.StatusInternalServerError))
		Expect(rec.Body.String()).To(ContainSubstring("Internal Server Error"))
	})

	It("returns 500 on panic(nil)", func() {
		handler := middleware.Recovery(logger)(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			//nolint:gocritic // intentional panic(nil) to test sentinel-bool recovery
			panic(nil)
		}))

		rec := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/nil-panic", nil)
		handler.ServeHTTP(rec, req)

		Expect(rec.Code).To(Equal(http.StatusInternalServerError))
		Expect(rec.Body.String()).To(ContainSubstring("Internal Server Error"))
	})

	It("returns 500 on panic with error value", func() {
		handler := middleware.Recovery(logger)(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			panic(fmt.Errorf("db error"))
		}))

		rec := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/db-panic", nil)
		handler.ServeHTTP(rec, req)

		Expect(rec.Code).To(Equal(http.StatusInternalServerError))
		Expect(rec.Body.String()).To(ContainSubstring("Internal Server Error"))
	})

	It("cannot override status when panic occurs after WriteHeader", func() {
		// When the handler calls WriteHeader before panicking, the response status
		// is already committed. Recovery still logs the panic but the client sees
		// the original status code, not 500.
		handler := middleware.Recovery(logger)(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(http.StatusOK)
			panic("panic after header written")
		}))

		rec := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/after-header", nil)
		handler.ServeHTTP(rec, req)

		// Header was already committed; client sees 200, not 500.
		Expect(rec.Code).To(Equal(http.StatusOK))
	})
})
