package middleware

import (
	"net/http"
	"net/http/httptest"
	"reflect"

	"github.com/gorilla/mux"

	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Chain Module Test Suite", func() {
	When("middleware chain test", func() {
		testApp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("app\n"))
		})
		tagMiddleware := func(tag string) mux.MiddlewareFunc {
			return func(h http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte(tag))
					h.ServeHTTP(w, r)
				})
			}
		}
		It("middleware chain basic test", func(ctx SpecContext) {
			c1 := func(h http.Handler) http.Handler {
				return nil
			}

			c2 := func(h http.Handler) http.Handler {
				return http.StripPrefix("potato", nil)
			}

			slice := []mux.MiddlewareFunc{c1, c2}

			chain := NewChain(slice...)
			for k := range slice {
				Expect(testutils.FuncsEqual(chain.handlers[k], slice[k])).To(BeTrue())
			}
		})
		It("middleware chain then function test", func(ctx SpecContext) {
			Expect(testutils.FuncsEqual(NewChain().Then(testApp), testApp)).To(BeTrue())
			Expect(testutils.FuncsEqual(NewChain().Then(nil), http.DefaultServeMux)).To(BeTrue())
			Expect(testutils.FuncsEqual(NewChain().ThenFunc(nil), http.DefaultServeMux)).To(BeTrue())
			fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
			})
			chain := NewChain().ThenFunc(fn)
			rec := httptest.NewRecorder()

			chain.ServeHTTP(rec, (*http.Request)(nil))
			Expect(reflect.TypeOf(chain)).To(Equal(reflect.TypeOf((http.HandlerFunc)(nil))))
			t1 := tagMiddleware("tag1\n")
			t2 := tagMiddleware("tag2\n")
			t3 := tagMiddleware("tag3\n")

			chain = NewChain(t1, t2, t3).Then(testApp)

			r, err := http.NewRequest("GET", "/", nil)
			Expect(err).To(BeNil())

			chain.ServeHTTP(rec, r)

			Expect(rec.Body.String()).To(Equal("tag1\ntag2\ntag3\napp\n"))
		})
		It("middleware chain append function test", func(ctx SpecContext) {
			chain := NewChain(tagMiddleware("tag1\n"), tagMiddleware("tag2\n"))
			chain.Append(tagMiddleware("tag3\n"), tagMiddleware("tag4\n"))
			Expect(len(chain.handlers)).To(Equal(4))

			h := chain.Then(testApp)

			rec := httptest.NewRecorder()
			r, err := http.NewRequest("GET", "/", nil)
			Expect(err).To(BeNil())

			h.ServeHTTP(rec, r)

			Expect(rec.Body.String()).To(Equal("tag1\ntag2\ntag3\ntag4\napp\n"))
		})
	})
})
