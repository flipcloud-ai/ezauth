package ezerror_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	ezerror "github.com/flipcloud-ai/ezauth/pkg/error"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("NewError", func() {
	It("should create an error with the default HTTP status text when no custom message is given", func() {
		e := ezerror.NewError(http.StatusNotFound)
		Expect(e.Code).To(Equal(http.StatusNotFound))
		Expect(e.Err).To(Equal(http.StatusText(http.StatusNotFound)))
	})

	It("should create an error with a custom message when provided", func() {
		e := ezerror.NewError(http.StatusBadRequest, "custom error message")
		Expect(e.Code).To(Equal(http.StatusBadRequest))
		Expect(e.Err).To(Equal("custom error message"))
	})
})

var _ = Describe("GeneralError", func() {
	Describe("Error", func() {
		It("should return the error message string", func() {
			e := ezerror.NewError(http.StatusInternalServerError, "something went wrong")
			Expect(e.Error()).To(Equal("something went wrong"))
		})
	})

	Describe("JSON", func() {
		It("should write the JSON representation to the response writer", func() {
			e := ezerror.NewError(http.StatusTeapot, "i am a teapot")
			rw := httptest.NewRecorder()
			e.JSON(rw)

			Expect(rw.Code).To(Equal(http.StatusTeapot))
			Expect(rw.Header().Get("Content-Type")).To(Equal("application/json"))

			var body map[string]any
			err := json.Unmarshal(rw.Body.Bytes(), &body)
			Expect(err).ToNot(HaveOccurred())
			Expect(body["code"]).To(BeNumerically("==", http.StatusTeapot))
			Expect(body["error"]).To(Equal("i am a teapot"))
		})
	})
})
