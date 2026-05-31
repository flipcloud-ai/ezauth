package dto

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ErrorResponse", func() {
	Describe("JSON serialization", func() {
		It("should marshal code and error without authenticated field", func() {
			resp := ErrorResponse{
				Code:  400,
				Error: "bad request",
			}

			data, err := json.Marshal(resp)
			Expect(err).ToNot(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(data, &result)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(HaveKey("code"))
			Expect(result).To(HaveKey("error"))
			Expect(result).ToNot(HaveKey("authenticated"))
			Expect(int(result["code"].(float64))).To(Equal(400))
			Expect(result["error"]).To(Equal("bad request"))
		})

		It("should marshal with authenticated set to false when explicitly provided", func() {
			authenticated := false
			resp := ErrorResponse{
				Code:          401,
				Error:         "unauthorized",
				Authenticated: &authenticated,
			}

			data, err := json.Marshal(resp)
			Expect(err).ToNot(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(data, &result)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(HaveKey("authenticated"))
			Expect(result["authenticated"]).To(BeFalse())
		})

		It("should include authenticated when set to true", func() {
			authenticated := true
			resp := ErrorResponse{
				Code:          200,
				Error:         "ok",
				Authenticated: &authenticated,
			}

			data, err := json.Marshal(resp)
			Expect(err).ToNot(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(data, &result)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(HaveKey("authenticated"))
			Expect(result["authenticated"]).To(BeTrue())
		})

		It("should round-trip unmarshal correctly", func() {
			resp := ErrorResponse{
				Code:  500,
				Error: "internal server error",
			}

			data, err := json.Marshal(resp)
			Expect(err).ToNot(HaveOccurred())

			var decoded ErrorResponse
			err = json.Unmarshal(data, &decoded)
			Expect(err).ToNot(HaveOccurred())
			Expect(decoded.Code).To(Equal(500))
			Expect(decoded.Error).To(Equal("internal server error"))
			Expect(decoded.Authenticated).To(BeNil())
		})

		It("should round-trip with authenticated field", func() {
			authenticated := false
			resp := ErrorResponse{
				Code:          401,
				Error:         "unauthorized",
				Authenticated: &authenticated,
			}

			data, err := json.Marshal(resp)
			Expect(err).ToNot(HaveOccurred())

			var decoded ErrorResponse
			err = json.Unmarshal(data, &decoded)
			Expect(err).ToNot(HaveOccurred())
			Expect(decoded.Code).To(Equal(401))
			Expect(decoded.Error).To(Equal("unauthorized"))
			Expect(decoded.Authenticated).ToNot(BeNil())
			Expect(*decoded.Authenticated).To(BeFalse())
		})

		It("should produce valid JSON for all common HTTP error codes", func() {
			codes := []int{400, 401, 403, 404, 405, 409, 422, 429, 500, 502, 503}
			for _, code := range codes {
				resp := ErrorResponse{Code: code, Error: "test error"}
				data, err := json.Marshal(resp)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).ToNot(BeEmpty())
			}
		})
	})
})
