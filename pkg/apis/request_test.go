package apis

import (
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("API Module Test Suite", func() {
	When("request info test", func() {
		now := time.Now().Truncate(time.Second)
		e := now.Add(time.Duration(888) * time.Second)
		DescribeTable("scope test table", func(ri *AuthRequest) {
			r, _ := http.NewRequest("GET", "/", nil)
			reqInfo := GetRequest(r)
			Expect(reqInfo.Session).To(BeNil())
			r = AddRequestInfo(r, ri)
			reqInfo = GetRequest(r)
			Expect(reqInfo.RequestID).To(Equal(ri.RequestID))
			Expect(reqInfo.TrustForwardedHeaders).To(Equal(ri.TrustForwardedHeaders))
			Expect(reqInfo.Session).To(Equal(ri.Session))
			Expect(reqInfo.Upstream).To(Equal(ri.Upstream))
		},
			Entry("full request info", &AuthRequest{
				TrustForwardedHeaders: true,
				Session: &Session{
					CreatedAt: now.Unix(),
					ExpiresOn: e.Unix(),
					Profile: Profile{
						Email:             "email@test.com",
						User:              "testuser",
						PreferredUsername: "preferred_name",
						Groups:            []string{"group1", "group2", "group3"},
					},
					AccessToken:  "AccessToken.1234567890qwertyuiopasdfghjkl.zxcvbnm0123456",
					IDToken:      "IDToken.1234567890qwertyuiopasdfghjkl.zxcvbnm0123456",
					RefreshToken: "RefreshToken.1234567890qwertyuiopasdfghjkl.zxcvbnm0123456",
					Nonce:        []byte("nonce"),
				},
				RequestID: "lalalalala",
				Upstream:  "https://www.test.com",
			}),
			Entry("no upstream", &AuthRequest{
				TrustForwardedHeaders: false,
				Session: &Session{
					CreatedAt: now.Unix(),
					ExpiresOn: e.Unix(),
					Profile: Profile{
						Email:             "email@test.com",
						User:              "testuser",
						PreferredUsername: "preferred_name",
						Groups:            []string{"group1", "group2", "group3"},
					},
					AccessToken:  "AccessToken.1234567890qwertyuiopasdfghjkl.zxcvbnm0123456",
					IDToken:      "IDToken.1234567890qwertyuiopasdfghjkl.zxcvbnm0123456",
					RefreshToken: "RefreshToken.1234567890qwertyuiopasdfghjkl.zxcvbnm0123456",
					Nonce:        []byte("nonce"),
				},
				RequestID: "lalalalala",
			}),
			Entry("empty session", &AuthRequest{
				TrustForwardedHeaders: false,
				RequestID:             "lalalalala",
			}),
		)
	})

	When("LookupRequest", func() {
		It("returns nil for nil request", func() {
			Expect(LookupRequest(nil)).To(BeNil())
		})
		It("returns nil when no request info stored", func(ctx SpecContext) {
			r, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
			Expect(LookupRequest(r)).To(BeNil())
		})
		It("returns request info when stored", func(ctx SpecContext) {
			r, _ := http.NewRequestWithContext(ctx, "GET", "/", nil)
			ri := &AuthRequest{RequestID: "test-id"}
			r = AddRequestInfo(r, ri)
			retrieved := LookupRequest(r)
			Expect(retrieved).To(Equal(ri))
			Expect(retrieved.RequestID).To(Equal("test-id"))
		})
	})
})
