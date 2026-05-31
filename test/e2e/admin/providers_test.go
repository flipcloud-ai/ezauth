//go:build e2e

package admin_test

import (
	"net/http"

	e2eutils "github.com/flipcloud-ai/ezauth/test/e2e/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func providerBody(name, issuer, clientID, clientSecret string) map[string]any {
	return map[string]any{
		"provider_name": name,
		"type":          "oauth2",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"redirect_url":  "http://localhost/callback",
		"issuer":        issuer,
		"scope":         "openid profile email",
		"enabled":       true,
	}
}

var _ = Describe("Admin Providers API", Ordered, func() {
	const providersPath = "/ezauth/provider/"
	var issuer string

	BeforeAll(func() {
		if e2eutils.ClusterMode() {
			issuer = e2eutils.ClusterDexURL()
			// Clean up providers from a previous run so create tests are idempotent.
			del(rootClient, providersPath+"oidc-test", nil)
			del(rootClient, providersPath+"oidc-toggle", nil)
		} else {
			issuer = "https://accounts.google.com"
		}
	})

	It("should create a provider", func() {
		resp := post(rootClient, providersPath, providerBody("oidc-test", issuer, "id", "secret"))
		Expect(resp.StatusCode).To(Equal(http.StatusCreated))
		_ = resp.Body.Close()
	})

	It("should list providers and include the new one", func() {
		items := decodeList(get(rootClient, providersPath))
		Expect(items).ToNot(BeEmpty())
		var found bool
		for _, item := range items {
			if item["provider_name"] == "oidc-test" {
				Expect(item["type"]).To(Equal("oauth2"))
				Expect(item["enabled"]).To(BeTrue())
				found = true
			}
		}
		Expect(found).To(BeTrue())
	})

	It("should get provider by name", func() {
		body := decodeData(get(rootClient, providersPath+"oidc-test"))
		Expect(body["provider_name"]).To(Equal("oidc-test"))
		Expect(body["client_id"]).To(Equal("id"))
	})

	It("should update provider user_claim", func() {
		resp := put(rootClient, providersPath+"oidc-test", map[string]any{"user_claim": "email"})
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		_ = resp.Body.Close()
	})

	It("should enable and disable a provider", func() {
		resp := post(rootClient, providersPath, map[string]any{
			"provider_name": "oidc-toggle",
			"type":          "oauth2",
			"client_id":     "tog",
			"client_secret": "tog-secret",
			"redirect_url":  "http://localhost/callback",
			"issuer":        issuer,
			"scope":         "openid",
			"enabled":       false,
		})
		Expect(resp.StatusCode).To(Equal(http.StatusCreated))
		_ = resp.Body.Close()

		Expect(decodeData(get(rootClient, providersPath+"oidc-toggle"))["enabled"]).To(BeFalse())

		resp = put(rootClient, providersPath+"oidc-toggle", map[string]any{"enabled": true})
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		_ = resp.Body.Close()

		Expect(decodeData(get(rootClient, providersPath+"oidc-toggle"))["enabled"]).To(BeTrue())
	})

	It("should delete provider", func() {
		resp := del(rootClient, providersPath+"oidc-test", nil)
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		_ = resp.Body.Close()
		Expect(get(rootClient, providersPath+"oidc-test").StatusCode).To(Equal(http.StatusNotFound))
	})

	It("should reject provider without provider_name", func() {
		resp := post(rootClient, providersPath, map[string]any{
			"type": "oauth2", "client_id": "x", "client_secret": "y", "issuer": issuer,
		})
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusBadRequest), Equal(http.StatusUnprocessableEntity)))
		_ = resp.Body.Close()
	})

	It("should reject provider without client credentials", func() {
		resp := post(rootClient, providersPath, map[string]any{
			"provider_name": "no-creds", "type": "oauth2", "issuer": issuer,
		})
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusBadRequest), Equal(http.StatusUnprocessableEntity)))
		_ = resp.Body.Close()
	})

	It("should return 404 for non-existent provider", func() {
		resp := get(rootClient, providersPath+"nonexistent-provider")
		Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
		_ = resp.Body.Close()
	})
})
