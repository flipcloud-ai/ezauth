//go:build e2e

package admin_test

import (
	"net/http"

	e2eutils "github.com/flipcloud-ai/ezauth/test/e2e/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Admin Access Control", Ordered, func() {
	It("should allow root to access admin endpoints", func() {
		for _, ep := range []string{"/ezauth/users/", "/ezauth/groups/"} {
			resp := get(rootClient, ep)
			Expect(resp.StatusCode).To(Equal(http.StatusOK), "root should have access to %s", ep)
			_ = resp.Body.Close()
		}
	})

	It("should deny non-admin user access to admin endpoints", func() {
		e2eutils.CreateDBUser(rootClient, env, "normal-user", "Normal123", "normal@test.local")
		normalClient := e2eutils.LoginAs(env, "normal-user", "Normal123")

		for _, ep := range []string{"/ezauth/users/", "/ezauth/groups/"} {
			resp := get(normalClient, ep)
			Expect(resp.StatusCode).To(Equal(http.StatusForbidden), "normal user must not access %s", ep)
			_ = resp.Body.Close()
		}
	})

	It("should deny unauthenticated access to admin endpoints", func() {
		noAuth := e2eutils.Client(env)
		for _, ep := range []string{"/ezauth/users/", "/ezauth/groups/"} {
			resp, err := noAuth.Get(env.URL + ep)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(SatisfyAny(
				Equal(http.StatusFound),
				Equal(http.StatusUnauthorized),
			))
			_ = resp.Body.Close()
		}
	})
})
