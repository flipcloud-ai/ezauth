//go:build e2e

package admin_test

import (
	"encoding/json"
	"net/http"

	e2eutils "github.com/flipcloud-ai/ezauth/test/e2e/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Admin RBAC API", Ordered, func() {
	It("should list permissions", func() {
		resp := get(rootClient, "/ezauth/auth/permission/")
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		_ = resp.Body.Close()
	})

	It("should list roles", func() {
		resp := get(rootClient, "/ezauth/auth/role/")
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		_ = resp.Body.Close()
	})

	It("should list policies", func() {
		resp := get(rootClient, "/ezauth/auth/policy/")
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		_ = resp.Body.Close()
	})

	It("should forbid deleting a system role", func() {
		resp := del(rootClient, "/ezauth/auth/role/system-admin", nil)
		Expect(resp.StatusCode).To(Equal(http.StatusForbidden))
		defer func() { _ = resp.Body.Close() }()
		var body map[string]any
		Expect(json.NewDecoder(resp.Body).Decode(&body)).To(Succeed())
		Expect(body["error"]).To(ContainSubstring("system resource"))
	})

	It("should return 404 for non-existent permission", func() {
		resp := get(rootClient, "/ezauth/auth/permission/nonexistent:perm")
		Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
		_ = resp.Body.Close()
	})

	It("should return 404 for non-existent role", func() {
		resp := get(rootClient, "/ezauth/auth/role/nonexistent-role")
		Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
		_ = resp.Body.Close()
	})
})

// RBACAdminRouteEnforcement verifies that /ezauth/* admin routes are protected:
// ordinary users are denied, and only users in the system-admins group can access them.
// Custom RBAC permissions cannot target /ezauth/* paths (isReservedPath rejects them).
// Access control on reserved routes is enforced by AdminGate (system-admins group membership).
var _ = Describe("RBAC admin route enforcement", Ordered, func() {
	const (
		adminGroupName = "system-admins"
		targetPath     = "/ezauth/users/"
	)

	var (
		rbacUserClient *http.Client
		rbacUserID     string
	)

	BeforeAll(func() {
		rbacUserID = e2eutils.CreateDBUser(rootClient, env, "rbac-access-user", "RbacAccess123", "rbac-access@test.local")
		Expect(rbacUserID).ToNot(BeEmpty(), "CreateDBUser must return a UUID")
		rbacUserClient = e2eutils.LoginAs(env, "rbac-access-user", "RbacAccess123")
	})

	It("should deny a plain user access to admin routes", func() {
		resp := e2eutils.Get(rbacUserClient, env, targetPath)
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusForbidden))
	})

	It("should allow access after adding user to the system-admins group", func() {
		// members/assign requires UUIDs, not usernames.
		resp := post(rootClient, "/ezauth/groups/"+adminGroupName+"/members/assign", map[string]any{
			"users": []string{rbacUserID},
		})
		Expect(resp.StatusCode).To(Equal(http.StatusOK), "assign member to system-admins failed")
		_ = resp.Body.Close()

		// Re-login so the session reflects the new group membership.
		rbacUserClient = e2eutils.LoginAs(env, "rbac-access-user", "RbacAccess123")

		resp = e2eutils.Get(rbacUserClient, env, targetPath)
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	It("should deny access after removing user from the system-admins group", func() {
		resp := del(rootClient, "/ezauth/groups/"+adminGroupName+"/members/unassign", map[string]any{
			"users": []string{rbacUserID},
		})
		Expect(resp.StatusCode).To(Equal(http.StatusOK), "unassign member failed")
		_ = resp.Body.Close()

		rbacUserClient = e2eutils.LoginAs(env, "rbac-access-user", "RbacAccess123")

		resp = e2eutils.Get(rbacUserClient, env, targetPath)
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusForbidden))
	})

	It("should reject custom permissions targeting reserved /ezauth/* paths", func() {
		resp := post(rootClient, "/ezauth/auth/permission/", map[string]any{
			"name":    "reserved-path-perm",
			"effect":  true,
			"service": "test",
			"action":  "users:list",
			"method":  "GET",
			"path":    targetPath,
		})
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusBadRequest), "creating permission for reserved path must be rejected")
	})
})
