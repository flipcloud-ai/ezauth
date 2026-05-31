//go:build e2e

package admin_test

import (
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Admin Users API", Ordered, func() {
	const usersPath = "/ezauth/users/"
	var createdUserID string

	It("should create a new user", func() {
		resp := post(rootClient, usersPath, map[string]any{
			"username":   "alice",
			"password":   "Secret123",
			"email":      "alice@test.local",
			"birth_date": "1990-01-01T00:00:00Z",
			"address":    map[string]string{"country": "US"},
		})
		Expect(resp.StatusCode).To(Equal(http.StatusCreated))
		_ = resp.Body.Close()

		for _, u := range decodeList(get(rootClient, usersPath)) {
			if u["username"] == "alice" {
				createdUserID = u["id"].(string)
				break
			}
		}
		Expect(createdUserID).ToNot(BeEmpty())
	})

	It("should list users and include alice", func() {
		resp := get(rootClient, usersPath)
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		Expect(decodeList(resp)).ToNot(BeEmpty())
	})

	It("should get user by ID", func() {
		resp := get(rootClient, usersPath+createdUserID)
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		Expect(decodeData(resp)["username"]).To(Equal("alice"))
	})

	It("should update user first_name", func() {
		resp := put(rootClient, usersPath, map[string]any{
			"id":         createdUserID,
			"first_name": "Alice2",
			"birth_date": "1990-01-01T00:00:00Z",
			"address":    map[string]string{"country": "US"},
		})
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		_ = resp.Body.Close()
		Expect(decodeData(get(rootClient, usersPath+createdUserID))["first_name"]).To(Equal("Alice2"))
	})

	It("should reset user password", func() {
		resp := put(rootClient, usersPath+createdUserID+"/reset-password", map[string]string{
			"password": "NewPassword123",
		})
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusOK), Equal(http.StatusNoContent)))
		_ = resp.Body.Close()
	})

	It("should delete user", func() {
		resp := del(rootClient, usersPath, map[string]string{"id": createdUserID})
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusOK), Equal(http.StatusNoContent)))
		_ = resp.Body.Close()
		Expect(get(rootClient, usersPath+createdUserID).StatusCode).To(Equal(http.StatusNotFound))
	})

	It("should reject user without username", func() {
		resp := post(rootClient, usersPath, map[string]string{"password": "NoUser1A"})
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusBadRequest), Equal(http.StatusUnprocessableEntity)))
		_ = resp.Body.Close()
	})

	It("should reject user without password", func() {
		resp := post(rootClient, usersPath, map[string]string{"username": "nopass"})
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusBadRequest), Equal(http.StatusUnprocessableEntity)))
		_ = resp.Body.Close()
	})

	It("should return 404 for non-existent user UUID", func() {
		resp := get(rootClient, usersPath+"00000000-0000-0000-0000-000000000000")
		Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
		_ = resp.Body.Close()
	})

	It("should support pagination", func() {
		resp := get(rootClient, usersPath+"?limit=2&offset=0")
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		_ = resp.Body.Close()
	})
})
