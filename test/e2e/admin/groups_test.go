//go:build e2e

package admin_test

import (
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Admin Groups API", Ordered, func() {
	const groupsPath = "/ezauth/groups/"
	const groupName = "test-group-e2e"
	const renamedTo = "test-group-e2e-renamed"

	It("should create a new group", func() {
		resp := post(rootClient, groupsPath, map[string]string{"name": groupName})
		Expect(resp.StatusCode).To(Equal(http.StatusCreated))
		_ = resp.Body.Close()
	})

	It("should list groups and include the new one", func() {
		resp := get(rootClient, groupsPath)
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		items := decodeData(resp)["items"]
		Expect(items).ToNot(BeNil())
	})

	It("should get group by name", func() {
		resp := get(rootClient, groupsPath+groupName)
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		Expect(decodeData(resp)["name"]).To(Equal(groupName))
	})

	It("should rename group", func() {
		resp := put(rootClient, groupsPath+groupName, map[string]string{"name": renamedTo})
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusOK), Equal(http.StatusNoContent)))
		_ = resp.Body.Close()
		Expect(get(rootClient, groupsPath+renamedTo).StatusCode).To(Equal(http.StatusOK))
	})

	It("should delete group", func() {
		resp := del(rootClient, groupsPath+renamedTo, nil)
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusOK), Equal(http.StatusNoContent)))
		_ = resp.Body.Close()
	})

	It("should return 404 for non-existent group", func() {
		resp := get(rootClient, groupsPath+"nonexistent-group")
		Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
		_ = resp.Body.Close()
	})
})
