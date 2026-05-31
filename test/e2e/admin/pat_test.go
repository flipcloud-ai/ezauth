//go:build e2e

package admin_test

import (
	"context"
	"fmt"
	"net/http"
	"time"

	e2eutils "github.com/flipcloud-ai/ezauth/test/e2e/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PAT self-service API", Ordered, func() {
	const meTokensPath = "/ezauth/me/tokens"
	var (
		userClient *http.Client
		patID      string
	)

	BeforeAll(func() {
		e2eutils.CreateDBUser(rootClient, env, "pat-user", "PatUser123", "pat-user@test.local")
		userClient = e2eutils.LoginAs(env, "pat-user", "PatUser123")
	})

	It("should create a PAT via /me/tokens", func() {
		expiresAt := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
		resp := doJSON(userClient, http.MethodPost, meTokensPath, map[string]any{
			"name":       "my-pat-token",
			"expires_at": expiresAt,
		})
		Expect(resp.StatusCode).To(Equal(http.StatusCreated))
		body := decodeData(resp)
		if id, ok := body["id"]; ok {
			patID = fmt.Sprint(id)
		}
	})

	It("should list PATs for the authenticated user", func() {
		resp := doJSON(userClient, http.MethodGet, meTokensPath, nil)
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		_ = resp.Body.Close()
	})

	It("should delete the PAT", func() {
		if patID == "" {
			Skip("PAT was not created")
		}
		resp := doJSON(userClient, http.MethodDelete, meTokensPath+"/"+patID, nil)
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusOK), Equal(http.StatusNoContent)))
		_ = resp.Body.Close()
	})

	It("should reject PAT creation without expires_at", func() {
		resp := doJSON(userClient, http.MethodPost, meTokensPath, map[string]any{"name": "no-expiry"})
		Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
		_ = resp.Body.Close()
	})

	It("should reject PAT with name longer than 128 characters", func() {
		expiresAt := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
		resp := doJSON(userClient, http.MethodPost, meTokensPath, map[string]any{
			"name":       string(make([]byte, 130)),
			"expires_at": expiresAt,
		})
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusBadRequest), Equal(http.StatusUnprocessableEntity)))
		_ = resp.Body.Close()
	})

	It("should reject PAT with expires_at more than 365 days in future", func() {
		expiresAt := time.Now().Add(400 * 24 * time.Hour).UTC().Format(time.RFC3339)
		resp := doJSON(userClient, http.MethodPost, meTokensPath, map[string]any{
			"name":       "too-far",
			"expires_at": expiresAt,
		})
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusBadRequest), Equal(http.StatusUnprocessableEntity)))
		_ = resp.Body.Close()
	})

	It("should reject PAT with expires_at in the past", func() {
		expiresAt := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
		resp := doJSON(userClient, http.MethodPost, meTokensPath, map[string]any{
			"name":       "already-expired",
			"expires_at": expiresAt,
		})
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusBadRequest), Equal(http.StatusUnprocessableEntity)))
		_ = resp.Body.Close()
	})

	It("should reject unauthenticated access to /me/tokens", func() {
		noAuth := e2eutils.Client(env)
		resp, err := noAuth.Get(env.URL + meTokensPath)
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusFound), Equal(http.StatusUnauthorized)))
		_ = resp.Body.Close()
	})
})

var _ = Describe("PAT authentication", Ordered, func() {
	const meTokensPath = "/ezauth/me/tokens"
	const authPrefix = "/ezauth"

	var (
		userAClient *http.Client
		userBClient *http.Client
		patToken    string
		patID       string
	)

	BeforeAll(func() {
		e2eutils.CreateDBUser(rootClient, env, "pat-auth-a", "PatAuthA123", "pat-auth-a@test.local")
		e2eutils.CreateDBUser(rootClient, env, "pat-auth-b", "PatAuthB123", "pat-auth-b@test.local")
		userAClient = e2eutils.LoginAs(env, "pat-auth-a", "PatAuthA123")
		userBClient = e2eutils.LoginAs(env, "pat-auth-b", "PatAuthB123")

		expiresAt := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
		resp := doJSON(userAClient, http.MethodPost, meTokensPath, map[string]any{
			"name":       "auth-test-token",
			"expires_at": expiresAt,
		})
		Expect(resp.StatusCode).To(Equal(http.StatusCreated))
		body := decodeData(resp)
		patToken = fmt.Sprint(body["token"])
		patID = fmt.Sprint(body["id"])
		Expect(patToken).ToNot(BeEmpty(), "PAT token must be returned on creation")
		Expect(patID).ToNot(BeEmpty(), "PAT id must be returned on creation")
	})

	It("should authenticate via Bearer token on /verify (LoadSession resolves PAT before Gate)", func() {
		// PAT authentication now happens in LoadSession (highest priority).
		// /verify uses the full sessionChain (LoadSession → Gate), so a valid
		// Bearer token is resolved into a session before Gate runs.
		noSession := e2eutils.Client(env)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env.URL+authPrefix+"/verify", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Authorization", "Bearer "+patToken)
		req.Header.Set("Accept", "application/json")
		resp, err := noSession.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	It("should return correct user profile via PAT Bearer token", func() {
		noSession := e2eutils.Client(env)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env.URL+authPrefix+"/me", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Authorization", "Bearer "+patToken)
		req.Header.Set("Accept", "application/json")
		resp, err := noSession.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		profile := e2eutils.DecodeData(resp)
		Expect(profile["username"]).To(Equal("pat-auth-a"))
		Expect(profile["id_type"]).ToNot(BeEmpty())
	})

	It("should reject deleted PAT token", func() {
		resp := doJSON(userAClient, http.MethodDelete, meTokensPath+"/"+patID, nil)
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusOK), Equal(http.StatusNoContent)))
		_ = resp.Body.Close()

		noSession := e2eutils.Client(env)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env.URL+authPrefix+"/verify", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Authorization", "Bearer "+patToken)
		req.Header.Set("Accept", "application/json")
		resp, err = noSession.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusUnauthorized), Equal(http.StatusFound)))
	})

	It("should not allow user B to delete user A's token", func() {
		expiresAt := time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
		createResp := doJSON(userAClient, http.MethodPost, meTokensPath, map[string]any{
			"name":       "isolation-token",
			"expires_at": expiresAt,
		})
		Expect(createResp.StatusCode).To(Equal(http.StatusCreated))
		isolationID := fmt.Sprint(e2eutils.DecodeData(createResp)["id"])

		resp := doJSON(userBClient, http.MethodDelete, meTokensPath+"/"+isolationID, nil)
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusNotFound), Equal(http.StatusForbidden)))
	})

	It("should reject PAT after the owning user is deleted", func() {
		const usersPath = "/ezauth/users/"
		cascadeUserID := e2eutils.CreateDBUser(rootClient, env, "pat-cascade", "PatCascade1", "pat-cascade@test.local")
		cascadeClient := e2eutils.LoginAs(env, "pat-cascade", "PatCascade1")

		expiresAt := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
		resp := doJSON(cascadeClient, http.MethodPost, meTokensPath, map[string]any{
			"name":       "cascade-token",
			"expires_at": expiresAt,
		})
		Expect(resp.StatusCode).To(Equal(http.StatusCreated))
		cascadeToken := fmt.Sprint(decodeData(resp)["token"])
		Expect(cascadeToken).ToNot(BeEmpty())

		// Verify PAT works before user deletion.
		noSession := e2eutils.Client(env)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env.URL+authPrefix+"/verify", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Authorization", "Bearer "+cascadeToken)
		req.Header.Set("Accept", "application/json")
		verifyResp, err := noSession.Do(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(verifyResp.StatusCode).To(Equal(http.StatusOK))
		_ = verifyResp.Body.Close()

		// Delete the owning user — PAT rows must cascade-delete.
		delResp := del(rootClient, usersPath, map[string]string{"id": cascadeUserID})
		Expect(delResp.StatusCode).To(SatisfyAny(Equal(http.StatusOK), Equal(http.StatusNoContent)))
		_ = delResp.Body.Close()

		// PAT must now be rejected.
		req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, env.URL+authPrefix+"/verify", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Authorization", "Bearer "+cascadeToken)
		req.Header.Set("Accept", "application/json")
		verifyResp, err = noSession.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = verifyResp.Body.Close() }()
		Expect(verifyResp.StatusCode).To(SatisfyAny(Equal(http.StatusUnauthorized), Equal(http.StatusFound)))
	})
})
