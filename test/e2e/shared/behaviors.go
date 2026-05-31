//go:build e2e

package shared

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	e2eutils "github.com/flipcloud-ai/ezauth/test/e2e/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// HealthBehaviors asserts that /healthz and /robots.txt work on any server.
func HealthBehaviors(env func() *e2eutils.TestEnv) {
	It("should return 200 with 'Healthy' for /healthz", func() {
		resp, err := e2eutils.Client(env()).Get(env().URL + "/healthz")
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		body, err := io.ReadAll(resp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(ContainSubstring("Healthy"))
	})

	It("should return 200 for /robots.txt", func() {
		resp, err := e2eutils.Client(env()).Get(env().URL + "/robots.txt")
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})
}

// AuthFlowBehaviors asserts login, verify, and logout behaviour.
// creds returns a valid username/password pair for the given environment.
func AuthFlowBehaviors(env func() *e2eutils.TestEnv, creds func() (string, string)) {
	It("should redirect unauthenticated request to login", func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+"/", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := e2eutils.Client(env()).Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusFound))
		Expect(resp.Header.Get("Location")).To(ContainSubstring("/login"))
	})

	It("should login with valid credentials", func() {
		username, password := creds()
		c := e2eutils.LoginAs(env(), username, password)
		authPrefix := env().Opts.Server.AuthPrefix
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+authPrefix+"/verify", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "application/json")
		resp, err := c.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		body, err := io.ReadAll(resp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(ContainSubstring(`"authenticated":true`))
	})

	It("should reject invalid credentials with 401", func() {
		authPrefix := env().Opts.Server.AuthPrefix
		loginURL := env().URL + authPrefix + "/login"

		// Use a jar-backed client so CSRF cookies are carried automatically.
		base := e2eutils.ClientWithJar(env())
		getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
		Expect(err).ToNot(HaveOccurred())
		getResp, err := base.Do(getReq)
		Expect(err).ToNot(HaveOccurred())
		bodyBytes, _ := io.ReadAll(getResp.Body)
		_ = getResp.Body.Close()
		csrfToken := e2eutils.ExtractCSRFToken(bodyBytes)

		form := url.Values{
			"username":   {"nobody"},
			"password":   {"wrongpassword"},
			"csrf_token": {csrfToken},
		}
		postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, loginURL,
			strings.NewReader(form.Encode()))
		Expect(err).ToNot(HaveOccurred())
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		postReq.Header.Set("Accept", "application/json")
		postReq.Header.Set("Origin", env().URL)

		resp, err := base.Do(postReq)
		Expect(err).ToNot(HaveOccurred())
		_ = resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
	})

	It("should logout and redirect to login", func() {
		username, password := creds()
		c := e2eutils.LoginAs(env(), username, password)
		authPrefix := env().Opts.Server.AuthPrefix

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+authPrefix+"/logout", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := c.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusFound))
		Expect(resp.Header.Get("Location")).To(ContainSubstring("/login"))
	})

	It("should reject access after logout", func() {
		username, password := creds()
		c := e2eutils.LoginAs(env(), username, password)
		authPrefix := env().Opts.Server.AuthPrefix

		logoutReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+authPrefix+"/logout", nil)
		Expect(err).ToNot(HaveOccurred())
		resp, err := c.Do(logoutReq)
		Expect(err).ToNot(HaveOccurred())
		_ = resp.Body.Close()

		Eventually(func() int {
			req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+"/", nil)
			if reqErr != nil {
				return 0
			}
			req.Header.Set("Accept", "text/html,application/xhtml+xml")
			r, respErr := c.Do(req)
			if respErr != nil {
				return 0
			}
			_ = r.Body.Close()
			return r.StatusCode
		}).WithTimeout(3 * time.Second).WithPolling(100 * time.Millisecond).
			Should(Equal(http.StatusFound))
	})
}

// SessionBehaviors asserts session cookie validation, logout invalidation,
// and concurrent session isolation.
// creds returns a valid username/password pair; required for the logout and
// concurrent-session cases. When nil, only the tampered-cookie test runs.
func SessionBehaviors(env func() *e2eutils.TestEnv, creds ...func() (string, string)) {
	It("should redirect to login when session cookie is invalid", func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+"/", nil)
		Expect(err).ToNot(HaveOccurred())
		req.AddCookie(&http.Cookie{
			Name:  env().Opts.Auth.Session.Cookie.Name,
			Value: "garbage-not-a-valid-encoded-session",
		})
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := e2eutils.Client(env()).Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusFound))
		Expect(resp.Header.Get("Location")).To(ContainSubstring("/login"))
	})

	if len(creds) == 0 {
		return
	}
	getCreds := creds[0]

	It("should clear the session cookie on logout", func() {
		username, password := getCreds()
		authPrefix := env().Opts.Server.AuthPrefix

		// Login and capture the session cookie.
		loginURL := env().URL + authPrefix + "/login"
		base := e2eutils.ClientWithJar(env())
		getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
		Expect(err).ToNot(HaveOccurred())
		getResp, err := base.Do(getReq)
		Expect(err).ToNot(HaveOccurred())
		bodyBytes, _ := io.ReadAll(getResp.Body)
		_ = getResp.Body.Close()
		csrfToken := e2eutils.ExtractCSRFToken(bodyBytes)

		form := url.Values{
			"username":   {username},
			"password":   {password},
			"csrf_token": {csrfToken},
		}
		postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, loginURL,
			strings.NewReader(form.Encode()))
		Expect(err).ToNot(HaveOccurred())
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		postReq.Header.Set("Origin", env().URL)
		loginResp, err := base.Do(postReq)
		Expect(err).ToNot(HaveOccurred())
		_ = loginResp.Body.Close()

		cookieName := env().Opts.Auth.Session.Cookie.Name
		var preLogoutCookie string
		for _, c := range loginResp.Cookies() {
			if c.Name == cookieName {
				preLogoutCookie = c.Value
				break
			}
		}
		Expect(preLogoutCookie).ToNot(BeEmpty(), "session cookie not set after login")

		// Logout clears the session cookie (server sends Set-Cookie with MaxAge=-1).
		logoutReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			env().URL+authPrefix+"/logout", nil)
		Expect(err).ToNot(HaveOccurred())
		logoutResp, err := base.Do(logoutReq)
		Expect(err).ToNot(HaveOccurred())
		var clearedCookie *http.Cookie
		for _, c := range logoutResp.Cookies() {
			if c.Name == cookieName {
				clearedCookie = c
				break
			}
		}
		_ = logoutResp.Body.Close()
		Expect(clearedCookie).ToNot(BeNil(), "logout must send a Set-Cookie to clear the session cookie")
		Expect(clearedCookie.MaxAge).To(BeNumerically("<", 0), "logout must expire the session cookie (MaxAge < 0)")
	})

	It("should maintain independent concurrent sessions for the same user", func() {
		username, password := getCreds()
		authPrefix := env().Opts.Server.AuthPrefix

		clientA := e2eutils.LoginAs(env(), username, password)
		clientB := e2eutils.LoginAs(env(), username, password)

		verifyURL := env().URL + authPrefix + "/verify"

		// Both sessions must be valid independently.
		reqA, err := http.NewRequestWithContext(context.Background(), http.MethodGet, verifyURL, nil)
		Expect(err).ToNot(HaveOccurred())
		reqA.Header.Set("Accept", "application/json")
		respA, err := clientA.Do(reqA)
		Expect(err).ToNot(HaveOccurred())
		_ = respA.Body.Close()
		Expect(respA.StatusCode).To(Equal(http.StatusOK), "session A must be valid")

		reqB, err := http.NewRequestWithContext(context.Background(), http.MethodGet, verifyURL, nil)
		Expect(err).ToNot(HaveOccurred())
		reqB.Header.Set("Accept", "application/json")
		respB, err := clientB.Do(reqB)
		Expect(err).ToNot(HaveOccurred())
		_ = respB.Body.Close()
		Expect(respB.StatusCode).To(Equal(http.StatusOK), "session B must be valid")

		// Logout session A.
		logoutReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			env().URL+authPrefix+"/logout", nil)
		Expect(err).ToNot(HaveOccurred())
		logoutResp, err := clientA.Do(logoutReq)
		Expect(err).ToNot(HaveOccurred())
		_ = logoutResp.Body.Close()

		// Session B must still be valid after A logged out.
		reqB2, err := http.NewRequestWithContext(context.Background(), http.MethodGet, verifyURL, nil)
		Expect(err).ToNot(HaveOccurred())
		reqB2.Header.Set("Accept", "application/json")
		respB2, err := clientB.Do(reqB2)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = respB2.Body.Close() }()
		Expect(respB2.StatusCode).To(Equal(http.StatusOK),
			"session B must survive logout of session A")
	})
}

// UpstreamBehaviors asserts that authenticated requests are proxied to the
// upstream with correct identity headers, and unauthenticated requests are not.
//
// env must be configured with an upstream. captured is called after each
// proxied request to return the headers the upstream received; the caller
// populates it via the httptest.Server handler.
func UpstreamBehaviors(env func() *e2eutils.TestEnv, creds func() (string, string), captured func() http.Header) {
	It("should proxy authenticated request to upstream and return 200", func() {
		username, _ := creds()
		c := e2eutils.LoginAs(env(), username, func() string { _, p := creds(); return p }())

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+"/", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := c.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	It("should set X-Auth-User header on proxied request", func() {
		username, password := creds()
		c := e2eutils.LoginAs(env(), username, password)

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+"/", nil)
		Expect(err).ToNot(HaveOccurred())
		resp, err := c.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()

		hdrs := captured()
		userHeader := env().Opts.Auth.Proxy.IdentityHeaders.User
		if userHeader == "" {
			userHeader = "X-Auth-User"
		}
		Expect(hdrs.Get(userHeader)).To(Equal(username))
	})

	It("should set X-Auth-Email header on proxied request", func() {
		username, password := creds()
		c := e2eutils.LoginAs(env(), username, password)

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+"/", nil)
		Expect(err).ToNot(HaveOccurred())
		resp, err := c.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()

		hdrs := captured()
		emailHeader := env().Opts.Auth.Proxy.IdentityHeaders.Email
		if emailHeader == "" {
			emailHeader = "X-Auth-Email"
		}
		// Email header is always injected; its value reflects the user's email
		// which is empty for static users without an email address.
		Expect(hdrs).To(HaveKey(emailHeader))
	})

	It("should strip client-supplied X-Auth-User before proxying", func() {
		// An unauthenticated client must not be able to spoof identity headers.
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+"/", nil)
		Expect(err).ToNot(HaveOccurred())
		userHeader := env().Opts.Auth.Proxy.IdentityHeaders.User
		if userHeader == "" {
			userHeader = "X-Auth-User"
		}
		req.Header.Set(userHeader, "spoofed-user")
		req.Header.Set("Accept", "text/html,application/xhtml+xml")

		resp, err := e2eutils.Client(env()).Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		// Unauthenticated → redirected to login, never reaches upstream.
		Expect(resp.StatusCode).To(Equal(http.StatusFound))
	})

	It("should not proxy unauthenticated request to upstream", func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+"/", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := e2eutils.Client(env()).Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusFound))
		Expect(resp.Header.Get("Location")).To(ContainSubstring("/login"))
	})
}

// CookieBehaviors asserts that the session cookie has the correct Secure attribute.
// expectSecure should be true when the server is configured with TLS.
// creds returns a valid username/password pair; defaults to "test"/"test1234" when nil.
func CookieBehaviors(env func() *e2eutils.TestEnv, expectSecure bool, creds ...func() (string, string)) {
	It("should set correct Secure attribute on session cookie", func() {
		username, password := "test", "test1234"
		if len(creds) > 0 {
			username, password = creds[0]()
		}

		authPrefix := env().Opts.Server.AuthPrefix
		loginURL := env().URL + authPrefix + "/login"

		base := e2eutils.ClientWithJar(env())
		getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
		Expect(err).ToNot(HaveOccurred())
		getResp, err := base.Do(getReq)
		Expect(err).ToNot(HaveOccurred())
		bodyBytes, _ := io.ReadAll(getResp.Body)
		_ = getResp.Body.Close()
		csrfToken := e2eutils.ExtractCSRFToken(bodyBytes)

		form := url.Values{
			"username":   {username},
			"password":   {password},
			"csrf_token": {csrfToken},
		}
		postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, loginURL,
			strings.NewReader(form.Encode()))
		Expect(err).ToNot(HaveOccurred())
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		postReq.Header.Set("Origin", env().URL)
		resp, err := base.Do(postReq)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()

		var sessionCookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == env().Opts.Auth.Session.Cookie.Name {
				sessionCookie = c
				break
			}
		}
		Expect(sessionCookie).ToNot(BeNil(), "session cookie not found in login response")
		Expect(sessionCookie.Secure).To(Equal(expectSecure),
			"cookie Secure=%v but expected %v (TLS enabled=%v)",
			sessionCookie.Secure, expectSecure, env().Opts.Server.TLS.Enabled)
		Expect(sessionCookie.HttpOnly).To(BeTrue(), "session cookie must have HttpOnly flag")
		Expect(sessionCookie.SameSite).To(SatisfyAny(
			Equal(http.SameSiteLaxMode),
			Equal(http.SameSiteStrictMode),
		), "session cookie SameSite must be Lax or Strict, got %v", sessionCookie.SameSite)
	})
}

// CSRFBehaviors asserts CSRF enforcement behaviour.
// When enforced=true, mutating requests without a valid token must be rejected
// with 403. When enforced=false, they must be allowed through.
func CSRFBehaviors(env func() *e2eutils.TestEnv, enforced bool) {
	// postLoginWithClient POSTs the login form. If client is nil, a stateless
	// client is used (tests 1 & 2). Pass a jar-backed client to carry the CSRF
	// session cookie so the server validates the token against the session (test 3).
	postLoginWithClient := func(c *http.Client, extraHeaders map[string]string) int {
		if c == nil {
			c = e2eutils.Client(env())
		}
		authPrefix := env().Opts.Server.AuthPrefix
		loginURL := env().URL + authPrefix + "/login"
		form := "username=test&password=test1234"
		postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, loginURL,
			strings.NewReader(form))
		Expect(err).ToNot(HaveOccurred())
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		postReq.Header.Set("Origin", env().URL)
		for k, v := range extraHeaders {
			postReq.Header.Set(k, v)
		}
		resp, err := c.Do(postReq)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	It("should reject POST without CSRF token when CSRF is enabled="+boolStr(enforced), func() {
		status := postLoginWithClient(nil, nil)
		if enforced {
			Expect(status).To(Equal(http.StatusForbidden))
		} else {
			Expect(status).ToNot(Equal(http.StatusForbidden))
		}
	})

	It("should reject POST with an invalid CSRF token when CSRF is enabled="+boolStr(enforced), func() {
		status := postLoginWithClient(nil, map[string]string{"X-CSRF-Token": "invalid-csrf-token"})
		if enforced {
			Expect(status).To(Equal(http.StatusForbidden))
		} else {
			Expect(status).ToNot(Equal(http.StatusForbidden))
		}
	})

	It("should accept POST with a valid CSRF token when CSRF is enabled="+boolStr(enforced), func() {
		if !enforced {
			status := postLoginWithClient(nil, nil)
			Expect(status).ToNot(Equal(http.StatusForbidden))
			return
		}

		authPrefix := env().Opts.Server.AuthPrefix
		loginURL := env().URL + authPrefix + "/login"

		base := e2eutils.ClientWithJar(env())
		getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
		Expect(err).ToNot(HaveOccurred())
		getResp, err := base.Do(getReq)
		Expect(err).ToNot(HaveOccurred())
		bodyBytes, _ := io.ReadAll(getResp.Body)
		_ = getResp.Body.Close()
		csrfToken := e2eutils.ExtractCSRFToken(bodyBytes)
		Expect(csrfToken).ToNot(BeEmpty(), "login page must contain a CSRF token")

		status := postLoginWithClient(base, map[string]string{"X-CSRF-Token": csrfToken})
		Expect(status).ToNot(Equal(http.StatusForbidden),
			"valid CSRF token must not be rejected by CSRF middleware")
	})

	It("should handle CSRF token reuse when CSRF is enabled="+boolStr(enforced), func() {
		if !enforced {
			return
		}

		authPrefix := env().Opts.Server.AuthPrefix
		loginURL := env().URL + authPrefix + "/login"

		base := e2eutils.ClientWithJar(env())
		getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
		Expect(err).ToNot(HaveOccurred())
		getResp, err := base.Do(getReq)
		Expect(err).ToNot(HaveOccurred())
		bodyBytes, _ := io.ReadAll(getResp.Body)
		_ = getResp.Body.Close()
		csrfToken := e2eutils.ExtractCSRFToken(bodyBytes)
		Expect(csrfToken).ToNot(BeEmpty(), "login page must contain a CSRF token")

		firstStatus := postLoginWithClient(base, map[string]string{"X-CSRF-Token": csrfToken})
		Expect(firstStatus).ToNot(Equal(http.StatusForbidden),
			"valid CSRF token must not be rejected on first use")

		secondStatus := postLoginWithClient(base, map[string]string{"X-CSRF-Token": csrfToken})
		Expect(secondStatus).To(SatisfyAny(
			Equal(http.StatusForbidden),
			Equal(http.StatusUnauthorized),
		), "CSRF token reuse: got %d", secondStatus)
	})
}

// RateLimitBehaviors asserts that repeated failed login attempts are blocked
// after limit attempts when rate limiting is enabled, or never blocked when
// disabled. limit is the configured IPLimit value (0 means disabled).
//
// When limit > 0, blockDuration and validCreds must be provided so the test
// can wait for the block to expire and verify login succeeds afterwards —
// ensuring subsequent tests are not affected by a lingering block.
func RateLimitBehaviors(env func() *e2eutils.TestEnv, limit int, opts ...any) {
	// rateLimitValidCreds extracts the validCreds callback from opts, or returns
	// nil when the caller did not provide it.
	rateLimitValidCreds := func() func() (string, string) {
		if len(opts) < 2 {
			return nil
		}
		creds, _ := opts[1].(func() (string, string))
		return creds
	}

	It("should handle repeated failed logins correctly for rate limit="+intStr(limit), func() {
		authPrefix := env().Opts.Server.AuthPrefix
		loginURL := env().URL + authPrefix + "/login"

		attempts := limit + 5
		if limit == 0 {
			attempts = 25
		}

		var lastStatus int
		floodUsername := "nobody-basic"
		for i := 0; i < attempts; i++ {
			lastStatus = failLoginOnce(e2eutils.ClientWithJar(env()), loginURL, env().URL, floodUsername)
			if lastStatus == http.StatusTooManyRequests {
				break
			}
		}

		if limit == 0 {
			Expect(lastStatus).ToNot(Equal(http.StatusTooManyRequests),
				"rate limit is disabled but got 429")
			return
		}

		Expect(lastStatus).To(Equal(http.StatusTooManyRequests),
			"expected 429 after %d attempts but got %d", attempts, lastStatus)

		if len(opts) < 2 {
			return
		}
		blockDuration, ok := opts[0].(time.Duration)
		if !ok {
			return
		}
		validCreds := rateLimitValidCreds()
		if validCreds == nil {
			return
		}

		username, password := validCreds()
		Eventually(func() int {
			// Inline login flow — no Expect calls, so Eventually retries on 429.
			jar, _ := cookiejar.New(nil)
			base := e2eutils.Client(env())
			base.Jar = jar

			getReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
			getResp, err := base.Do(getReq)
			if err != nil {
				return 0
			}
			body, _ := io.ReadAll(getResp.Body)
			_ = getResp.Body.Close()
			if getResp.StatusCode == http.StatusTooManyRequests {
				return http.StatusTooManyRequests
			}
			csrfToken := e2eutils.ExtractCSRFToken(body)

			postReq, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, loginURL,
				strings.NewReader(url.Values{
					"username":   {username},
					"password":   {password},
					"csrf_token": {csrfToken},
				}.Encode()))
			postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			postReq.Header.Set("Origin", env().URL)
			postResp, err := base.Do(postReq)
			if err != nil {
				return 0
			}
			_ = postResp.Body.Close()
			if postResp.StatusCode != http.StatusOK && postResp.StatusCode != http.StatusFound {
				return postResp.StatusCode
			}

			// Login succeeded — verify the session is active.
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
				env().URL+authPrefix+"/verify", nil)
			req.Header.Set("Accept", "application/json")
			resp, err := base.Do(req)
			if err != nil {
				return 0
			}
			_ = resp.Body.Close()
			return resp.StatusCode
		}).WithTimeout(blockDuration+15*time.Second).WithPolling(1*time.Second).
			Should(Equal(http.StatusOK), "login should succeed after block expires")
	})

	if limit > 0 {
		It("should not block a different IP when one IP triggers rate limit", func() {
			validCreds := rateLimitValidCreds()
			if validCreds == nil {
				Skip("validCreds not provided")
			}
			authPrefix := env().Opts.Server.AuthPrefix
			loginURL := env().URL + authPrefix + "/login"

			blockedIP := "10.0.0.1"
			cleanIP := "10.0.0.2"

			floodUsername := "nobody-diffip"
			floodUntilBlocked(clientWithRealIP(env(), blockedIP), loginURL, env().URL, limit, floodUsername)

			// Confirm blockedIP is now rate-limited.
			getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
			Expect(err).ToNot(HaveOccurred())
			getResp, err := clientWithRealIP(env(), blockedIP).Do(getReq)
			Expect(err).ToNot(HaveOccurred())
			_ = getResp.Body.Close()
			Expect(getResp.StatusCode).To(Equal(http.StatusTooManyRequests),
				"blockedIP should be rate-limited")

			// cleanIP must still be able to log in successfully.
			username, password := validCreds()
			cleanClient := clientWithRealIP(env(), cleanIP)
			getReq2, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
			Expect(err).ToNot(HaveOccurred())
			getResp2, err := cleanClient.Do(getReq2)
			Expect(err).ToNot(HaveOccurred())
			body, _ := io.ReadAll(getResp2.Body)
			_ = getResp2.Body.Close()
			Expect(getResp2.StatusCode).ToNot(Equal(http.StatusTooManyRequests),
				"cleanIP must not be blocked")

			postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, loginURL,
				strings.NewReader(url.Values{
					"username":   {username},
					"password":   {password},
					"csrf_token": {e2eutils.ExtractCSRFToken(body)},
				}.Encode()))
			Expect(err).ToNot(HaveOccurred())
			postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			postReq.Header.Set("Origin", env().URL)
			postResp, err := cleanClient.Do(postReq)
			Expect(err).ToNot(HaveOccurred())
			defer func() { _ = postResp.Body.Close() }()
			Expect(postResp.StatusCode).To(BeElementOf(http.StatusOK, http.StatusFound),
				"cleanIP login must succeed while blockedIP is rate-limited")
		})

		It("should not invalidate existing sessions when rate limit is triggered", func() {
			validCreds := rateLimitValidCreds()
			if validCreds == nil {
				Skip("validCreds not provided")
			}
			authPrefix := env().Opts.Server.AuthPrefix
			loginURL := env().URL + authPrefix + "/login"

			// Establish a valid session before triggering the block.
			username, password := validCreds()
			client := e2eutils.ClientWithJar(env())
			innocentClient := e2eutils.LoginAs(env(), username, password)

			floodUsername := "nobody-session"
			floodUntilBlocked(client, loginURL, env().URL, limit, floodUsername)

			// Confirm the IP is now blocked.
			getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
			Expect(err).ToNot(HaveOccurred())
			getResp, err := client.Do(getReq)
			Expect(err).ToNot(HaveOccurred())
			_ = getResp.Body.Close()
			Expect(getResp.StatusCode).To(Equal(http.StatusTooManyRequests),
				"IP should be blocked after flooding failed logins")

			// The pre-existing session must still be valid.
			verifyReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
				env().URL+authPrefix+"/verify", nil)
			Expect(err).ToNot(HaveOccurred())
			verifyReq.Header.Set("Accept", "application/json")
			verifyResp, err := innocentClient.Do(verifyReq)
			Expect(err).ToNot(HaveOccurred())
			defer func() { _ = verifyResp.Body.Close() }()
			Expect(verifyResp.StatusCode).To(Equal(http.StatusOK),
				"existing session must not be invalidated by rate limit trigger")
		})

		It("should count IP even when username is already blocked", func() {
			authPrefix := env().Opts.Server.AuthPrefix
			loginURL := env().URL + authPrefix + "/login"

			// Exhaust username "frank" from three different IPs so the
			// username counter reaches its limit without any single IP
			// reaching the IP limit.
			for _, ip := range []string{"10.7.0.1", "10.7.0.2", "10.7.0.3"} {
				c := clientWithRealIP(env(), ip)
				status := failLoginOnce(c, loginURL, env().URL, "frank")
				Expect(status).To(Equal(http.StatusUnauthorized))
			}

			// A fourth IP tries "frank" — blocked by username limit, but
			// the IP counter must still be incremented.
			blockedIP := "10.7.0.4"
			c4 := clientWithRealIP(env(), blockedIP)
			status := failLoginOnce(c4, loginURL, env().URL, "frank")
			Expect(status).To(Equal(http.StatusTooManyRequests))

			// Two more failures from the same IP with different usernames.
			// The IP counter was at 1 after the blocked username attempt,
			// and should reach its limit (3) after these two.
			for _, username := range []string{"george", "harry"} {
				status := failLoginOnce(c4, loginURL, env().URL, username)
				Expect(status).To(Equal(http.StatusUnauthorized))
			}

			// The IP should now be at its limit.
			getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
			Expect(err).ToNot(HaveOccurred())
			getResp, err := c4.Do(getReq)
			Expect(err).ToNot(HaveOccurred())
			_ = getResp.Body.Close()
			Expect(getResp.StatusCode).To(Equal(http.StatusTooManyRequests),
				"IP should be blocked after username was already blocked")
		})
	}
}

// floodUntilBlocked sends limit+2 failed login attempts from c, stopping early
// if the server starts returning 429 before the loop finishes.
func floodUntilBlocked(c *http.Client, loginURL, origin string, limit int, username string) {
	for i := 0; i < limit+2; i++ {
		status := failLoginOnce(c, loginURL, origin, username)
		if status == http.StatusTooManyRequests {
			break
		}
	}
}

// failLoginOnce performs one GET+POST login cycle with invalid credentials and
// returns the POST response status. Returns 429 early if the GET itself is blocked.
func failLoginOnce(c *http.Client, loginURL, origin, username string) int {
	getReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
	getResp, err := c.Do(getReq)
	if err != nil {
		return 0
	}
	body, _ := io.ReadAll(getResp.Body)
	_ = getResp.Body.Close()
	if getResp.StatusCode == http.StatusTooManyRequests {
		return http.StatusTooManyRequests
	}
	postReq, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, loginURL,
		strings.NewReader(url.Values{
			"username":   {username},
			"password":   {"wrongpass"},
			"csrf_token": {e2eutils.ExtractCSRFToken(body)},
		}.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Origin", origin)
	resp, err := c.Do(postReq)
	if err != nil {
		return 0
	}
	status := resp.StatusCode
	_ = resp.Body.Close()
	return status
}

// clientWithRealIP returns a jar-backed client that injects X-Real-IP on every
// request so the server rate-limiter sees ip regardless of the actual connection.
func clientWithRealIP(env *e2eutils.TestEnv, ip string) *http.Client {
	c := e2eutils.ClientWithJar(env)
	inner := c.Transport
	if inner == nil {
		inner = http.DefaultTransport
	}
	c.Transport = &realIPTransport{Base: inner, IP: ip}
	return c
}

// realIPTransport injects X-Real-IP on every request so the server's
// rate-limiter sees the configured IP regardless of the actual connection.
type realIPTransport struct {
	Base http.RoundTripper
	IP   string
}

func (t *realIPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("X-Real-IP", t.IP)
	return t.Base.RoundTrip(req)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func intStr(n int) string {
	if n == 0 {
		return "disabled"
	}
	return fmt.Sprintf("%d", n)
}

// ErrorPageBehaviors asserts that unauthenticated and 404 responses are HTML.
func ErrorPageBehaviors(env func() *e2eutils.TestEnv) {
	It("should return HTML for unauthenticated access to /", func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+"/", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := e2eutils.Client(env()).Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		// Accept either a redirect to login or a direct HTML 401 page.
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusFound), Equal(http.StatusUnauthorized)))
	})

	It("should return non-JSON response for unknown path", func() {
		resp, err := e2eutils.Client(env()).Get(env().URL + "/nonexistent/path")
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).NotTo(ContainSubstring(`{"code":`))
	})
}

// StaticUserRejectedBehaviors asserts that static user credentials are rejected
// when the server is running in DB mode. creds returns a static username/password
// pair that exists in EmptyConfig-based setups but must not be accepted when a database is configured.
func StaticUserRejectedBehaviors(env func() *e2eutils.TestEnv, creds func() (string, string)) {
	It("should reject static user credentials with 401 in DB mode", func() {
		username, password := creds()
		authPrefix := env().Opts.Server.AuthPrefix
		loginURL := env().URL + authPrefix + "/login"

		base := e2eutils.ClientWithJar(env())
		getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil)
		Expect(err).ToNot(HaveOccurred())
		getResp, err := base.Do(getReq)
		Expect(err).ToNot(HaveOccurred())
		bodyBytes, _ := io.ReadAll(getResp.Body)
		_ = getResp.Body.Close()
		csrfToken := e2eutils.ExtractCSRFToken(bodyBytes)

		form := url.Values{
			"username":   {username},
			"password":   {password},
			"csrf_token": {csrfToken},
		}
		postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, loginURL,
			strings.NewReader(form.Encode()))
		Expect(err).ToNot(HaveOccurred())
		postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		postReq.Header.Set("Accept", "application/json")
		postReq.Header.Set("Origin", env().URL)
		resp, err := base.Do(postReq)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
	})
}

// MeBehaviors asserts the /me profile endpoint.
// creds returns a valid username/password pair.
// expectEmail controls whether the email field must be non-empty
// (DB and OIDC users have email; static users do not).
func MeBehaviors(env func() *e2eutils.TestEnv, creds func() (string, string), expectEmail bool) {
	It("should reject unauthenticated request to /me", func() {
		authPrefix := env().Opts.Server.AuthPrefix
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+authPrefix+"/me", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "application/json")
		resp, err := e2eutils.Client(env()).Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusUnauthorized), Equal(http.StatusFound)))
	})

	It("should return profile for authenticated user", func() {
		username, password := creds()
		c := e2eutils.LoginAs(env(), username, password)
		authPrefix := env().Opts.Server.AuthPrefix
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+authPrefix+"/me", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "application/json")
		resp, err := c.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))

		profile := e2eutils.DecodeData(resp)
		Expect(profile["username"]).To(Equal(username))
		Expect(profile["id_type"]).ToNot(BeEmpty())
		if expectEmail {
			Expect(profile["email"]).ToNot(BeEmpty())
		}
	})
}

// AdminGateBehaviors asserts that the admin gate correctly allows/denies access.
// adminCreds must be a user with system-admin privileges.
// nonAdminCreds must be a regular user without admin privileges.
func AdminGateBehaviors(env func() *e2eutils.TestEnv, adminCreds, nonAdminCreds func() (string, string)) {
	const usersPath = "/ezauth/users/"

	It("should reject unauthenticated request to admin routes", func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env().URL+usersPath, nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "application/json")
		resp, err := e2eutils.Client(env()).Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusUnauthorized), Equal(http.StatusFound)))
	})

	It("should deny non-admin user with 403", func() {
		username, password := nonAdminCreds()
		c := e2eutils.LoginAs(env(), username, password)
		resp := e2eutils.Get(c, env(), usersPath)
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusForbidden))
	})

	It("should allow admin user through the gate", func() {
		username, password := adminCreds()
		c := e2eutils.LoginAs(env(), username, password)
		resp := e2eutils.Get(c, env(), usersPath)
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).ToNot(SatisfyAny(
			Equal(http.StatusUnauthorized),
			Equal(http.StatusForbidden),
			Equal(http.StatusFound),
		))
	})
}

// PortalBehaviors asserts portal availability.
// When enabled=false, the portal route is not registered; unauthenticated
// requests redirect to login (302) and authenticated requests are forwarded
// to the upstream proxy (not served as portal HTML).
// When enabled=true, unauthenticated access redirects to login and
// authenticated access returns a 200 HTML page.
func PortalBehaviors(env func() *e2eutils.TestEnv, enabled bool, creds ...func() (string, string)) {
	authPrefix := func() string { return env().Opts.Server.AuthPrefix }
	profilePath := func() string { return env().URL + authPrefix() + "/portal/profile" }

	if !enabled {
		It("should redirect unauthenticated request to login when portal is disabled", func() {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, profilePath(), nil)
			Expect(err).ToNot(HaveOccurred())
			req.Header.Set("Accept", "text/html,application/xhtml+xml")
			resp, err := e2eutils.Client(env()).Do(req)
			Expect(err).ToNot(HaveOccurred())
			defer func() { _ = resp.Body.Close() }()
			Expect(resp.StatusCode).To(Equal(http.StatusFound))
			Expect(resp.Header.Get("Location")).To(ContainSubstring("/login"))
		})
		return
	}

	It("should redirect unauthenticated request to portal profile", func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, profilePath(), nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := e2eutils.Client(env()).Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusFound))
		Expect(resp.Header.Get("Location")).To(ContainSubstring("/login"))
	})

	It("should return 200 HTML for authenticated portal profile", func() {
		if len(creds) == 0 {
			Skip("no creds provided for portal behavior")
		}
		username, password := creds[0]()
		c := e2eutils.LoginAs(env(), username, password)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, profilePath(), nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := c.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		body, err := io.ReadAll(resp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(ContainSubstring("<html"))
	})
}
