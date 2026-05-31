//go:build e2e

package admin_test

import (
	"context"
	"net/http"
	"net/url"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"

	e2eutils "github.com/flipcloud-ai/ezauth/test/e2e/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Self-service /me API", Ordered, func() {
	var userClient *http.Client

	BeforeAll(func() {
		e2eutils.CreateDBUser(rootClient, env, "me-test-user", "MeTestUser1", "me-test@test.local")
		userClient = e2eutils.LoginAs(env, "me-test-user", "MeTestUser1")
	})

	It("should return user profile via GET /me", func() {
		body := decodeData(doJSON(userClient, http.MethodGet, "/ezauth/me", nil))
		Expect(body["username"]).To(Equal("me-test-user"))
		Expect(body["email"]).To(Equal("me-test@test.local"))
	})

	It("should return root profile via GET /me", func() {
		body := decodeData(doJSON(rootClient, http.MethodGet, "/ezauth/me", nil))
		Expect(body["username"]).To(Equal("root"))
	})

	It("should reject unauthenticated access to /me", func() {
		noAuth := e2eutils.Client(env)
		resp, err := noAuth.Get(env.URL + "/ezauth/me")
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(SatisfyAny(Equal(http.StatusFound), Equal(http.StatusUnauthorized)))
		_ = resp.Body.Close()
	})
})

var _ = Describe("Self-service portal pages", Serial, Label("browser"), func() {
	var browser *rod.Browser

	BeforeEach(func() {
		browser = e2eutils.NewBrowser()
	})

	AfterEach(func() {
		if browser != nil {
			browser.MustClose()
		}
	})

	It("should render the profile portal page as HTML", func() {
		page := browser.MustPage("")
		defer page.MustClose()
		setBrowserCookies(page, rootClient)
		_ = page.Navigate(env.URL + "/ezauth/portal/profile")
		page.MustWaitLoad()
		html, err := page.HTML()
		Expect(err).ToNot(HaveOccurred())
		Expect(html).To(ContainSubstring("<html"))
	})

	It("should render the tokens portal page as HTML", func() {
		page := browser.MustPage("")
		defer page.MustClose()
		setBrowserCookies(page, rootClient)
		_ = page.Navigate(env.URL + "/ezauth/portal/tokens")
		page.MustWaitLoad()
		html, err := page.HTML()
		Expect(err).ToNot(HaveOccurred())
		Expect(html).To(ContainSubstring("<html"))
	})

	It("should redirect unauthenticated portal access to login", func() {
		// First check with plain HTTP: the server must 302 to /ezauth/login
		// when the request looks like it came from a browser (Accept: text/html).
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env.URL+"/ezauth/portal/profile", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		noauthClient := e2eutils.Client(env)
		noauthClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
		resp, err := noauthClient.Do(req)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = resp.Body.Close() }()
		GinkgoWriter.Printf("[portal-redir] http status=%d location=%q\n", resp.StatusCode, resp.Header.Get("Location"))
		Expect(resp.StatusCode).To(Equal(http.StatusFound), "portal should redirect unauthenticated access to login")
		Expect(resp.Header.Get("Location")).To(ContainSubstring("/ezauth/login"))

		// Then check with a real browser.
		page := browser.MustPage("")
		defer page.MustClose()
		_ = page.Navigate(env.URL + "/ezauth/portal/profile")
		page.MustWaitLoad()
		Expect(page.MustInfo().URL).To(ContainSubstring("/ezauth/login"))
	})
})

// setBrowserCookies injects session cookies from an authenticated client into the browser page.
func setBrowserCookies(page *rod.Page, c *http.Client) {
	u, _ := url.Parse(env.URL)
	var params []*proto.NetworkCookieParam
	for _, cookie := range c.Jar.Cookies(u) {
		params = append(params, &proto.NetworkCookieParam{
			Name:   cookie.Name,
			Value:  cookie.Value,
			Domain: "localhost",
			Path:   cookie.Path,
		})
	}
	_ = page.SetCookies(params)
}
