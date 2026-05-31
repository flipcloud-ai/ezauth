//go:build e2e

package providers_test

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-rod/rod"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	e2eutils "github.com/flipcloud-ai/ezauth/test/e2e/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDC login flow via static provider", Serial, Ordered, Label("browser"), func() {
	var (
		oidcEnv      *e2eutils.TestEnv
		browser      *rod.Browser
		idp          *mockOIDCIdP
		providerName string
	)

	BeforeAll(func() {
		if e2eutils.ClusterMode() {
			Skip("static provider OIDC flow requires a local mock IdP")
		}

		providerName = "e2e-oidc-" + randomHex(6)
		port := e2eutils.FreePort()
		srvURL := fmt.Sprintf("http://localhost:%d", port)
		callbackURL, _ := url.Parse(srvURL + "/ezauth/callback")

		idp = newMockOIDCIdP(map[string]oidcTestUser{
			"testuser":  oidcUser("testpass", "testuser@mock.idp", "testuser@mock.idp", "Test User", "developers"),
			"adminuser": oidcUser("adminpass", "admin@mock.idp", "admin@mock.idp", "Admin User", "administrators"),
		})
		issuerURL, _ := url.Parse(idp.Issuer)

		opts := providersConfig(pgDB, 10)
		opts.Server.Port = port
		opts.Auth.Provider = append(opts.Auth.Provider, &ezcfg.ProviderConfig{
			ProviderName: providerName,
			Type:         "oauth2",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  callbackURL,
			Scope:        "openid profile email groups",
			UserClaim:    "email",
			OIDCConfig: ezcfg.OIDCConfig{
				Issuer: issuerURL,
			},
		})
		oidcEnv = e2eutils.StartServer(opts, "providers-oidc", 10*time.Second)
		browser = e2eutils.NewBrowser()
	})

	AfterAll(func() {
		if browser != nil {
			browser.MustClose()
		}
		if oidcEnv != nil {
			oidcEnv.Stop()
		}
		if idp != nil {
			idp.Close()
		}
	})

	It("should render the login page with proper HTML structure", func() {
		page := browser.MustPage("")
		defer page.MustClose()
		_ = page.Navigate(oidcEnv.URL + "/ezauth/login")
		page.MustWaitLoad()
		html, err := page.HTML()
		Expect(err).ToNot(HaveOccurred())
		Expect(html).To(ContainSubstring("<html"))
		Expect(html).NotTo(ContainSubstring(`{"code":`))
	})

	It("should redirect unauthenticated users to login page", func() {
		page := browser.MustPage("")
		defer page.MustClose()
		_ = page.Navigate(oidcEnv.URL + "/")
		page.MustWaitLoad()
		Expect(page.MustInfo().URL).To(SatisfyAny(
			ContainSubstring("/ezauth/login"),
			ContainSubstring("/login"),
		))
	})

	It("should complete OIDC login flow via the mock IdP", func() {
		page := browser.MustPage("")
		defer page.MustClose()

		_ = page.Navigate(oidcEnv.URL + "/ezauth/start?provider=" + providerName)
		page.MustWaitLoad()

		page.MustElement("input[name='login'], input[name='username']").MustInput("testuser")
		page.MustElement("input[name='password']").MustInput("testpass")
		page.MustElement("button[type='submit']").MustClick()

		Eventually(func() string {
			info, _ := page.Info()
			if info == nil {
				return ""
			}
			return info.URL
		}).WithTimeout(15 * time.Second).WithPolling(500 * time.Millisecond).Should(
			SatisfyAll(
				Not(ContainSubstring("/auth")),
				Not(ContainSubstring("/login")),
			),
		)

		cookies := page.MustCookies()
		c := e2eutils.Client(oidcEnv)
		verifyReq, err := http.NewRequestWithContext(
			GinkgoT().Context(), http.MethodGet,
			oidcEnv.URL+"/ezauth/verify", nil,
		)
		Expect(err).ToNot(HaveOccurred())
		for _, ck := range cookies {
			verifyReq.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
		}
		verifyResp, err := c.Do(verifyReq)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = verifyResp.Body.Close() }()
		Expect(verifyResp.StatusCode).To(Equal(http.StatusOK))
	})

	It("should return OIDC user profile from /me after login", func() {
		page := browser.MustPage("")
		defer page.MustClose()

		_ = page.Navigate(oidcEnv.URL + "/ezauth/start?provider=" + providerName)
		page.MustWaitLoad()
		page.MustElement("input[name='login'], input[name='username']").MustInput("testuser")
		page.MustElement("input[name='password']").MustInput("testpass")
		page.MustElement("button[type='submit']").MustClick()
		Eventually(func() string {
			info, _ := page.Info()
			if info == nil {
				return ""
			}
			return info.URL
		}).WithTimeout(15 * time.Second).WithPolling(500 * time.Millisecond).Should(
			SatisfyAll(Not(ContainSubstring("/auth")), Not(ContainSubstring("/login"))),
		)

		cookies := page.MustCookies()
		c := e2eutils.Client(oidcEnv)
		meReq, err := http.NewRequestWithContext(
			GinkgoT().Context(), http.MethodGet,
			oidcEnv.URL+"/ezauth/me", nil,
		)
		Expect(err).ToNot(HaveOccurred())
		meReq.Header.Set("Accept", "application/json")
		for _, ck := range cookies {
			meReq.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
		}
		meResp, err := c.Do(meReq)
		Expect(err).ToNot(HaveOccurred())
		defer func() { _ = meResp.Body.Close() }()
		Expect(meResp.StatusCode).To(Equal(http.StatusOK))

		profile := e2eutils.DecodeData(meResp)
		Expect(profile["username"]).ToNot(BeEmpty())
		Expect(profile["email"]).ToNot(BeEmpty())
		Expect(profile["id_type"]).To(Equal("oauth"))
	})

	It("should serve a valid discovery document from the mock IdP", func() {
		c := e2eutils.Client(oidcEnv)
		resp, err := c.Get(idp.URL + "/.well-known/openid-configuration")
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		_ = resp.Body.Close()
	})

	It("should serve JWKS from the mock IdP", func() {
		c := e2eutils.Client(oidcEnv)
		resp, err := c.Get(idp.URL + "/jwks")
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		_ = resp.Body.Close()
	})
})
