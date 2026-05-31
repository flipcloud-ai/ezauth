package templates

import (
	"bytes"
	"errors"
	"html/template"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/agiledragon/gomonkey/v2"

	testutils "github.com/flipcloud-ai/ezauth/test/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Server Template Test Suite", func() {
	When("template unit test", func() {
		templatePath := testutils.TestPath() + "/statics"
		It("loading templates", func() {
			var logintpl bytes.Buffer
			var errtpl bytes.Buffer
			// Load default templates
			t, _, err := loadTemplates("")
			Expect(err).To(BeNil())
			Expect(t.Lookup("error.html")).NotTo(BeNil())
			Expect(t.Lookup("login.html")).NotTo(BeNil())
			// All admin portal templates must be present in the default bundle.
			for _, adminTmpl := range []string{
				"admin/overview.html",
				"admin/users.html",
				"admin/groups.html",
				"admin/roles.html",
				"admin/policies.html",
				"admin/providers.html",
				"admin/audit.html",
				"admin/nav.html",
			} {
				Expect(t.Lookup(adminTmpl)).NotTo(BeNil(), "default bundle is missing template: "+adminTmpl)
			}
			// Load templates with specific path
			t, _, err = loadTemplates(templatePath + "/html/")
			Expect(err).To(BeNil())
			Expect(t.Lookup("error.html")).NotTo(BeNil())
			Expect(t.Lookup("login.html")).NotTo(BeNil())
			_ = t.Lookup("login.html").Execute(&logintpl, nil)
			loginPage, err := os.ReadFile(templatePath + "/html/login.html")
			Expect(err).To(BeNil())
			Expect(logintpl.String()).To(Equal(string(loginPage)))
			_ = t.Lookup("error.html").Execute(&errtpl, nil)
			errorPage, err := os.ReadFile(templatePath + "/html/error.html")
			Expect(err).To(BeNil())
			Expect(errtpl.String()).To(Equal(string(errorPage)))
		})
		It("loading static files", func() {
			static, err := loadStatics("")
			Expect(err).ToNot(HaveOccurred())
			Expect(static["robots.txt"]).To(Equal(defaultRobots))
			static, err = loadStatics(templatePath + "/html/")
			Expect(err).ToNot(HaveOccurred())
			robotsFile, oerr := os.ReadFile(templatePath + "/html/robots.txt")
			Expect(oerr).To(BeNil())
			Expect(static["robots.txt"]).To(Equal(string(robotsFile)))
		})

		DescribeTable("loading custom assets: non-directory paths",
			func(logoPath, wantLogo, wantFavicon string) {
				logo, favicon, err := loadCustomAssets(logoPath)
				Expect(err).ToNot(HaveOccurred())
				Expect(logo).To(Equal(wantLogo))
				Expect(favicon).To(Equal(wantFavicon))
			},
			Entry("empty path returns defaults", "", defaultLogoData, defaultFaviconData),
			Entry("dash disables both", "-", "", ""),
			Entry("https URL uses URL logo and default favicon",
				"https://logo.com/img.png",
				`<img src="https://logo.com/img.png" alt="Logo" />`,
				defaultFaviconData),
		)

		It("loads SVG logo and reuses it as favicon when favicon.svg is absent", func() {
			dir := GinkgoT().TempDir()
			svgData := "<svg><rect/></svg>"
			Expect(os.WriteFile(filepath.Join(dir, "logo.svg"), []byte(svgData), 0600)).To(Succeed())
			logo, favicon, err := loadCustomAssets(dir)
			Expect(err).ToNot(HaveOccurred())
			Expect(logo).To(Equal(svgData))
			Expect(favicon).To(Equal(svgData))
		})

		It("loads SVG logo and separate favicon.svg independently", func() {
			dir := GinkgoT().TempDir()
			logoSVG := "<svg><circle/></svg>"
			faviconSVG := "<svg><square/></svg>"
			Expect(os.WriteFile(filepath.Join(dir, "logo.svg"), []byte(logoSVG), 0600)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "favicon.svg"), []byte(faviconSVG), 0600)).To(Succeed())
			logo, favicon, err := loadCustomAssets(dir)
			Expect(err).ToNot(HaveOccurred())
			Expect(logo).To(Equal(logoSVG))
			Expect(favicon).To(Equal(faviconSVG))
		})

		It("uses default favicon when raster logo has no favicon.svg", func() {
			dir := GinkgoT().TempDir()
			pngData, rerr := os.ReadFile(templatePath + "/html/logo.png")
			Expect(rerr).ToNot(HaveOccurred())
			Expect(os.WriteFile(filepath.Join(dir, "logo.png"), pngData, 0600)).To(Succeed())
			logo, favicon, err := loadCustomAssets(dir)
			Expect(err).ToNot(HaveOccurred())
			Expect(logo).To(Equal(encodeImg(pngData, "png")))
			Expect(favicon).To(Equal(defaultFaviconData))
		})

		It("returns default logo when directory has no logo.* files", func() {
			dir := GinkgoT().TempDir()
			logo, favicon, err := loadCustomAssets(dir)
			Expect(err).ToNot(HaveOccurred())
			Expect(logo).To(Equal(defaultLogoData))
			Expect(favicon).To(Equal(defaultFaviconData))
		})

		It("returns error for unsupported logo extension", func() {
			dir := GinkgoT().TempDir()
			Expect(os.WriteFile(filepath.Join(dir, "logo.txt"), []byte("text"), 0600)).To(Succeed())
			_, _, err := loadCustomAssets(dir)
			Expect(err).To(HaveOccurred())
		})
	})
})

var _ = Describe("New", func() {
	It("should create a Renderer with default templates", func() {
		r, warnings, err := New("", "")
		Expect(err).ToNot(HaveOccurred())
		Expect(r).NotTo(BeNil())
		Expect(warnings).To(BeEmpty())
	})

	It("should return warnings when templateDir is set but no template files exist", func() {
		_, warnings, err := New("/nonexistent/path/html/", "")
		Expect(err).ToNot(HaveOccurred())
		Expect(warnings).To(HaveLen(2))
	})

	It("should return error for invalid logo path", func() {
		dir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(dir, "logo.txt"), []byte("text"), 0600)).To(Succeed())
		_, _, err := New("", dir)
		Expect(err).To(HaveOccurred())
	})

	It("should return error when loadStatics fails to read a file", func() {
		dir := GinkgoT().TempDir()
		robotsPath := filepath.Join(dir, "robots.txt")
		Expect(os.WriteFile(robotsPath, []byte("robots"), 0000)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(robotsPath, 0600) })
		_, _, err := New(dir+"/", "")
		Expect(err).To(HaveOccurred())
	})

	It("should return warnings and use embedded default when templateDir is set but file is missing", func() {
		dir := GinkgoT().TempDir()
		// 只放 login.html，不放 error.html
		templatePath := testutils.TestPath() + "/statics"
		loginData, rerr := os.ReadFile(templatePath + "/html/login.html")
		Expect(rerr).ToNot(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(dir, "login.html"), loginData, 0600)).To(Succeed())

		r, warnings, err := New(dir+"/", "")
		Expect(err).ToNot(HaveOccurred())
		Expect(r).NotTo(BeNil())
		Expect(warnings).To(HaveLen(1))
		Expect(warnings[0]).To(ContainSubstring("error.html"))
		Expect(warnings[0]).To(ContainSubstring("embedded default"))
	})
})

var _ = Describe("readLogoFile", func() {
	It("should encode jpeg logo as img tag", func() {
		dir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(dir, "logo.jpg"), []byte("fake-jpg"), 0600)).To(Succeed())
		data, found, err := readLogoFile(dir)
		Expect(err).ToNot(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(data).To(ContainSubstring("data:image/jpeg;base64"))
	})

	It("should fail when logo file cannot be read", func() {
		dir := GinkgoT().TempDir()
		logoPath := filepath.Join(dir, "logo.png")
		Expect(os.WriteFile(logoPath, []byte("fake-png"), 0000)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(logoPath, 0600) })
		_, _, err := readLogoFile(dir)
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("loadCustomAssets favicon error", func() {
	It("should return error when favicon.svg exists but cannot be read", func() {
		dir := GinkgoT().TempDir()
		svgData := "<svg><rect/></svg>"
		Expect(os.WriteFile(filepath.Join(dir, "logo.svg"), []byte(svgData), 0600)).To(Succeed())
		faviconPath := filepath.Join(dir, "favicon.svg")
		Expect(os.WriteFile(faviconPath, []byte("<svg/>"), 0000)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(faviconPath, 0600) })
		_, _, err := loadCustomAssets(dir)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("favicon.svg"))
	})
})

var _ = Describe("loadTemplates with custom directory", func() {
	It("should load and use custom template files when both exist", func() {
		templatePath := testutils.TestPath() + "/statics"
		t, warnings, err := loadTemplates(templatePath + "/html/")
		Expect(err).ToNot(HaveOccurred())
		Expect(warnings).To(BeEmpty())
		Expect(t.Lookup("login.html")).ToNot(BeNil())
		Expect(t.Lookup("error.html")).ToNot(BeNil())
		// Admin templates are always embedded defaults.
		Expect(t.Lookup("admin/overview.html")).ToNot(BeNil())
	})

	It("should return error when template file exists but cannot be read (permission denied)", func() {
		dir := GinkgoT().TempDir()
		loginPath := filepath.Join(dir, "login.html")
		Expect(os.WriteFile(loginPath, []byte("<html/>"), 0000)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(loginPath, 0600) })
		_, _, err := loadTemplates(dir + "/")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("Renderer methods", func() {
	var r *Renderer

	BeforeEach(func() {
		var err error
		r, _, err = New("", "")
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("Execute", func() {
		It("should render the named template without error", func() {
			out, err := r.Execute("login.html", map[string]any{"StatusCode": 200})
			Expect(err).NotTo(HaveOccurred())
			Expect(out).NotTo(BeEmpty())
		})

		It("should return error for unknown template", func() {
			_, err := r.Execute("nonexistent.html", nil)
			Expect(err).To(HaveOccurred())
		})

		It("should return error when template execution fails", func() {
			patch := gomonkey.ApplyMethod(&template.Template{}, "Execute", func(_ *template.Template, _ io.Writer, _ any) error {
				return errors.New("simulated execute failure")
			})
			defer patch.Reset()
			_, err := r.Execute("login.html", nil)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("Static", func() {
		It("should return robots.txt content", func() {
			content := r.Static("robots.txt")
			Expect(content).NotTo(BeEmpty())
		})

		It("should return empty string for unknown key", func() {
			Expect(r.Static("unknown.key")).To(BeEmpty())
		})
	})

	Describe("Logo", func() {
		It("should return non-empty logo HTML", func() {
			logo := r.Logo()
			Expect(string(logo)).NotTo(BeEmpty())
		})
	})

	Describe("Handler", func() {
		It("should serve robots.txt as text/plain", func() {
			h := r.Handler("robots.txt")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, nil)
			Expect(rec.Code).To(Equal(200))
			Expect(rec.Header().Get("Content-Type")).To(ContainSubstring("text/plain"))
			Expect(rec.Body.String()).NotTo(BeEmpty())
		})

		It("should serve SVG logo as image/svg+xml", func() {
			h := r.Handler("logo.svg")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, nil)
			Expect(rec.Code).To(Equal(200))
			Expect(rec.Header().Get("Content-Type")).To(Equal("image/svg+xml"))
		})

		It("should return 204 for empty asset", func() {
			// Use a fresh renderer whose statics have an empty key set
			r2, _, _ := New("", "-") // dash disables logo/favicon
			h := r2.Handler("logo.svg")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, nil)
			Expect(rec.Code).To(Equal(204))
		})

		It("should serve raster logo as SVG placeholder when data is an img tag", func() {
			// Build a renderer with a PNG logo so statics["logo.svg"] is an <img ...>
			dir := GinkgoT().TempDir()
			templatePath := testutils.TestPath() + "/statics"
			pngData, _ := os.ReadFile(templatePath + "/html/logo.png")
			Expect(os.WriteFile(filepath.Join(dir, "logo.png"), pngData, 0600)).To(Succeed())
			r3, _, err := New("", dir)
			Expect(err).ToNot(HaveOccurred())
			h := r3.Handler("logo.svg")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, nil)
			Expect(rec.Code).To(Equal(200))
			Expect(rec.Header().Get("Content-Type")).To(Equal("image/svg+xml"))
			// Placeholder SVG is returned, not the <img> tag
			Expect(rec.Body.String()).To(ContainSubstring("<svg"))
		})
	})

})
