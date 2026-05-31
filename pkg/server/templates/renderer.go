package templates

import (
	// Import embed to allow importing default page templates
	"bytes"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed html/error.html
var defaultErrorTemplate string

//go:embed html/login.html
var defaultSignInTemplate string

//go:embed html/robots.txt
var defaultRobots string

//go:embed html/logo.svg
var defaultLogoData string

//go:embed html/favicon.svg
var defaultFaviconData string

//go:embed html/admin/nav.html
var defaultAdminNavTemplate string

//go:embed html/admin/overview.html
var defaultAdminOverviewTemplate string

//go:embed html/admin/users.html
var defaultAdminUsersTemplate string

//go:embed html/admin/groups.html
var defaultAdminGroupsTemplate string

//go:embed html/admin/roles.html
var defaultAdminRolesTemplate string

//go:embed html/admin/policies.html
var defaultAdminPoliciesTemplate string

//go:embed html/admin/providers.html
var defaultAdminProvidersTemplate string

//go:embed html/admin/audit.html
var defaultAdminAuditTemplate string

//go:embed html/admin/profile.html
var defaultAdminProfileTemplate string

//go:embed html/admin/tokens.html
var defaultAdminTokensTemplate string

// StaticFiles holds the embedded CSS, JS, and font assets served under the static prefix.
//
//go:embed static/*
var StaticFiles embed.FS

// Renderer holds the loaded HTML templates and static assets for the server UI.
type Renderer struct {
	tmpl    *template.Template
	statics map[string]string
	pool    sync.Pool
}

// New loads templates from templateDir (empty string uses embedded defaults) and
// logo/favicon assets from logoPath, returning a ready-to-use Renderer.
// Warnings are returned when templateDir is set but individual template files are
// missing and the embedded default is used as a fallback.
func New(templateDir, logoPath string) (*Renderer, []string, error) {
	tmpl, warnings, err := loadTemplates(templateDir)
	if err != nil {
		return nil, nil, err
	}
	statics, err := loadStatics(templateDir)
	if err != nil {
		return nil, nil, err
	}
	if statics == nil {
		statics = make(map[string]string)
	}
	statics["logo.svg"], statics["favicon.svg"], err = loadCustomAssets(logoPath)
	if err != nil {
		return nil, nil, err
	}
	r := &Renderer{tmpl: tmpl, statics: statics}
	r.pool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
	return r, warnings, nil
}

// Execute renders the named template into a byte slice.
// Returns an error if the template is not found or rendering fails.
func (r *Renderer) Execute(name string, data any) ([]byte, error) {
	t := r.tmpl.Lookup(name)
	if t == nil {
		return nil, fmt.Errorf("template %q not found", name)
	}
	buf := r.pool.Get().(*bytes.Buffer)
	buf.Reset()
	defer r.pool.Put(buf)
	if err := t.Execute(buf, data); err != nil {
		return nil, fmt.Errorf("execute template %q: %w", name, err)
	}
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out, nil
}

// Static returns the static asset string for the given key.
func (r *Renderer) Static(key string) string {
	return r.statics[key]
}

// Logo returns the logo SVG/HTML as a template.HTML value.
func (r *Renderer) Logo() template.HTML {
	return template.HTML(r.statics["logo.svg"]) //nolint:gosec // logo.svg is loaded from controlled server static files
}

// Handler returns an http.HandlerFunc that serves the static asset for key.
// For SVG keys, it sets Content-Type image/svg+xml and handles raster logo
// replacement. Returns 204 when the asset is empty.
func (r *Renderer) Handler(key string) http.HandlerFunc {
	return func(rw http.ResponseWriter, _ *http.Request) {
		data := r.statics[key]
		if data == "" {
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasSuffix(key, ".txt") {
			rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = rw.Write([]byte(data))
			return
		}
		if strings.HasPrefix(data, "<img ") {
			data = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>`
		}
		rw.Header().Set("Content-Type", "image/svg+xml")
		_, _ = rw.Write([]byte(data))
	}
}

func loadStatics(templateDir string) (map[string]string, error) {
	static := map[string]string{
		"robots.txt": defaultRobots,
	}
	for p := range static {
		filePath := filepath.Join(templateDir, p)
		if _, err := os.Stat(filePath); err == nil {
			b, err := os.ReadFile(filePath) //nolint:gosec // path is constructed from config-provided templateDir
			if err != nil {
				return nil, fmt.Errorf("failed to read static file %s: %w", filePath, err)
			}
			static[p] = string(b)
		}
	}
	return static, nil
}

func loadTemplates(templateDir string) (*template.Template, []string, error) {
	t := template.New("").Funcs(template.FuncMap{
		"ToUpper":   strings.ToUpper,
		"ToLower":   strings.ToLower,
		"GetURL":    func(u *url.URL) string { return u.String() },
		"UrlEscape": url.QueryEscape,
	})
	// customizable holds templates that can be overridden via templateDir.
	customizable := map[string]string{
		"login.html": defaultSignInTemplate,
		"error.html": defaultErrorTemplate,
	}
	// adminTemplates are always served from embedded defaults.
	adminTemplates := map[string]string{
		"admin/nav.html":       defaultAdminNavTemplate,
		"admin/overview.html":  defaultAdminOverviewTemplate,
		"admin/users.html":     defaultAdminUsersTemplate,
		"admin/groups.html":    defaultAdminGroupsTemplate,
		"admin/roles.html":     defaultAdminRolesTemplate,
		"admin/policies.html":  defaultAdminPoliciesTemplate,
		"admin/providers.html": defaultAdminProvidersTemplate,
		"admin/audit.html":     defaultAdminAuditTemplate,
		"admin/profile.html":   defaultAdminProfileTemplate,
		"admin/tokens.html":    defaultAdminTokensTemplate,
	}
	var (
		err      error
		warnings []string
	)
	for p, h := range customizable {
		if templateDir != "" {
			filePath := filepath.Join(templateDir, p)
			if _, statErr := os.Stat(filePath); statErr != nil {
				if !os.IsNotExist(statErr) {
					return nil, nil, fmt.Errorf("stat template file %q: %w", filePath, statErr)
				}
				// File not found — fallback to embedded default and record a warning.
				warnings = append(warnings, fmt.Sprintf("template %q not found in %q, using embedded default", p, templateDir))
			} else {
				t, err = t.ParseFiles(filePath)
				if err != nil {
					return nil, nil, fmt.Errorf("parse template file %q: %w", filePath, err)
				}
				continue
			}
		}

		t, err = t.Parse(h)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse http template %s", p)
		}
	}
	for p, h := range adminTemplates {
		t, err = t.Parse(h)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse http template %s", p)
		}
	}

	return t, warnings, nil
}

// loadCustomAssets loads the logo and favicon from logoPath.
// logoPath may be "", "-", an https:// URL, or a directory path.
// When logoPath is a directory, it globs for logo.* and favicon.svg.
// If logo.* is an SVG and favicon.svg is absent, favicon reuses the logo data.
func loadCustomAssets(logoPath string) (logo, favicon string, err error) {
	if logoPath == "" {
		return defaultLogoData, defaultFaviconData, nil
	}
	if logoPath == "-" {
		return "", "", nil
	}
	if strings.HasPrefix(logoPath, "https://") {
		return fmt.Sprintf("<img src=\"%s\" alt=\"Logo\" />", logoPath), defaultFaviconData, nil
	}

	logo, logoFound, err := readLogoFile(logoPath)
	if err != nil {
		return "", "", err
	}

	faviconPath := filepath.Join(logoPath, "favicon.svg")
	faviconData, ferr := os.ReadFile(faviconPath) //nolint:gosec // path is constructed from config-provided logoPath
	if ferr == nil {
		favicon = string(faviconData)
	} else if os.IsNotExist(ferr) {
		// reuse SVG logo as favicon only if we actually loaded one from disk
		if logoFound && !strings.HasPrefix(logo, "<img ") {
			favicon = logo
		} else {
			favicon = defaultFaviconData
		}
	} else {
		return "", "", fmt.Errorf("reading favicon.svg: %w", ferr)
	}

	return logo, favicon, nil
}

// readLogoFile reads logo.* (first match) from dir.
// Returns (data, true, nil) when a file is found, (defaultLogoData, false, nil) when none exists.
func readLogoFile(dir string) (data string, found bool, err error) {
	matches, globErr := filepath.Glob(filepath.Join(dir, "logo.*"))
	if globErr != nil {
		return "", false, fmt.Errorf("glob logo.*: %w", globErr)
	}
	if len(matches) == 0 {
		return defaultLogoData, false, nil
	}

	logoPath := matches[0]
	logoData, readErr := os.ReadFile(logoPath) //nolint:gosec // path is constructed from config-provided dir
	if readErr != nil {
		return "", false, readErr //nolint:wrapcheck // return raw error so callers can use os.Is(err)
	}

	switch strings.ToLower(filepath.Ext(logoPath)) {
	case ".svg":
		return string(logoData), true, nil
	case ".jpg", ".jpeg":
		return encodeImg(logoData, "jpeg"), true, nil
	case ".png":
		return encodeImg(logoData, "png"), true, nil
	default:
		return "", false, fmt.Errorf("unknown extension: %q, supported extensions are .svg, .jpg, .jpeg and .png", filepath.Ext(logoPath))
	}
}

// encodeImg takes the raw image data and converts it to an HTML Img tag with
// a base64 data source.
func encodeImg(data []byte, format string) string {
	b64Data := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("<img src=\"data:image/%s;base64,%s\" alt=\"Logo\" />", format, b64Data)
}
