package config

// AuthProxyConfig configures the reverse-proxy authentication layer.
type AuthProxyConfig struct {
	Enabled         *bool                 `mapstructure:"enabled" default:"true" flag:"proxy-enabled"`
	JSONResponse    bool                  `mapstructure:"json_response" default:"false" flag:"json-response"`
	ProxyPrefix     string                `mapstructure:"prefix" default:"/"`
	SkipAuthPaths   []SkipAuthConfig      `mapstructure:"skip_auth_paths"`
	AllowDomains    []string              `mapstructure:"allow_domains"`
	IdentityHeaders IdentityHeadersConfig `mapstructure:"identity_headers"`
}

// IdentityHeadersConfig specifies the header names used to forward identity
// information from the session to the upstream service.
type IdentityHeadersConfig struct {
	User    string `mapstructure:"user"    default:"X-Auth-User"`
	Email   string `mapstructure:"email"   default:"X-Auth-Email"`
	Groups  string `mapstructure:"groups"  default:"X-Auth-Groups"`
	Subject string `mapstructure:"subject" default:"X-Auth-Subject"`
}

// IsEnabled returns true when the reverse proxy should be initialized.
// Returns true by default (nil == not configured) for backward compatibility.
func (p *AuthProxyConfig) IsEnabled() bool {
	if p == nil {
		return true
	}
	return p.Enabled == nil || *p.Enabled
}

// SkipAuthConfig defines a path/method pattern that bypasses authentication.
type SkipAuthConfig struct {
	Path   string `mapstructure:"path"`
	Method string `mapstructure:"method"`
	Match  string `mapstructure:"match" default:"exact"`
}
