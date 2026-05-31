package config

import (
	"net/url"

	"github.com/spf13/cobra"
)

// PprofConfig controls the Go pprof debug endpoint.
type PprofConfig struct {
	Enabled bool `mapstructure:"enabled" default:"false" flag:"pprof-enabled"`
}

// ServerConfig holds HTTP server settings including ports, timeouts, and path prefixes.
type ServerConfig struct {
	ForceHTTPS        bool         `mapstructure:"force_https" default:"false" flag:"force-https"`
	TLS               TLSConfig    `mapstructure:"tls"`
	Http2             bool         `mapstructure:"http2" default:"false" flag:"http2"`
	Hostname          string       `mapstructure:"hostname" default:"0.0.0.0" flag:"hostname"`
	Port              int          `mapstructure:"port" flag:"port"`
	IdleTimeout       int          `mapstructure:"idle_timeout" default:"60" flag:"idle-timeout"`
	WriteTimeout      int          `mapstructure:"write_timeout" default:"300" flag:"write-timeout"`
	ReadTimeout       int          `mapstructure:"read_timeout" default:"300" flag:"read-timeout"`
	ReadHeaderTimeout int          `mapstructure:"read_header_timeout" default:"10" flag:"read-header-timeout"`
	TemplatePath      string       `mapstructure:"template_path"`
	LogoPath          string       `mapstructure:"logo_path"`
	Portal            PortalConfig `mapstructure:"portal"`
	AppName           string       `mapstructure:"app_name" default:"ezauth"`
	HideAppName       bool         `mapstructure:"hide_app_name" default:"false"`
	Upstream          *url.URL     `mapstructure:"upstream" default:"http://127.0.0.1:8080" flag:"upstream"`

	AuthPrefix            string        `mapstructure:"auth_prefix" default:"/ezauth"`
	StaticPrefix          string        `mapstructure:"static_prefix" default:"/static"`
	TrustForwardedHeaders *bool         `mapstructure:"trust_forwarded_headers" default:"true"`
	Pprof                 PprofConfig   `mapstructure:"pprof"`
	Metrics               MetricsConfig `mapstructure:"metrics"`
}

// MetricsConfig holds settings for the Prometheus /metrics endpoint.
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled" default:"false" flag:"metrics-enabled"`
	Path    string `mapstructure:"path" default:"/metrics"`
	Port    int    `mapstructure:"port" default:"9090" flag:"metrics-port"`
	Host    string `mapstructure:"host" default:"127.0.0.1" flag:"metrics-host"`
}

// TLSConfig holds TLS certificate and cipher settings for the HTTP server.
type TLSConfig struct {
	Enabled      bool     `mapstructure:"enabled" flag:"tls-enable"`
	CertPath     string   `mapstructure:"cert_path" default:"/opt/ezauth/tls/cert.crt" flag:"tls-cert"`
	KeyPath      string   `mapstructure:"key_path" default:"/opt/ezauth/tls/key.pem" flag:"tls-key"`
	CipherSuites []string `mapstructure:"cipher_suites"`
	Version      string   `mapstructure:"version" default:"TLS1.2"`
}

// PortalConfig controls the admin web UI portal.
type PortalConfig struct {
	Enabled bool `mapstructure:"enabled" default:"false"`
}

// AddServerFlags registers HTTP server flags on cmd.
func AddServerFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("force-https", false, "Whether force ezauth redirect http to https")
	cmd.Flags().Bool("http2", false, "Whether enable http2 protocol")
	cmd.Flags().IntP("port", "p", 8088, "the port for the server to listen on")
	cmd.Flags().String("hostname", "localhost", "the hostname for the server to listen on")
	cmd.Flags().Int("idle-timeout", 60, "the maximum amount of time an idle connection will remain, default is 60")
	cmd.Flags().Int("write-timeout", 300, "the maximum duration before timing out writes of the response, default is 300")
	cmd.Flags().Int("read-timeout", 300, "the maximum duration for reading the entire request, default is 300")
	cmd.Flags().Int("read-header-timeout", 10, "the maximum duration for reading the request headers, default is 10")
	cmd.Flags().Bool("pprof-enabled", false, "Enable pprof debug endpoints (exposes runtime profiling data)")
	cmd.Flags().Bool("tls-enable", false, "Whether enable TLS")
	cmd.Flags().String("tls-cert", "/opt/ezauth/tls/cert.crt", "TLS certificate path")
	cmd.Flags().String("tls-key", "/opt/ezauth/tls/key.pem", "TLS private key path")
	cmd.Flags().Bool("metrics-enabled", false, "Enable Prometheus /metrics endpoint on a separate port")
	cmd.Flags().Int("metrics-port", 9090, "Port for the standalone metrics HTTP listener")
	cmd.Flags().String("metrics-host", "127.0.0.1", "Bind address for the metrics HTTP listener")
}
