package config

// AccessConfig holds access-control settings. It is the umbrella for both L2
// (group-based) and L3 (RBAC) features. Fields under this block are optional —
// the server auto-detects the operational layer from what is configured.
type AccessConfig struct {
	SystemAdminGroup string          `mapstructure:"system_admin_group" default:"system-admins"`
	RBAC             RBACConfig      `mapstructure:"rbac"`
	Bootstrap        BootstrapConfig `mapstructure:"bootstrap"`
}

// RBACConfig holds L3 role-based access control settings. Enabled must be true
// AND a database must be configured for RBAC to initialize.
type RBACConfig struct {
	Enabled bool `mapstructure:"enabled" default:"false"`
}

// BootstrapConfig controls idempotent DB bootstrap performed at every startup
// when a database is configured. It creates the root user and a system admin
// group so that admin-API access works even when RBAC is disabled.
//
// SecretFile stores base64("<user>:<password>") written on first run.
type BootstrapConfig struct {
	SecretFile string `mapstructure:"secret_file" default:"/opt/ezauth/bootstrap/root_secret"`
}
