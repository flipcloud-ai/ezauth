package config

import (
	"time"

	"github.com/spf13/cobra"
)

// DatabaseConfig holds connection parameters for the PostgreSQL database.
type DatabaseConfig struct {
	SkipInit       bool              `mapstructure:"skip_init" default:"false"`
	Driver         string            `mapstructure:"driver" default:"" flag:"database-driver"`
	Hostname       string            `mapstructure:"hostname" default:"localhost" flag:"database-host"`
	SSL            DatabaseTLSConfig `mapstructure:"ssl"`
	Port           int               `mapstructure:"port" flag:"database-port" default:"5432"`
	Name           string            `mapstructure:"database_name" default:"ezauth" flag:"database-name"`
	User           string            `mapstructure:"user" default:"" flag:"database-user"`
	Password       SecretRef         `mapstructure:"password" json:"-"`
	ConnectTimeout time.Duration     `mapstructure:"connect_timeout" default:"5s" flag:"database-connect-timeout"`

	// MaxConnLifetime is the duration since creation after which a connection will be automatically closed.
	MaxConnLifetime time.Duration `mapstructure:"max_conn_lifetime"`

	// MaxConnLifetimeJitter is the duration after MaxConnLifetime to randomly decide to close a connection.
	// This helps prevent all connections from being closed at the exact same time, starving the pool.
	MaxConnLifetimeJitter time.Duration `mapstructure:"max_conn_lifetime_jitter"`

	// MaxConnIdleTime is the duration after which an idle connection will be automatically closed by the health check.
	MaxConnIdleTime time.Duration `mapstructure:"max_conn_idle_time"`

	// PingTimeout is the maximum amount of time to wait for a connection to pong before considering it as unhealthy and
	// destroying it. If zero, the default is no timeout.
	PingTimeout time.Duration `mapstructure:"ping_timeout"`

	// MaxConns is the maximum size of the pool.
	MaxConns int32 `mapstructure:"max_conns"`

	// MinConns is the minimum size of the pool.
	MinConns int32 `mapstructure:"min_conns"`

	// MinIdleConns is the minimum number of idle connections in the pool.
	MinIdleConns int32 `mapstructure:"min_idle_conns"`
	// HealthCheckPeriod is the duration between checks of the health of idle connections.
	HealthCheckPeriod time.Duration `mapstructure:"healthcheck_period"`
	// DropUnusedColumns when enabled causes Migrate to drop database columns not present
	// in Go struct definitions. This is a destructive operation and should remain disabled in production.
	DropUnusedColumns bool `mapstructure:"drop_unused_columns" default:"false"`
}

// DatabaseTLSConfig holds TLS settings for the database connection.
type DatabaseTLSConfig struct {
	Mode         string `mapstructure:"mode" default:"disable" flag:"database-ssl-mode"`
	RootCert     string `mapstructure:"root_cert"`
	Cert         string `mapstructure:"cert"`
	Key          string `mapstructure:"key"`
	Password     string `mapstructure:"password"`
	SNI          string `mapstructure:"sni"`
	NegotiateTLS string `mapstructure:"negotiate_tls"`
}

// AddDBFlags registers database connection flags on cmd.
func AddDBFlags(cmd *cobra.Command) {
	cmd.Flags().String("database-driver", "", "The database driver (pgx, mysql, sqlite)")
	cmd.Flags().String("database-host", "localhost", "The hostname for the ezauth database")
	cmd.Flags().String("database-ssl-mode", "disable", "Whether enable ssl mode for ezauth database")
	cmd.Flags().Int("database-port", 5432, "The port for the ezauth database")
	cmd.Flags().String("database-name", "ezauth", "The database name for the ezauth database")
	cmd.Flags().String("database-user", "postgres", "The username for the ezauth database")
	cmd.Flags().String("database-password", "", "The password for the ezauth database")
	cmd.Flags().String("database-connect-timeout", "5s", "Connection timeout for ezauth database")
}
