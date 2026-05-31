package pgx

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"moul.io/zapgorm2"

	"github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
)

// DefaultAppName is the application_name sent to PostgreSQL for monitoring.
const DefaultAppName = "ezauth"

// PGxDB is a PostgreSQL database handle backed by pgxpool and GORM.
//
//nolint:revive // established API name; renaming would be a breaking change
type PGxDB struct {
	ezdb.Database
}

func txErrorToDBError(err error) error {
	if strings.HasPrefix(err.Error(), "validation error") {
		return ezdb.NewDatabaseError(http.StatusBadRequest, err)
	}
	if err == gorm.ErrDuplicatedKey {
		return ezdb.ErrConflict
	}
	return ezdb.ErrOperation
}

// ConnString builds a PostgreSQL connection string from the given configuration.
func ConnString(cfg config.DatabaseConfig) string {
	fields := []string{
		"host=" + escapeConnVal(cfg.Hostname),
		"port=" + strconv.Itoa(cfg.Port),
		"user=" + escapeConnVal(cfg.User),
		"application_name=" + DefaultAppName,
		"sslmode=" + cfg.SSL.Mode,
		"password=" + escapeConnVal(cfg.Password.String()),
		"dbname=" + cfg.Name,
	}
	if cfg.SSL.Mode != "disable" {
		if cfg.SSL.RootCert != "" {
			fields = append(fields, "sslrootcert="+escapeConnVal(cfg.SSL.RootCert))
		}
		if cfg.SSL.Cert != "" {
			fields = append(fields, "sslcert="+escapeConnVal(cfg.SSL.Cert))
		}
		if cfg.SSL.Key != "" {
			fields = append(fields, "sslkey="+escapeConnVal(cfg.SSL.Key))
		}
	}

	if cfg.MaxConns > 0 {
		fields = append(fields, "pool_max_conns="+strconv.Itoa(int(cfg.MaxConns)))
	}
	if cfg.MinConns > 0 {
		fields = append(fields, "pool_min_conns="+strconv.Itoa(int(cfg.MinConns)))
	}
	if cfg.MaxConnIdleTime > 0 {
		fields = append(fields, "pool_max_conn_idle_time="+cfg.MaxConnIdleTime.String())
	}
	if cfg.MaxConnLifetime > 0 {
		fields = append(fields, "pool_max_conn_lifetime="+cfg.MaxConnLifetime.String())
	}
	if cfg.HealthCheckPeriod > 0 {
		fields = append(fields, "pool_health_check_period="+cfg.HealthCheckPeriod.String())
	}
	if cfg.MaxConnLifetimeJitter > 0 {
		fields = append(fields, "pool_max_conn_lifetime_jitter="+cfg.MaxConnLifetimeJitter.String())
	}

	return strings.Join(fields, " ")
}

// escapeConnVal escapes and single-quotes a connection-string value when it
// contains characters that would break the libpq keyword=value parser.
func escapeConnVal(v string) string {
	if !strings.ContainsAny(v, " \\'\t\n") {
		return v
	}
	s := strings.ReplaceAll(v, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	return "'" + s + "'"
}

// PGxPool constructs a PGxDB backed by a pgxpool connection pool.
//
//nolint:revive // established API name; renaming would be a breaking change
func PGxPool(ctx context.Context, cfg config.DatabaseConfig) (*PGxDB, error) {
	config, err := pgxpool.ParseConfig(ConnString(cfg))
	logger := ezlog.FromContext(ctx, "server")
	if err != nil {
		logger.Error("failed to parse postgres config", ezlog.Err(err))
		return nil, ezdb.NewDatabaseError(http.StatusInternalServerError, err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		logger.Error("failed to create postgres pool", ezlog.Err(err))
		return nil, ezdb.NewDatabaseError(http.StatusInternalServerError, err)
	}
	// Use stdlib connector to expose pgxpool as database/sql compatible interface
	// This maintains the pool semantics while providing sql.DB interface for GORM
	connector := stdlib.GetPoolConnector(pool)
	sqlDB := sql.OpenDB(connector)

	// CRITICAL: Set MaxIdleConns to 0 as per GetPoolConnector documentation
	// The pgxpool manages all connections internally. Setting idle connections on sql.DB
	// would cause it to hold connections outside the pool, starving direct pgxpool users.
	sqlDB.SetMaxIdleConns(0)

	// Set MaxOpenConns to match pgxpool's MaxConns to prevent sql.DB from trying
	// to open more connections than the pool allows
	if cfg.MaxConns > 0 {
		sqlDB.SetMaxOpenConns(int(cfg.MaxConns))
	}

	// Connection lifetime is managed by pgxpool, but we set it on sql.DB as well
	// to ensure consistency in connection recycling behavior
	if cfg.MaxConnLifetime > 0 {
		sqlDB.SetConnMaxLifetime(cfg.MaxConnLifetime)
	}

	// Open GORM with the properly configured sql.DB backed by pgxpool
	gormDB, err := gorm.Open(
		postgres.New(postgres.Config{
			Conn: sqlDB,
		}),
		&gorm.Config{
			Logger:                 zapgorm2.New(logger.Zap()),
			SkipDefaultTransaction: true, // Disable default transactions for performance
			PrepareStmt:            true, // Enable prepared statement cache for better performance
		},
	)
	pgxdb := &PGxDB{
		Database: ezdb.Database{
			Logger:            logger,
			DropUnusedColumns: cfg.DropUnusedColumns,
		},
	}
	pgxdb.DB = gormDB
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		e := errors.Unwrap(err)
		var pgErr *pgconn.PgError
		if errors.As(e, &pgErr) && pgErr.Code == "3D000" {
			logger.Error("database does not exist", ezlog.Str("name", cfg.Name))
			return nil, ezdb.ErrNoDatabase
		}
		logger.Error("fail to connect to database", ezlog.Str("name", cfg.Name))
		return nil, ezdb.NewDatabaseError(http.StatusInternalServerError, err)
	}
	return pgxdb, nil
}
