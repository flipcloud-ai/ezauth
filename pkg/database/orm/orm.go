package orm

import (
	"context"
	"fmt"
	"net/http"

	"github.com/flipcloud-ai/ezauth/config"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/pgx"
)

// DSN returns the data source name for the given database configuration.
func DSN(cfg config.DatabaseConfig) string {
	switch cfg.Driver {
	case "pgx", "postgres", "postgresql":
		return pgx.ConnString(cfg)
	default:
		return ""
	}
}

// NewDB constructs and returns a DatabaseInterface for the given configuration.
func NewDB(ctx context.Context, cfg config.DatabaseConfig) (database.DatabaseInterface, error) {
	if err := ValidateDBName(cfg.Name); err != nil {
		return nil, database.NewDatabaseError(http.StatusBadRequest, err)
	}
	switch cfg.Driver {
	case "pgx", "postgres", "postgresql":
		return pgx.PGxPool(ctx, cfg)
	default:
		return nil, database.NewDatabaseError(http.StatusInternalServerError, fmt.Errorf("unsupported database driver: %s", cfg.Driver))
	}
}
