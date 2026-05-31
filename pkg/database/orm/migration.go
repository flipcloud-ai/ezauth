package orm

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/flipcloud-ai/ezauth/pkg/database"
)

var (
	dbnameRe    = regexp.MustCompile(`dbname=\S+`)
	validDBName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)
)

// ValidateDBName returns an error if name does not match the allowed identifier pattern.
func ValidateDBName(name string) error {
	if !validDBName.MatchString(name) {
		return fmt.Errorf("invalid database name: %q (must match ^[a-zA-Z_][a-zA-Z0-9_]{0,62}$)", name)
	}
	return nil
}

// Init runs auto-migrations for the given driver/dbname using connStr.
func Init(driver string, dbname string, connStr string, silent ...bool) error {
	var db *gorm.DB
	var err error

	gormCfg := &gorm.Config{}
	if len(silent) > 0 && silent[0] {
		gormCfg.Logger = logger.Default.LogMode(logger.Silent)
	}

	if err := ValidateDBName(dbname); err != nil {
		return err
	}

	switch driver {
	case "pgx", "postgres", "postgresql":
		// Connect to the default "postgres" database to create the target database.
		initConnStr := dbnameRe.ReplaceAllString(connStr, "dbname=postgres")
		db, err = gorm.Open(postgres.Open(initConnStr), gormCfg)
		if err != nil {
			return fmt.Errorf("open init connection: %w", err)
		}
		tx := db.Exec(fmt.Sprintf("CREATE DATABASE %s;", dbname))
		if tx.Error != nil {
			var pgErr *pgconn.PgError
			if errors.As(tx.Error, &pgErr) && pgErr.Code == "42P04" {
				// Database already exists — not an error.
			} else {
				return tx.Error
			}
		}
		// Reconnect using the original DSN which already targets the correct database.
		db, err = gorm.Open(postgres.Open(connStr), gormCfg)
		if err != nil {
			return fmt.Errorf("open target connection: %w", err)
		}
	default:
		return fmt.Errorf("unsupported database driver: %s", driver)
	}

	ezdb := &database.Database{DB: db}
	return ezdb.Migrate(context.Background())
}
