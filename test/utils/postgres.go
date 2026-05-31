//go:build integration || e2e

package utils

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	. "github.com/onsi/ginkgo/v2"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// NewPostgresContainer starts a throwaway PostgreSQL container and returns a
// ready DSN and a cleanup function. Calls Skip (not Fail) when Docker is
// unavailable so suites degrade gracefully in environments without Docker.
func NewPostgresContainer() (connStr string, cleanup func()) {
	ctx := context.Background()
	pg, err := tcpostgres.Run(ctx, "postgres:15-alpine",
		tcpostgres.WithDatabase("testdb"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
	)
	if err != nil {
		Skip("PostgreSQL container not available: " + err.Error())
		return "", func() {}
	}

	connStr, err = pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pg.Terminate(ctx)
		Skip("Failed to get connection string: " + err.Error())
		return "", func() {}
	}

	cleanup = func() { _ = pg.Terminate(ctx) }

	for i := 0; i < 20; i++ {
		db, err := sql.Open("pgx", connStr)
		if err == nil {
			if err := db.Ping(); err == nil {
				db.Close()
				return connStr, cleanup
			}
			db.Close()
		}
		time.Sleep(2 * time.Second)
	}

	cleanup()
	Skip("PostgreSQL not ready after 40 seconds")
	return "", func() {}
}
