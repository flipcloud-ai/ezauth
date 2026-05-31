//go:build integration

package cmd

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/spf13/cobra"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var pgContainer *tcpostgres.PostgresContainer
var pgCleanup func()

var _ = BeforeSuite(func() {
	ctx := context.Background()
	pg, err := tcpostgres.Run(ctx, "postgres:15-alpine",
		tcpostgres.WithDatabase("testdb"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
	)
	if err != nil {
		Skip("PostgreSQL container not available: " + err.Error())
		return
	}

	connStr, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pg.Terminate(ctx)
		Skip("Failed to get connection string: " + err.Error())
		return
	}

	pgContainer = pg
	pgCleanup = func() { _ = pg.Terminate(ctx) }

	for i := 0; i < 20; i++ {
		db, openErr := sql.Open("pgx", connStr)
		if openErr == nil {
			if pingErr := db.Ping(); pingErr == nil {
				db.Close()
				return
			}
			db.Close()
		}
		time.Sleep(2 * time.Second)
	}
})

var _ = AfterSuite(func() {
	if pgCleanup != nil {
		pgCleanup()
	}
})

var _ = Describe("Database commands (integration)", func() {
	var host, port string
	var secretDir string

	BeforeEach(func() {
		ctx := context.Background()
		var err error
		host, err = pgContainer.Host(ctx)
		Expect(err).ToNot(HaveOccurred())
		mappedPort, err := pgContainer.MappedPort(ctx, "5432")
		Expect(err).ToNot(HaveOccurred())
		port = mappedPort.Port()

		secretDir, err = os.MkdirTemp("", "ezauth-cmd-bootstrap-*")
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(secretDir)
	})

	Describe("init-db command", func() {
		It("should create database and run migrations", func() {
			rootCmd := &cobra.Command{}
			addDBInitCommands(rootCmd)
			rootCmd.SetArgs([]string{"init-db",
				"--driver=pgx",
				"--host=" + host,
				"--port=" + port,
				"--username=postgres",
				"--password=postgres",
				"--database=cmd_init_test",
			})
			Expect(rootCmd.Execute()).To(Succeed())
		})

		It("should be idempotent (database already exists)", func() {
			rootCmd := &cobra.Command{}
			addDBInitCommands(rootCmd)
			rootCmd.SetArgs([]string{"init-db",
				"--driver=pgx",
				"--host=" + host,
				"--port=" + port,
				"--username=postgres",
				"--password=postgres",
				"--database=cmd_init_test",
			})
			Expect(rootCmd.Execute()).To(Succeed())
		})
	})

	Describe("bootstrap command", func() {
		var dbName = "cmd_bootstrap_test"

		BeforeEach(func() {
			rootCmd := &cobra.Command{}
			addDBInitCommands(rootCmd)
			rootCmd.SetArgs([]string{"init-db",
				"--driver=pgx",
				"--host=" + host,
				"--port=" + port,
				"--username=postgres",
				"--password=postgres",
				"--database=" + dbName,
			})
			Expect(rootCmd.Execute()).To(Succeed())
		})

		It("should bootstrap root user and system admin group", func() {
			secretFile := filepath.Join(secretDir, "root_secret")
			rootCmd := &cobra.Command{}
			addBootstrapCommand(rootCmd)
			rootCmd.SetArgs([]string{"bootstrap",
				"--driver=pgx",
				"--host=" + host,
				"--port=" + port,
				"--db-user=postgres",
				"--db-password=postgres",
				"--database=" + dbName,
				"--secret-file=" + secretFile,
				"--username=root",
				"--password=TestPass1",
			})
			Expect(rootCmd.Execute()).To(Succeed())
		})

		It("should be idempotent (safe to run multiple times)", func() {
			secretFile := filepath.Join(secretDir, "root_secret")
			for i := 0; i < 2; i++ {
				rootCmd := &cobra.Command{}
				addBootstrapCommand(rootCmd)
				rootCmd.SetArgs([]string{"bootstrap",
					"--driver=pgx",
					"--host=" + host,
					"--port=" + port,
					"--db-user=postgres",
					"--db-password=postgres",
					"--database=" + dbName,
					"--secret-file=" + secretFile,
					"--username=root",
					"--password=TestPass1",
				})
				Expect(rootCmd.Execute()).To(Succeed())
			}
		})
	})
})
