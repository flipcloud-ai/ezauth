package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	"github.com/flipcloud-ai/ezauth/pkg/bootstrap"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm"
	"github.com/flipcloud-ai/ezauth/pkg/utils"
)

func addBootstrapCommand(rootCmd *cobra.Command) {
	var bootstrapCmd = &cobra.Command{
		Use:   "bootstrap",
		Short: "Idempotently bootstrap the root user and system admin group",
		Long: `Ensures that the root user and system admin group exist in the database,
creating them if they do not. Safe to run multiple times.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			driver, _ := cmd.Flags().GetString("driver")
			host, _ := cmd.Flags().GetString("host")
			port, _ := cmd.Flags().GetString("port")
			dbUser, _ := cmd.Flags().GetString("db-user")
			dbPassword, _ := cmd.Flags().GetString("db-password")
			sslmode, _ := cmd.Flags().GetString("sslmode")
			connstr := "host=" + host + " user=" + dbUser + " password=" + dbPassword
			if port != "" {
				connstr += " port=" + port
			}
			connstr += " sslmode=" + sslmode
			dbname, _ := cmd.Flags().GetString("database")
			if err := orm.ValidateDBName(dbname); err != nil {
				return err
			}
			connstr += " dbname=" + dbname
			if err := orm.Init(driver, dbname, connstr); err != nil {
				return fmt.Errorf("schema init: %w", err)
			}

			portNum, _ := strconv.Atoi(port)

			dbCfg := ezcfg.DatabaseConfig{
				Driver:   driver,
				Hostname: host,
				Port:     portNum,
				Name:     dbname,
				User:     dbUser,
				Password: ezcfg.NewResolvedSecretRef([]byte(dbPassword)),
				SSL: ezcfg.DatabaseTLSConfig{
					Mode: sslmode,
				},
			}

			db, err := orm.NewDB(cmd.Context(), dbCfg)
			if err != nil {
				return fmt.Errorf("db connect: %w", err)
			}

			zl, err := zap.NewProduction()
			if err != nil {
				return fmt.Errorf("create logger: %w", err)
			}
			logger := ezlog.New(zl)

			secretFile, _ := cmd.Flags().GetString("secret-file")
			adminGroup, _ := cmd.Flags().GetString("system-admin-group")
			rootUser, _ := cmd.Flags().GetString("username")
			rootPass, _ := cmd.Flags().GetString("password")

			if rootPass != "" {
				if !utils.IsValidUsername(rootUser) {
					return fmt.Errorf("invalid root username: %q", rootUser)
				}
				if !utils.IsValidPassword(rootPass) {
					return fmt.Errorf("invalid root password: must be at least 8 characters with uppercase, lowercase, and a digit")
				}
				encoded := base64.StdEncoding.EncodeToString([]byte(rootUser + ":" + rootPass))
				if dir := filepath.Dir(secretFile); dir != "" && dir != "." {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						return fmt.Errorf("create secret dir: %w", err)
					}
				}
				if err := os.WriteFile(secretFile, []byte(encoded+"\n"), 0o600); err != nil {
					return fmt.Errorf("write secret file: %w", err)
				}
			}

			bootstrap.Bootstrap(context.Background(), db, logger, bootstrap.Config{
				SecretFile:       secretFile,
				SystemAdminGroup: adminGroup,
			})
			return nil
		},
	}

	bootstrapCmd.Flags().StringP("driver", "d", "pgx", "database driver (pgx, mysql, sqlite)")
	bootstrapCmd.Flags().String("host", "localhost", "database hostname")
	bootstrapCmd.Flags().String("port", "", "database port")
	bootstrapCmd.Flags().String("db-user", "", "database username")
	bootstrapCmd.Flags().String("db-password", "", "database password")
	bootstrapCmd.Flags().String("database", "ezauth", "database name")
	bootstrapCmd.Flags().String("sslmode", "disable", "database ssl mode (disable, require, verify-ca, verify-full)")
	bootstrapCmd.Flags().String("secret-file", "/opt/ezauth/bootstrap/root_secret", "path to bootstrap secret file")
	bootstrapCmd.Flags().String("username", "root", "root username for bootstrap")
	bootstrapCmd.Flags().String("password", "", "root password for bootstrap")
	bootstrapCmd.Flags().String("system-admin-group", "system-admins", "name of the system admin group")

	_ = bootstrapCmd.MarkFlagRequired("db-user")
	_ = bootstrapCmd.MarkFlagRequired("db-password")
	_ = bootstrapCmd.MarkFlagRequired("port")

	rootCmd.AddCommand(bootstrapCmd)
}
