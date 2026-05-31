package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/flipcloud-ai/ezauth/pkg/database/orm"
)

func addDBInitCommands(rootCmd *cobra.Command) {
	var dbinit = &cobra.Command{
		Use:   "init-db",
		Short: "Initialize the database schema",
		Long: `
Initialize the database schema for EzAuth`,
		RunE: func(cmd *cobra.Command, args []string) error {
			driver, _ := cmd.Flags().GetString("driver")
			host, _ := cmd.Flags().GetString("host")
			port, _ := cmd.Flags().GetString("port")
			dbUser, _ := cmd.Flags().GetString("username")
			dbPassword, _ := cmd.Flags().GetString("password")
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
			if initErr := orm.Init(driver, dbname, connstr); initErr != nil {
				return fmt.Errorf("init database: %w", initErr)
			}
			return nil
		},
	}
	dbinit.Flags().StringP("driver", "d", "pgx", "database driver (pgx, mysql, sqlite)")
	dbinit.Flags().String("host", "localhost", "database hostname")
	dbinit.Flags().String("port", "", "database port")
	dbinit.Flags().StringP("username", "u", "", "database username")
	dbinit.Flags().StringP("password", "p", "", "database password")
	dbinit.Flags().String("database", "ezauth", "database name")
	dbinit.Flags().String("sslmode", "disable", "database ssl mode (disable, require, verify-ca, verify-full)")
	if err := dbinit.MarkFlagRequired("username"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to mark flag required: %v\n", err)
	}
	if err := dbinit.MarkFlagRequired("password"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to mark flag required: %v\n", err)
	}
	if err := dbinit.MarkFlagRequired("port"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to mark flag required: %v\n", err)
	}
	rootCmd.AddCommand(dbinit)
}
