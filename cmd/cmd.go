package cmd

import (
	"github.com/spf13/cobra"

	"github.com/flipcloud-ai/ezauth/config"
)

// AddFlags registers common CLI flags on rootCmd.
func AddFlags(rootCmd *cobra.Command) {
	rootCmd.Flags().StringP("config", "f", "/opt/ezauth/config.yaml", "Config file (default is /opt/ezauth/config.yaml)")
	rootCmd.Flags().Bool("debug", false, "Whether enable debug mode in the service")
	rootCmd.Flags().String("log-path", "", "EzAuth log path")
	rootCmd.Flags().String("log-level", "INFO", "EzAuth log level, one of (info, warn, debug)")
	rootCmd.Flags().String("provider-name", "", "Oauth2 provider name")
	rootCmd.Flags().String("client-id", "", "Oauth2 client ID")
	rootCmd.Flags().String("client-secret", "", "Oauth2 client Secret")
	config.AddServerFlags(rootCmd)
	config.AddDBFlags(rootCmd)
}

// Command builds the root cobra command for the ezauth binary.
func Command(function func(opts config.Options) error) *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "ezauth",
		Short: "A tool that can provide a simple and secure way to protect your web applications with OAuth2 / OIDC authentication",
		Long: `
A flexible tool that can act as either a standalone reverse proxy or a middleware component to provide a simple and secure way to protect your web applications with OAuth2 / OIDC authentication`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := config.LoadConfiguration(cmd)
			if err == nil {
				err = function(*opts)
			}
			return err
		},
	}
	AddFlags(rootCmd)
	addDBInitCommands(rootCmd)
	addBootstrapCommand(rootCmd)
	return rootCmd
}
