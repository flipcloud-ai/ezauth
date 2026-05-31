// @title           EzAuth API
// @version         1.0.0
// @description     OAuth2 / OIDC authentication reverse proxy. Supports username/password login, OIDC provider federation, session management, and admin CRUD for users, groups, providers, and RBAC.
// @termsOfService  https://github.com/flipcloud-ai/ezauth

// @contact.name   EzAuth Maintainers
// @contact.url    https://github.com/flipcloud-ai/ezauth

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

// @host      localhost:8080
// @BasePath  /

// @securityDefinitions.apikey  BearerAuth
// @in                          header
// @name                        Authorization
// @description                 JWT bearer token obtained from a successful login. Prefix with "Bearer ".

// @securityDefinitions.apikey  CookieAuth
// @in                          cookie
// @name                        _xw_session
// @description                 Session cookie set after login. Used by browser-based clients.

package main

import (
	"os"

	"github.com/flipcloud-ai/ezauth/cmd"
)

// Version is the current version of EzAuth.
var Version = "0.0.1"

//go:generate ./scripts/generate-swagger.sh

func main() {
	rootCmd := cmd.Command(Start)
	rootCmd.Flags().String("version", Version, "EzAuth version")
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
