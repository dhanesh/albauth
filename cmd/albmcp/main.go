// Command albmcp is an MCP server that transparently handles AWS ALB
// authenticate-oidc sessions, so an MCP client can call protected API URLs
// without knowing anything about the authentication layer in front of them.
package main

import (
	"context"
	"os"

	"albmcp/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

func main() {
	os.Exit(cli.Run(context.Background(), cli.Env{
		Args:    os.Args[1:],
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Version: version,
	}))
}
