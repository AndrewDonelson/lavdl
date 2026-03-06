package cmd

import "context"

// cmd_ctx returns a background context for use in CLI command handlers.
func cmd_ctx() context.Context {
	return context.Background()
}
