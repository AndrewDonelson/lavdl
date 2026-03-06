// Copyright (c) 2026 Nlaak Studios (https://nlaak.com)
// Author: Andrew Donelson (https://www.linkedin.com/in/andrew-donelson/)
//
// helpers.go — shared CLI utilities (context helpers used by all commands)

package cmd

import "context"

// cmd_ctx returns a background context for use in CLI command handlers.
func cmd_ctx() context.Context {
	return context.Background()
}
