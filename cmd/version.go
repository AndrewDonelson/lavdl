// Copyright (c) 2026 Nlaak Studios (https://nlaak.com)
// Author: Andrew Donelson (https://www.linkedin.com/in/andrew-donelson/)
//
// version.go — `ladl version` command — prints the build version and commit hash

package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// BuildVersion is injected via -ldflags at build time.
var BuildVersion = "0.1.0-dev"

// BuildDate is injected via -ldflags at build time.
var BuildDate = "unknown"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ladl %s (built %s, %s/%s)\n",
				BuildVersion, BuildDate, runtime.GOOS, runtime.GOARCH)
		},
	}
}
