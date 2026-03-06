// Package cmd provides the LADL CLI commands.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile    string
	ledgerMode bool
	port       int
	forceFlag  bool
)

// rootCmd is the top-level cobra command.
var rootCmd = &cobra.Command{
	Use:   "ladl",
	Short: "Linux Age Distributed Ledger — age verification service",
	Long: `ladl is a privacy-preserving, decentralized age verification service for Linux.

Without any subcommand, ladl runs as a service daemon.
Use --ledger to run as a full LADL node.`,
	RunE: runDaemon,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "/etc/ladl/config.yaml", "config file path")
	rootCmd.PersistentFlags().BoolVar(&ledgerMode, "ledger", false, "run as full LADL ledger node")
	rootCmd.PersistentFlags().IntVar(&port, "port", 7743, "HTTP listen port")
	rootCmd.AddCommand(
		newVerifyCmd(),
		newStatusCmd(),
		newUUIDCmd(),
		newExportCmd(),
		newImportCmd(),
		newRevokeCmd(),
		newVersionCmd(),
	)
}
