// Copyright (c) 2026 Nlaak Studios (https://nlaak.com)
// Author: Andrew Donelson (https://www.linkedin.com/in/andrew-donelson/)
//
// import.go — `ladl import-identity` command — decrypts and restores a keypair backup

package cmd

import (
	"fmt"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/AndrewDonelson/ladl/internal/identity"
)

func newImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import-identity <backup-file>",
		Short: "Restore identity from an encrypted backup",
		Args:  cobra.ExactArgs(1),
		RunE:  runImport,
	}
	cmd.Flags().BoolP("force", "f", false, "overwrite existing identity")
	return cmd
}

func runImport(cmd *cobra.Command, args []string) error {
	backupPath := args[0]
	overwrite, _ := cmd.Flags().GetBool("force")

	fmt.Print("Enter passphrase: ")
	passBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	dir := identity.ConfigDir()
	uid, err := identity.Import(dir, backupPath, string(passBytes), overwrite)
	if err != nil {
		return err
	}

	fmt.Printf("Identity restored. UUID: %s\n", uid.UUID)
	return nil
}
