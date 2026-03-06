// export.go — `ladl export-identity` command.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/AndrewDonelson/ladl/internal/identity"
)

func newExportCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "export-identity",
		Short: "Export an AES-256-GCM encrypted keypair backup",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExport(output)
		},
	}

	home, _ := os.UserHomeDir()
	cmd.Flags().StringVar(&output, "output", filepath.Join(home, "ladl-backup.key"), "output file path")
	return cmd
}

func runExport(outPath string) error {
	passphrase, err := readPassphrase("Passphrase: ")
	if err != nil {
		return err
	}
	confirm, err := readPassphrase("Confirm passphrase: ")
	if err != nil {
		return err
	}
	if passphrase != confirm {
		return fmt.Errorf("passphrases do not match")
	}

	dir := identity.ConfigDir()
	if err := identity.Export(dir, outPath, passphrase); err != nil {
		return err
	}
	fmt.Printf("Identity exported to: %s\n", outPath)
	return nil
}

func readPassphrase(prompt string) (string, error) {
	fmt.Print(prompt)
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	return string(b), nil
}
