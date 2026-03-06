// verify.go — `ladl verify` command.
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	ladlerrors "github.com/AndrewDonelson/ladl/internal/errors"
	"github.com/AndrewDonelson/ladl/internal/format"
	"github.com/AndrewDonelson/ladl/internal/identity"
	"github.com/AndrewDonelson/ladl/internal/ledger"
	"github.com/AndrewDonelson/ladl/internal/verification"
)

func newVerifyCmd() *cobra.Command {
	var level int
	var group string
	var docPath string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Initiate or upgrade verification for the current user",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(level, group, docPath)
		},
	}

	cmd.Flags().IntVar(&level, "level", 1, "verification level: 1=self-attest, 2=document OCR, 3=VC")
	cmd.Flags().StringVar(&group, "group", "", "age group: a, b, c, or d (level 1 only)")
	cmd.Flags().StringVar(&docPath, "document", "", "path to document image (level 2 only)")
	return cmd
}

func runVerify(level int, group, docPath string) error {
	dir := identity.ConfigDir()

	// Generate keypair if not present.
	if !identity.Exists(dir) {
		fmt.Println("Generating new identity keypair...")
		pub, priv, err := identity.GenerateKeypair()
		if err != nil {
			return fmt.Errorf("generate keypair: %w", err)
		}
		if err := identity.Save(dir, pub, priv); err != nil {
			return fmt.Errorf("save keypair: %w", err)
		}
	}

	uid, _, priv, err := identity.Load(dir)
	if err != nil {
		return err
	}

	switch level {
	case 1:
		if group == "" {
			group = promptAgeGroup()
		}
		if err := format.ValidateGroup(group); err != nil {
			return ladlerrors.ErrInvalidAgeGroup
		}

		rec, err := verification.Level1(group, uid.UUID, priv)
		if err != nil {
			return err
		}

		led := ledger.NewMemLedger()
		defer led.Shutdown()

		if pErr := led.Publish(cmd_ctx(), uid.UUID, rec.Payload); pErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", pErr)
		}

		two := format.FormatTwoBytes(rec.Payload)
		fmt.Printf("UUID:   %s\nStatus: %s\n", uid.UUID, two)

	case 2:
		if docPath == "" {
			docPath = promptDocumentPath()
		}
		opts := &verification.L2Options{}
		rec, err := verification.Level2(docPath, uid.UUID, priv, opts)
		if err != nil {
			return err
		}

		led := ledger.NewMemLedger()
		defer led.Shutdown()

		if pErr := led.Publish(cmd_ctx(), uid.UUID, rec.Payload); pErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", pErr)
		}

		two := format.FormatTwoBytes(rec.Payload)
		fmt.Printf("UUID:   %s\nStatus: %s\n", uid.UUID, two)

	case 3:
		return fmt.Errorf("level 3 (Verifiable Credential) is not yet supported via CLI; use POST /verify")

	default:
		return fmt.Errorf("invalid level: %d (must be 1, 2, or 3)", level)
	}

	return nil
}

func promptAgeGroup() string {
	fmt.Println("Select your age group:")
	fmt.Println("  a) Under 13")
	fmt.Println("  b) Teen (13-17)")
	fmt.Println("  c) Adult (18-20)")
	fmt.Println("  d) Full Adult (21+)")
	fmt.Print("Choice: ")

	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(strings.ToLower(line))
}

func promptDocumentPath() string {
	fmt.Print("Document image path (JPEG or PNG): ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}
