package cmd

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

func newUUIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uuid",
		Short: "Print your LADL UUID",
		RunE:  runUUID,
	}
}

func runUUID(cmd *cobra.Command, args []string) error {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/uuid", port))
	if err != nil {
		return fmt.Errorf("connect to ladl daemon: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fmt.Println(strings.TrimSpace(string(body)))
	return nil
}
