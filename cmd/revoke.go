// Copyright (c) 2026 Nlaak Studios (https://nlaak.com)
// Author: Andrew Donelson (https://www.linkedin.com/in/andrew-donelson/)
//
// revoke.go — `ladl revoke` command — revokes the local identity on the ledger

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"
)

func newRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke",
		Short: "Revoke your LADL identity record",
		RunE:  runRevoke,
	}
}

func runRevoke(cmd *cobra.Command, args []string) error {
	fmt.Println("This will permanently revoke your LADL identity. Are you sure? [y/N]: ")
	var answer string
	fmt.Scanln(&answer)
	if answer != "y" && answer != "Y" {
		fmt.Println("Revocation cancelled.")
		return nil
	}

	body, _ := json.Marshal(map[string]bool{"confirm": true})
	resp, err := http.Post(
		fmt.Sprintf("http://127.0.0.1:%d/revoke", port),
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return fmt.Errorf("connect to ladl daemon: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoke failed (%d): %s", resp.StatusCode, respBody)
	}

	fmt.Println("Identity successfully revoked.")
	return nil
}
