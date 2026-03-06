// Copyright (c) 2026 Nlaak Studios (https://nlaak.com)
// Author: Andrew Donelson (https://www.linkedin.com/in/andrew-donelson/)
//
// daemon.go — runs the ladl service (peer mode) via HTTP

package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/AndrewDonelson/ladl/internal/api"
	"github.com/AndrewDonelson/ladl/internal/config"
	"github.com/AndrewDonelson/ladl/internal/identity"
	ladledger "github.com/AndrewDonelson/ladl/internal/ledger"

	stratal4 "github.com/AndrewDonelson/strata/l4"
)

func runDaemon(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if port != 7743 {
		cfg.Service.Port = port
	}
	if ledgerMode {
		cfg.Strata.L4.Mode = "ledger"
	}

	// Build L4 layer.
	l4cfg := stratal4.Config{
		Enabled:        cfg.Strata.L4.Enabled,
		Mode:           cfg.Strata.L4.Mode,
		Port:           cfg.Strata.L4.Port,
		SyncInterval:   cfg.Strata.L4.SyncInterval,
		MaxPeers:       cfg.Strata.L4.MaxPeers,
		Quorum:         cfg.Strata.L4.Quorum,
		BootstrapPeers: cfg.Strata.L4.BootstrapPeers,
		DNSSeed:        cfg.Strata.L4.DNSSeed,
	}

	var l4layer stratal4.L4Layer
	if cfg.Strata.L4.Enabled {
		l4layer, err = stratal4.New(l4cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ladl: L4 init failed (%v) — running without ledger sync\n", err)
		}
	}

	var led *ladledger.Ledger
	if l4layer != nil {
		signer, _ := stratal4.NewSigner()
		led = ladledger.New(l4layer, signer.PublicKeyHex())
	} else {
		led = ladledger.NewMemLedger()
	}
	defer led.Shutdown()

	localSvc := &api.LocalService{
		IdentityDir: identity.ConfigDir(),
		Ledger:      led,
		OCRPath:     cfg.Verification.OCR.TesseractPath,
	}

	ledgerSvc := &api.LedgerService{
		Ledger: led,
	}

	mux := api.NewCombinedMux(localSvc, ledgerSvc, ledgerMode)

	// Determine listen address.
	var listenAddr string
	if ledgerMode {
		listenAddr = fmt.Sprintf("0.0.0.0:%d", cfg.Service.Port)
	} else {
		listenAddr = fmt.Sprintf("127.0.0.1:%d", cfg.Service.Port)
	}

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	// Also listen on Unix socket.
	socketPath := cfg.Service.Socket
	if socketPath != "" {
		_ = os.Remove(socketPath)
		unixLn, listenErr := net.Listen("unix", socketPath)
		if listenErr == nil {
			go func() {
				_ = http.Serve(unixLn, mux)
			}()
		}
	}

	// Graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		fmt.Println("ladl: shutting down...")
		_ = srv.Shutdown(context.Background())
	}()

	fmt.Printf("ladl: listening on %s (ledger=%v)\n", listenAddr, ledgerMode)
	return srv.ListenAndServe()
}
