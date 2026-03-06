package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AndrewDonelson/ladl/internal/config"
)

func TestDefault_ReturnsNonNil(t *testing.T) {
	cfg := config.Default()
	if cfg == nil {
		t.Fatal("Default() returned nil")
	}
}

func TestDefault_Values(t *testing.T) {
	cfg := config.Default()
	if cfg.Service.Port != 7743 {
		t.Errorf("Service.Port = %d, want 7743", cfg.Service.Port)
	}
	if cfg.Service.Socket != "/run/ladl/ladl.sock" {
		t.Errorf("Service.Socket = %q, want /run/ladl/ladl.sock", cfg.Service.Socket)
	}
	if cfg.Verification.OCR.TesseractPath != "/usr/bin/tesseract" {
		t.Errorf("TesseractPath = %q, want /usr/bin/tesseract", cfg.Verification.OCR.TesseractPath)
	}
	if cfg.Strata.L4.Port != 7744 {
		t.Errorf("L4.Port = %d, want 7744", cfg.Strata.L4.Port)
	}
	if cfg.Strata.L4.MaxPeers != 64 {
		t.Errorf("L4.MaxPeers = %d, want 64", cfg.Strata.L4.MaxPeers)
	}
	if cfg.Strata.L4.Quorum != 2 {
		t.Errorf("L4.Quorum = %d, want 2", cfg.Strata.L4.Quorum)
	}
	if cfg.Strata.L4.Mode != "peer" {
		t.Errorf("L4.Mode = %q, want peer", cfg.Strata.L4.Mode)
	}
	if cfg.Strata.L4.SyncInterval != 30*time.Second {
		t.Errorf("L4.SyncInterval = %v, want 30s", cfg.Strata.L4.SyncInterval)
	}
}

func TestLoad_EmptyPath(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load(\"\") error = %v", err)
	}
	if cfg == nil {
		t.Fatal("Load(\"\") returned nil config")
	}
	if cfg.Service.Port != 7743 {
		t.Errorf("Service.Port = %d, want 7743 (default)", cfg.Service.Port)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	cfg, err := config.Load("/totally/nonexistent/path/ladl-config.yaml")
	if err != nil {
		t.Fatalf("Load() with missing file error = %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() with missing file returned nil config")
	}
	// Should return defaults unchanged.
	if cfg.Service.Port != 7743 {
		t.Errorf("Service.Port = %d, want 7743 (default)", cfg.Service.Port)
	}
}

func TestLoad_ValidYAML_OverridesPort(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	yaml := "service:\n  port: 9000\n  socket: /tmp/ladl-test.sock\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Service.Port != 9000 {
		t.Errorf("Service.Port = %d, want 9000", cfg.Service.Port)
	}
	if cfg.Service.Socket != "/tmp/ladl-test.sock" {
		t.Errorf("Service.Socket = %q, want /tmp/ladl-test.sock", cfg.Service.Socket)
	}
	// Non-specified fields should retain defaults.
	if cfg.Strata.L4.Port != 7744 {
		t.Errorf("L4.Port = %d, want 7744 (default)", cfg.Strata.L4.Port)
	}
}

func TestLoad_ValidYAML_L4Config(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	yaml := `strata:
  l4:
    enabled: true
    mode: ledger
    port: 8000
    max_peers: 32
    quorum: 3
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Strata.L4.Enabled {
		t.Error("L4.Enabled should be true")
	}
	if cfg.Strata.L4.Mode != "ledger" {
		t.Errorf("L4.Mode = %q, want ledger", cfg.Strata.L4.Mode)
	}
	if cfg.Strata.L4.Port != 8000 {
		t.Errorf("L4.Port = %d, want 8000", cfg.Strata.L4.Port)
	}
	if cfg.Strata.L4.MaxPeers != 32 {
		t.Errorf("L4.MaxPeers = %d, want 32", cfg.Strata.L4.MaxPeers)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(cfgPath, []byte("service: [broken: yaml: {{{"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := config.Load(cfgPath)
	if err == nil {
		t.Error("Load() with invalid YAML should return error")
	}
}

func TestLoad_UnreadableFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("service:\n  port: 1234\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Make the file unreadable.
	os.Chmod(cfgPath, 0000)
	defer os.Chmod(cfgPath, 0644)

	_, err := config.Load(cfgPath)
	if err == nil {
		t.Error("Load() with unreadable file should return error")
	}
}

func TestDefault_IndependentInstances(t *testing.T) {
	// Two calls to Default() should return independent structs.
	cfg1 := config.Default()
	cfg2 := config.Default()
	cfg1.Service.Port = 9999
	if cfg2.Service.Port == 9999 {
		t.Error("Default() instances share state — should be independent")
	}
}
