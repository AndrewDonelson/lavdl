// Copyright (c) 2026 Nlaak Studios (https://nlaak.com)
// Author: Andrew Donelson (https://www.linkedin.com/in/andrew-donelson/)
//
// config.go — LADL configuration loading and defaults from YAML or environment

// Package config provides configuration loading for ladl.
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure.
type Config struct {
	Service      ServiceConfig      `yaml:"service"`
	Verification VerificationConfig `yaml:"verification"`
	Strata       StrataConfig       `yaml:"strata"`
}

// ServiceConfig controls the HTTP server.
type ServiceConfig struct {
	Port   int    `yaml:"port"`
	Socket string `yaml:"socket"`
}

// VerificationConfig controls verification behaviour.
type VerificationConfig struct {
	OCR OCRConfig `yaml:"ocr"`
}

// OCRConfig specifies the Tesseract path.
type OCRConfig struct {
	TesseractPath string `yaml:"tesseract_path"`
}

// StrataConfig holds Strata L4 configuration.
type StrataConfig struct {
	L4 L4Config `yaml:"l4"`
}

// L4Config mirrors the Strata l4.Config fields we expose.
type L4Config struct {
	Enabled        bool          `yaml:"enabled"`
	Mode           string        `yaml:"mode"`
	Port           int           `yaml:"port"`
	SyncInterval   time.Duration `yaml:"sync_interval"`
	MaxPeers       int           `yaml:"max_peers"`
	Quorum         int           `yaml:"quorum"`
	BootstrapPeers []string      `yaml:"bootstrap_peers"`
	DNSSeed        string        `yaml:"dns_seed"`
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		Service: ServiceConfig{
			Port:   7743,
			Socket: "/run/ladl/ladl.sock",
		},
		Verification: VerificationConfig{
			OCR: OCRConfig{
				TesseractPath: "/usr/bin/tesseract",
			},
		},
		Strata: StrataConfig{
			L4: L4Config{
				Enabled:      false,
				Mode:         "peer",
				Port:         7744,
				SyncInterval: 30 * time.Second,
				MaxPeers:     64,
				Quorum:       2,
			},
		},
	}
}

// Load reads the YAML config file at path and merges with defaults.
// If path is empty or the file does not exist, only defaults are returned.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
