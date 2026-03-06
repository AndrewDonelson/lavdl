// Copyright (c) 2026 Nlaak Studios (https://nlaak.com)
// Author: Andrew Donelson (https://www.linkedin.com/in/andrew-donelson/)
//
// main.go — ladl entry point — Linux Age Distributed Ledger daemon

// ladl — Linux Age Distributed Ledger daemon.
//
// Usage:
//
//	ladl [--port 7743] [--config /etc/ladl/config.yaml]           # peer mode
//	ladl --ledger [--port 7743] [--config /etc/ladl/config.yaml]  # ledger mode
//	ladl <command> [flags]
//
// See `ladl --help` for more information.
package main

import "github.com/AndrewDonelson/ladl/cmd"

func main() {
	cmd.Execute()
}
