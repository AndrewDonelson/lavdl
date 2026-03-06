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
