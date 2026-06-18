// Command mosey is the single entry point for the mosey terminal-
// sharing tool. Subcommands:
//
//	mosey launch  --secret=SECRET -- PROGRAM [ARGS...]
//	  Run PROGRAM under a mosey-reachable PTY. Prints listener
//	  endpoints to stderr.
//
//	mosey attach  --secret=SECRET ENDPOINT
//	  Connect to a mosey PTY and bridge it to the local terminal.
//
//	mosey control SUBCMD ENDPOINT [...]
//	  Admin operations against a running launch (list-clients,
//	  promote, kick, demote, set-mode). Uses the same auth flags
//	  as `attach`.
//
//	mosey cert    SUBCMD ...
//	  Workspace-master + cert minting (mint-master, mint-agent,
//	  revoke). Lives in this binary because every host that runs
//	  launch / attach already has it.
//
//	mosey session SUBCMD ...
//	  On-chain wallet-auth ops against the mosey-session program
//	  (register, transfer, bump-epoch, grant). Owner-signed Solana
//	  transactions; the off-chain `grant` is separate.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "launch":
		os.Exit(runLaunch(os.Args[2:], os.Stderr))
	case "attach":
		os.Exit(runAttach(os.Args[2:], os.Stderr))
	case "control":
		os.Exit(runControl(os.Args[2:], os.Stdout, os.Stderr))
	case "cert":
		os.Exit(runCert(os.Args[2:], os.Stdout, os.Stderr))
	case "grant":
		os.Exit(runGrant(os.Args[2:], os.Stdout, os.Stderr))
	case "session":
		os.Exit(runSession(os.Args[2:], os.Stdout, os.Stderr))
	case "wallet":
		os.Exit(runWallet(os.Args[2:], os.Stdout, os.Stderr))
	case "-h", "--help", "help":
		usage(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "mosey: unknown subcommand %q\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, `mosey — peer-to-peer terminal sharing

Usage:
  mosey launch  [flags] -- PROGRAM [ARGS...]   run PROGRAM under a shareable PTY
  mosey attach  [flags] ENDPOINT                connect to a running launch
  mosey control SUBCMD [flags] ENDPOINT ...     admin ops (list-clients, promote, kick, demote, set-mode)
  mosey cert    SUBCMD [flags] ...              workspace master + cert minting
  mosey grant   [flags]                         sign an off-chain wallet-auth delegation
  mosey session SUBCMD [flags]                   on-chain session ops (register, transfer, bump-epoch, grant)
  mosey wallet  SUBCMD [flags]                   browser-wallet ops (sign: approve a grant via Phantom)

Run "mosey SUBCMD -h" for subcommand-specific flags.`)
}
