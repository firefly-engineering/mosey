// runCert implements `mosey cert` — workspace-master + cert
// minting. See main.go for the binary-level usage.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/proto"

	"github.com/firefly-engineering/mosey/internal/cert"
)

func runCert(args []string, stdout, stderr *os.File) int {
	if len(args) < 1 {
		certUsage(stderr)
		return 2
	}
	switch args[0] {
	case "mint-master":
		return cmdMintMaster(args[1:], stdout, stderr)
	case "mint-agent":
		return cmdMintAgent(args[1:], stdout, stderr)
	case "revoke":
		return cmdRevoke(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		certUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "mosey cert: unknown subcommand %q\n", args[0])
		certUsage(stderr)
		return 2
	}
}

func certUsage(w *os.File) {
	fmt.Fprintln(w, `mosey cert: workspace-master + cert minting

Subcommands:
  mint-master --out=DIR
  mint-agent  --master-key=PATH --workspace=ID --agent-id=ID --label=NAME --caps=CAPS --valid-for=DURATION --out=DIR
  revoke      --revocation-file=PATH --serial=SERIAL`)
}

// cmdMintMaster generates a fresh master key + mnemonic.
func cmdMintMaster(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("mint-master", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outDir := fs.String("out", "", "output directory for master.pub + master.key (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *outDir == "" {
		fmt.Fprintln(stderr, "mint-master: --out is required")
		return 2
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		fmt.Fprintln(stderr, "mint-master:", err)
		return 1
	}

	mnemonic, priv, err := cert.NewMasterMnemonic()
	if err != nil {
		fmt.Fprintln(stderr, "mint-master:", err)
		return 1
	}
	pub := cert.MasterPublicKey(priv)

	if err := writeKeyMaterial(filepath.Join(*outDir, "master.key"), priv); err != nil {
		fmt.Fprintln(stderr, "mint-master:", err)
		return 1
	}
	if err := os.WriteFile(filepath.Join(*outDir, "master.pub"), []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		fmt.Fprintln(stderr, "mint-master: write pub:", err)
		return 1
	}

	fmt.Fprintln(stdout, "Master key generated.")
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "RECORD THIS MNEMONIC SOMEWHERE DURABLE AND SECRET.")
	fmt.Fprintln(stdout, "Loss = no more cert minting / revocation for this workspace.")
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, mnemonic)
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "Files written:")
	fmt.Fprintf(stdout, "  %s  — secret; same content as the mnemonic above\n", filepath.Join(*outDir, "master.key"))
	fmt.Fprintf(stdout, "  %s  — public; distribute alongside every vterm\n", filepath.Join(*outDir, "master.pub"))
	return 0
}

// cmdMintAgent mints a per-agent cert + keypair signed by the
// master.
func cmdMintAgent(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("mint-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	masterKeyPath := fs.String("master-key", "", "path to master.key (required)")
	workspace := fs.String("workspace", "", "workspace id (required)")
	agentID := fs.String("agent-id", "", "agent id; default = freshly-generated ULID")
	label := fs.String("label", "", "human-readable label for logs / UI (required)")
	capsRaw := fs.String("caps", "owner", "comma-separated caps: owner, write, resize")
	validFor := fs.Duration("valid-for", 90*24*time.Hour, "cert validity window measured from now")
	outDir := fs.String("out", "", "output directory for <label>.cert + <label>.key (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *masterKeyPath == "" || *workspace == "" || *label == "" || *outDir == "" {
		fmt.Fprintln(stderr, "mint-agent: --master-key, --workspace, --label, --out are required")
		return 2
	}

	masterPriv, err := loadKeyMaterial(*masterKeyPath)
	if err != nil {
		fmt.Fprintln(stderr, "mint-agent: load master:", err)
		return 1
	}
	caps, err := parseCaps(*capsRaw)
	if err != nil {
		fmt.Fprintln(stderr, "mint-agent:", err)
		return 2
	}
	id := *agentID
	if id == "" {
		id = ulid.Make().String()
	}

	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(stderr, "mint-agent: peer key:", err)
		return 1
	}
	now := time.Now()
	claim := cert.Claim{
		AgentID:     id,
		PeerPubKey:  peerPub,
		Label:       *label,
		CapsBits:    caps,
		NotBefore:   now.Add(-time.Minute), // small slack for clock skew
		NotAfter:    now.Add(*validFor),
		Serial:      ulid.Make().String(),
		WorkspaceID: *workspace,
	}
	c, err := cert.Sign(masterPriv, claim)
	if err != nil {
		fmt.Fprintln(stderr, "mint-agent: sign:", err)
		return 1
	}

	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		fmt.Fprintln(stderr, "mint-agent:", err)
		return 1
	}
	certPath := filepath.Join(*outDir, *label+".cert")
	keyPath := filepath.Join(*outDir, *label+".key")
	certBytes, err := proto.Marshal(c)
	if err != nil {
		fmt.Fprintln(stderr, "mint-agent: marshal cert:", err)
		return 1
	}
	if err := os.WriteFile(certPath, certBytes, 0o644); err != nil {
		fmt.Fprintln(stderr, "mint-agent: write cert:", err)
		return 1
	}
	if err := writeKeyMaterial(keyPath, peerPriv); err != nil {
		fmt.Fprintln(stderr, "mint-agent:", err)
		return 1
	}

	fmt.Fprintln(stdout, "Agent enrolled.")
	fmt.Fprintf(stdout, "  agent_id: %s\n", id)
	fmt.Fprintf(stdout, "  serial:   %s\n", claim.Serial)
	fmt.Fprintf(stdout, "  expires:  %s\n", claim.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(stdout, "  files:    %s, %s\n", certPath, keyPath)
	return 0
}

func cmdRevoke(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	revPath := fs.String("revocation-file", "", "path to the revocation list (required)")
	serial := fs.String("serial", "", "cert serial to revoke (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *revPath == "" || *serial == "" {
		fmt.Fprintln(stderr, "revoke: --revocation-file and --serial are required")
		return 2
	}
	if err := cert.AppendRevocation(*revPath, *serial); err != nil {
		fmt.Fprintln(stderr, "revoke:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Revoked %s (file: %s)\n", *serial, *revPath)
	return 0
}

// writeKeyMaterial writes priv to path as a hex string + newline,
// mode 0600. The hex form keeps key files trivially copy/paste-able
// without binary escaping.
func writeKeyMaterial(path string, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("key length %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	return os.WriteFile(path, []byte(hex.EncodeToString(priv)+"\n"), 0o600)
}

// loadKeyMaterial reads a hex-encoded Ed25519 private key from path.
func loadKeyMaterial(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("decoded key length %d, want %d", len(decoded), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}

func parseCaps(s string) (uint32, error) {
	if s == "" {
		return 0, errors.New("empty caps")
	}
	var bits uint32
	for _, tok := range strings.Split(s, ",") {
		switch strings.TrimSpace(tok) {
		case "owner":
			bits |= cert.CapsBitOwner
		case "write":
			bits |= cert.CapsBitWrite
		case "resize":
			bits |= cert.CapsBitResize
		default:
			return 0, fmt.Errorf("unknown cap %q (have: owner, write, resize)", tok)
		}
	}
	return bits, nil
}
