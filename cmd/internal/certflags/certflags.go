// Package certflags wires the workspace-cert authenticator into a
// CLI. Shared by `mosey launch`, `mosey attach`, and `mosey control`
// so the user-facing flag surface is identical on every side.
package certflags

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/firefly-engineering/mosey/internal/api"
	"github.com/firefly-engineering/mosey/internal/auth"
	"github.com/firefly-engineering/mosey/internal/cert"
)

// Flags is the bundle of cert-auth-related CLI inputs. Bind to a
// flag set via Register; resolve to an Authenticator (or
// nil-no-cert) via Build.
type Flags struct {
	CertPath       string
	KeyPath        string
	MasterPubPath  string
	WorkspaceID    string
	RevocationPath string
}

// Register attaches the flags to fs. Pass the same Flags pointer
// to Build after fs.Parse.
func (f *Flags) Register(fs *flag.FlagSet) {
	fs.StringVar(&f.CertPath, "cert", "", "path to this peer's workspace cert (mints via `mosey cert mint-agent`)")
	fs.StringVar(&f.KeyPath, "key", "", "path to the Ed25519 private key matching --cert")
	fs.StringVar(&f.MasterPubPath, "master-pub", "", "path to the workspace master public key (hex). Required when --cert is set.")
	fs.StringVar(&f.WorkspaceID, "workspace", "", "workspace id this peer belongs to. Required when --cert is set.")
	fs.StringVar(&f.RevocationPath, "revocation-file", "", "optional revocation list path; cert serials listed here are rejected on handshake")
}

// Configured reports whether enough flags are set for a cert
// authenticator to be constructed. The CLI uses this to pick
// between PSK and cert auth.
func (f *Flags) Configured() bool {
	return f.CertPath != "" || f.KeyPath != "" || f.MasterPubPath != ""
}

// Build resolves the flags into a configured [*auth.CertAuth].
// Returns an error if any of the required pieces are missing or
// malformed. Caller is expected to bail out — there's no useful
// partial-success path.
func (f *Flags) Build() (*auth.CertAuth, error) {
	if !f.Configured() {
		return nil, errors.New("certflags: cert auth not configured (no --cert / --key / --master-pub)")
	}
	if f.CertPath == "" || f.KeyPath == "" || f.MasterPubPath == "" || f.WorkspaceID == "" {
		return nil, errors.New("certflags: --cert, --key, --master-pub, --workspace are all required when using cert auth")
	}

	certBytes, err := os.ReadFile(f.CertPath)
	if err != nil {
		return nil, fmt.Errorf("certflags: read --cert: %w", err)
	}
	var c api.Cert
	if err := proto.Unmarshal(certBytes, &c); err != nil {
		return nil, fmt.Errorf("certflags: parse --cert: %w", err)
	}

	priv, err := loadPrivateKey(f.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("certflags: --key: %w", err)
	}
	pub, err := loadPublicKey(f.MasterPubPath)
	if err != nil {
		return nil, fmt.Errorf("certflags: --master-pub: %w", err)
	}

	revoked := map[string]struct{}{}
	if f.RevocationPath != "" {
		revoked, err = cert.LoadRevocationFile(f.RevocationPath)
		if err != nil {
			return nil, fmt.Errorf("certflags: --revocation-file: %w", err)
		}
	}

	return auth.NewCertAuth(auth.CertAuthOptions{
		LocalCert:   &c,
		LocalPriv:   priv,
		MasterPub:   pub,
		WorkspaceID: f.WorkspaceID,
		Revoked:     revoked,
	})
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(dec) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("decoded length %d, want %d", len(dec), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(dec), nil
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(dec) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("decoded length %d, want %d", len(dec), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(dec), nil
}
