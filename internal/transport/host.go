// Package transport sets up libp2p hosts for ship peers.
//
// The default configuration enables hole-punching, NAT services, and
// auto-relay against the IPFS public bootstrap set, so a fresh
// `vterm` running on a residential laptop is dialable from anywhere
// without manual port-forwarding. Pass NewOptions.Bootstrap to point
// at a private network instead.
package transport

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/multiformats/go-multiaddr"

	"github.com/firefly-engineering/ship/internal/auth"
)

// Options configures a [Host]. Zero values pick sensible defaults
// suitable for the v1 vterm / attach workflow.
type Options struct {
	// Auth is the authenticator whose [auth.Authenticator.HostOptions]
	// will be folded into the libp2p host construction. Required.
	Auth auth.Authenticator

	// Identity is the libp2p private key for this host. Zero means
	// "generate a fresh Ed25519 key" — fine for ephemeral vterm /
	// attach processes. Persist this when you want a stable peer id
	// across restarts (future: the cert model needs this).
	Identity crypto.PrivKey

	// ListenAddrs is the list of multiaddrs to bind. Zero means
	// "listen on /ip4/0.0.0.0/tcp/0 and /ip4/0.0.0.0/udp/0/quic-v1"
	// — both random ports, both protocol families, all interfaces.
	ListenAddrs []multiaddr.Multiaddr

	// Bootstrap is the list of public multiaddrs to use for NAT
	// hole-punching and relay discovery. Zero means "use the IPFS
	// public bootstrap set" via [DefaultBootstrap]. Pass an empty
	// (non-nil) slice for "no bootstrap" — useful for LAN-only
	// testing.
	Bootstrap []peer.AddrInfo
}

// New constructs a libp2p host wired with the supplied authenticator
// + reasonable defaults (Noise security, default transports incl.
// QUIC + TCP, NAT services, hole-punching, auto-relay).
//
// The returned host's lifetime is the caller's responsibility — call
// [host.Host.Close] when done. The host immediately starts listening
// on opts.ListenAddrs.
func New(ctx context.Context, opts Options) (host.Host, error) {
	if opts.Auth == nil {
		return nil, errors.New("ship/transport: Options.Auth is required")
	}

	identity := opts.Identity
	if identity == nil {
		priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ship/transport: generate identity: %w", err)
		}
		identity = priv
	}

	listenStrings := defaultListenStrings
	if len(opts.ListenAddrs) > 0 {
		listenStrings = make([]string, 0, len(opts.ListenAddrs))
		for _, a := range opts.ListenAddrs {
			listenStrings = append(listenStrings, a.String())
		}
	}

	// Transport selection is the Authenticator's call — PSK is
	// TCP-only, cert-based (future) will keep DefaultTransports +
	// QUIC for proper NAT traversal. We bake the rest of the
	// stack (security, hole-punching, NAT service, relay) here.
	libp2pOpts := []libp2p.Option{
		libp2p.Identity(identity),
		libp2p.ListenAddrStrings(listenStrings...),
		libp2p.Security(noise.ID, noise.New),
		libp2p.EnableHolePunching(),
		libp2p.EnableNATService(),
		libp2p.EnableRelay(),
	}
	libp2pOpts = append(libp2pOpts, opts.Auth.HostOptions()...)

	bootstrap := opts.Bootstrap
	if bootstrap == nil {
		var err error
		bootstrap, err = DefaultBootstrap()
		if err != nil {
			return nil, err
		}
	}
	if len(bootstrap) > 0 {
		relayInfos := make([]peer.AddrInfo, 0, len(bootstrap))
		relayInfos = append(relayInfos, bootstrap...)
		libp2pOpts = append(libp2pOpts, libp2p.EnableAutoRelayWithStaticRelays(relayInfos))
	}

	h, err := libp2p.New(libp2pOpts...)
	if err != nil {
		return nil, fmt.Errorf("ship/transport: new libp2p host: %w", err)
	}

	if len(bootstrap) > 0 {
		// Spin up a Kademlia DHT client + connect to bootstrap so
		// peer-id lookups + relay discovery work. The DHT runs in
		// the background and is closed when the host closes.
		kdht, err := dht.New(ctx, h, dht.Mode(dht.ModeAuto), dht.BootstrapPeers(bootstrap...))
		if err != nil {
			_ = h.Close()
			return nil, fmt.Errorf("ship/transport: new dht: %w", err)
		}
		if err := kdht.Bootstrap(ctx); err != nil {
			_ = h.Close()
			return nil, fmt.Errorf("ship/transport: bootstrap dht: %w", err)
		}
		// Best-effort: dial each bootstrap peer so we surface NAT
		// info quickly. Errors here are non-fatal — peers may be
		// reachable later.
		for _, info := range bootstrap {
			_ = h.Connect(ctx, info)
		}
	}

	return h, nil
}

// defaultListenStrings is the listen-addr fallback when
// Options.ListenAddrs is empty. TCP only — the v1 PSK auth doesn't
// support QUIC. Once a cert-based authenticator lands we'll have it
// override this to include QUIC.
var defaultListenStrings = []string{
	"/ip4/0.0.0.0/tcp/0",
}
