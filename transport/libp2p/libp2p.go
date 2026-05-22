// Package libp2p is the libp2p backend for mosey's
// [transport.Transport]. It speaks the "libp2p://..." (or bare
// "/ip4/..." multiaddr) scheme. Identity = a fresh Ed25519 key per
// Backend (Options.Identity to persist); listeners default to
// TCP+QUIC on all interfaces; NAT hole-punching + AutoRelay default
// on, with IPFS public bootstrap providing the relay swarm.
//
// Authentication lives one level up (mosey's application-layer
// handshake on [api.ProtoAuth]) — this backend is plain libp2p
// with DefaultTransports, so QUIC is in play and DCUtR
// hole-punching actually works across NATs.
package libp2p

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	libp2pgo "github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/multiformats/go-multiaddr"

	"github.com/firefly-engineering/mosey/transport"
)

// Scheme is the URI scheme this backend claims under a
// [transport.Multi] aggregator.
const Scheme = "libp2p"

// Options configures a [Backend].
type Options struct {
	// Identity is the libp2p private key. Zero means "generate a
	// fresh Ed25519 key" — fine for ephemeral processes; persist
	// when you need a stable peer id across restarts (the cert
	// authenticator's identity will live in this key).
	Identity crypto.PrivKey

	// ListenAddrs are the multiaddrs to bind. Zero means default
	// (TCP + QUIC on all interfaces, random ports). Pass an empty
	// (non-nil) slice for "no listener" — useful for client-only
	// configurations.
	ListenAddrs []multiaddr.Multiaddr

	// Bootstrap is the set of public peers to use for DHT
	// bootstrap, hole-punching, and AutoRelay discovery. Zero
	// means "use [DefaultBootstrap] (IPFS public)". Empty
	// (non-nil) slice means "no bootstrap".
	Bootstrap []peer.AddrInfo
}

// New constructs a libp2p [transport.Transport] backend. The
// returned backend immediately starts listening; call Close to
// release listener + outstanding streams.
func New(ctx context.Context, opts Options) (*Backend, error) {
	identity := opts.Identity
	if identity == nil {
		priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("libp2p: generate identity: %w", err)
		}
		identity = priv
	}

	listenStrings := defaultListenStrings
	if len(opts.ListenAddrs) > 0 {
		listenStrings = make([]string, 0, len(opts.ListenAddrs))
		for _, a := range opts.ListenAddrs {
			listenStrings = append(listenStrings, a.String())
		}
	} else if opts.ListenAddrs != nil {
		listenStrings = nil
	}

	libp2pOpts := []libp2pgo.Option{
		libp2pgo.Identity(identity),
		libp2pgo.Security(noise.ID, noise.New),
		libp2pgo.DefaultTransports,
		libp2pgo.EnableHolePunching(),
		libp2pgo.EnableNATService(),
		libp2pgo.EnableRelay(),
	}
	if len(listenStrings) > 0 {
		libp2pOpts = append(libp2pOpts, libp2pgo.ListenAddrStrings(listenStrings...))
	} else {
		libp2pOpts = append(libp2pOpts, libp2pgo.NoListenAddrs)
	}

	bootstrap := opts.Bootstrap
	if bootstrap == nil {
		var err error
		bootstrap, err = DefaultBootstrap()
		if err != nil {
			return nil, err
		}
	}
	if len(bootstrap) > 0 {
		relayInfos := make([]peer.AddrInfo, len(bootstrap))
		copy(relayInfos, bootstrap)
		libp2pOpts = append(libp2pOpts, libp2pgo.EnableAutoRelayWithStaticRelays(relayInfos))
	}

	h, err := libp2pgo.New(libp2pOpts...)
	if err != nil {
		return nil, fmt.Errorf("libp2p: new host: %w", err)
	}

	if len(bootstrap) > 0 {
		kdht, err := dht.New(ctx, h, dht.Mode(dht.ModeAuto), dht.BootstrapPeers(bootstrap...))
		if err != nil {
			_ = h.Close()
			return nil, fmt.Errorf("libp2p: new dht: %w", err)
		}
		if err := kdht.Bootstrap(ctx); err != nil {
			_ = h.Close()
			return nil, fmt.Errorf("libp2p: bootstrap dht: %w", err)
		}
		for _, info := range bootstrap {
			_ = h.Connect(ctx, info)
		}
	}

	return &Backend{host: h}, nil
}

// Backend implements [transport.Transport] over libp2p.
type Backend struct {
	host host.Host
}

// Host returns the underlying libp2p host. Escape hatch for
// integration tests that want to drive libp2p operations directly;
// production code should stay inside the [transport.Transport]
// surface.
func (b *Backend) Host() host.Host { return b.host }

// Schemes implements [transport.Transport].
func (b *Backend) Schemes() []string { return []string{Scheme} }

// Endpoints implements [transport.Transport]. Returns each listen
// address, suffixed with /p2p/<peer-id>, prefixed with "libp2p:"
// so the multi-transport's scheme dispatch routes correctly.
func (b *Backend) Endpoints() []string {
	addrs := b.host.Addrs()
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, fmt.Sprintf("libp2p:%s/p2p/%s", a, b.host.ID()))
	}
	return out
}

// Handle implements [transport.Transport]. Wraps the supplied
// [transport.Handler] in libp2p's stream-handler shape.
func (b *Backend) Handle(proto string, h transport.Handler) {
	b.host.SetStreamHandler(protocol.ID(proto), func(s network.Stream) {
		h(&streamAdapter{Stream: s})
	})
}

// Unhandle implements [transport.Transport].
func (b *Backend) Unhandle(proto string) {
	b.host.RemoveStreamHandler(protocol.ID(proto))
}

// Dial implements [transport.Transport]. Accepts two endpoint
// forms:
//   - bare multiaddr starting with `/`: "/ip4/.../p2p/..."
//   - prefixed: "libp2p:/ip4/.../p2p/..."
//
// Both resolve via [peer.AddrInfoFromP2pAddr]. The connection's
// peer id and dialable addrs are extracted from the multiaddr —
// no DHT lookup at this layer.
func (b *Backend) Dial(ctx context.Context, endpoint, proto string) (transport.Stream, error) {
	info, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, fmt.Errorf("libp2p: dial: %w", err)
	}
	if err := b.host.Connect(ctx, info); err != nil {
		return nil, fmt.Errorf("libp2p: connect %s: %w", info.ID, err)
	}
	s, err := b.host.NewStream(ctx, info.ID, protocol.ID(proto))
	if err != nil {
		return nil, fmt.Errorf("libp2p: open %s: %w", proto, err)
	}
	return &streamAdapter{Stream: s}, nil
}

// Close implements [transport.Transport].
func (b *Backend) Close() error { return b.host.Close() }

// streamAdapter wraps a libp2p [network.Stream] to satisfy
// [transport.Stream]. CloseWrite is native libp2p; RemoteID
// returns the remote peer's libp2p multihash for log tagging.
type streamAdapter struct{ network.Stream }

func (s *streamAdapter) CloseWrite() error { return s.Stream.CloseWrite() }
func (s *streamAdapter) RemoteID() string  { return s.Stream.Conn().RemotePeer().String() }

// parseEndpoint accepts a "libp2p:..." URL or a bare multiaddr and
// returns the dial target.
func parseEndpoint(endpoint string) (peer.AddrInfo, error) {
	if endpoint == "" {
		return peer.AddrInfo{}, errors.New("empty endpoint")
	}
	maStr := endpoint
	if len(endpoint) > len(Scheme)+1 && endpoint[:len(Scheme)+1] == Scheme+":" {
		maStr = endpoint[len(Scheme)+1:]
	}
	ma, err := multiaddr.NewMultiaddr(maStr)
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("parse multiaddr %q: %w", maStr, err)
	}
	info, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("multiaddr needs /p2p/<peer-id> suffix: %w", err)
	}
	return *info, nil
}

// defaultListenStrings is the listen-addr fallback. Both TCP and
// QUIC, random ports, all interfaces — auth lives at the app layer,
// so neither transport needs pnet's TCP-only constraint.
var defaultListenStrings = []string{
	"/ip4/0.0.0.0/tcp/0",
	"/ip4/0.0.0.0/udp/0/quic-v1",
}
