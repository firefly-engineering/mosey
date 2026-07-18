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
	routedhost "github.com/libp2p/go-libp2p/p2p/host/routed"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/multiformats/go-multiaddr"

	"github.com/firefly-engineering/mosey/transport"
)

// Scheme is the URI scheme this backend claims under a
// [transport.Multi] aggregator.
const Scheme = "libp2p"

// Options configures a [Backend].
type Options struct {
	// Host, when non-nil, is used as-is and the backend will not
	// construct or close one of its own. Use this when the caller
	// already runs a libp2p host (so identity, listeners, and any
	// extra protocols stay on a single peer id) — for example a
	// daemon that wants /mosey/pty/ to share a connection with its
	// own RPC. Setting Host together with any of Identity,
	// ListenAddrs, or Bootstrap is a configuration error: those
	// fields describe construction of a host the backend doesn't
	// build.
	Host host.Host

	// Identity is the libp2p private key. Zero means "generate a
	// fresh Ed25519 key" — fine for ephemeral processes; persist
	// when you need a stable peer id across restarts (the cert
	// authenticator's identity will live in this key). Ignored when
	// Host is set.
	Identity crypto.PrivKey

	// ListenAddrs are the multiaddrs to bind. Zero means default
	// (TCP + QUIC on all interfaces, random ports). Pass an empty
	// (non-nil) slice for "no listener" — useful for client-only
	// configurations. Ignored when Host is set.
	ListenAddrs []multiaddr.Multiaddr

	// Bootstrap is the set of public peers to use for DHT
	// bootstrap, hole-punching, and AutoRelay discovery. Zero
	// means "use [DefaultBootstrap] (IPFS public)". Empty
	// (non-nil) slice means "no bootstrap". Ignored when Host is
	// set.
	Bootstrap []peer.AddrInfo
}

// New constructs a libp2p [transport.Transport] backend. The
// returned backend immediately starts listening; call Close to
// release listener + outstanding streams.
//
// When opts.Host is non-nil the backend uses the supplied host
// directly; its construction options (Identity, ListenAddrs,
// Bootstrap) must be zero and the caller retains ownership —
// Close becomes a no-op on the host so the caller can keep using
// it for other protocols.
func New(ctx context.Context, opts Options) (*Backend, error) {
	if opts.Host != nil {
		if opts.Identity != nil || opts.ListenAddrs != nil || opts.Bootstrap != nil {
			return nil, errors.New("libp2p: Options.Host is exclusive with Identity/ListenAddrs/Bootstrap (configure those on the caller-supplied host instead)")
		}
		return &Backend{host: opts.Host, ownsHost: false}, nil
	}

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
		// Wrap the host so Dial can reach a bare /p2p/<peer-id> with no
		// transport addrs: Connect falls back to dht.FindPeer to resolve
		// current addresses. This is what lets the web gateway dial a
		// session_key (== peer id) instead of a full multiaddr. Hosts in
		// the public DHT (incl. AutoRelay'd ones) resolve; otherwise pass
		// a full multiaddr.
		h = routedhost.Wrap(h, kdht)
	}

	return &Backend{host: h, ownsHost: true}, nil
}

// Backend implements [transport.Transport] over libp2p.
type Backend struct {
	host host.Host
	// ownsHost is true when New constructed the host; false when
	// the caller supplied one via Options.Host. Gates whether
	// Close shuts the host down.
	ownsHost bool
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
// Both resolve via [peer.AddrInfoFromP2pAddr]. A full multiaddr
// carries its own dialable addrs; a bare "/p2p/<peer-id>" carries
// only the id, and Connect resolves current addrs via the DHT when
// the host was built with bootstrap peers (see New's routedhost.Wrap).
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

// Close implements [transport.Transport]. When the host was
// caller-supplied (Options.Host), Close leaves it alone so the
// caller can keep using it for other protocols.
func (b *Backend) Close() error {
	if !b.ownsHost {
		return nil
	}
	return b.host.Close()
}

// streamAdapter wraps a libp2p [network.Stream] to satisfy
// [transport.Stream]. CloseWrite is native libp2p; the remote peer's
// libp2p multihash is both the log tag and the cryptographically
// attested correlation handle.
type streamAdapter struct{ network.Stream }

func (s *streamAdapter) CloseWrite() error { return s.Stream.CloseWrite() }
func (s *streamAdapter) RemoteID() string  { return s.Stream.Conn().RemotePeer().String() }

// CorrelationID returns the remote peer id — cryptographically
// attested, so it is a stable, unforgeable correlation handle.
func (s *streamAdapter) CorrelationID() string { return s.Stream.Conn().RemotePeer().String() }

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
