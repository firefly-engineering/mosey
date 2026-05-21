package transport

import (
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// ipfsBootstrapAddrs is the IPFS public bootstrap set as of 2026.
// Same list go-ipfs ships with by default. These nodes provide DHT
// bootstrap, circuit relay v2, and DCUtR coordination so ship peers
// behind NAT can find each other and hole-punch direct connections.
//
// Lift these into a config field once anyone wants to point at a
// private network — for v1 the defaults are baked.
var ipfsBootstrapAddrs = []string{
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoCPnTcWj4QcMG5p5wTUNVjqEPgEoB7eU1tFqMc",
	"/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
	"/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
	"/ip4/104.131.131.82/udp/4001/quic-v1/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
}

// DefaultBootstrap parses [ipfsBootstrapAddrs] into [peer.AddrInfo]
// slice. Returns an error only when a hard-coded address fails to
// parse — that's a programming bug, not a runtime fault.
func DefaultBootstrap() ([]peer.AddrInfo, error) {
	out := make([]peer.AddrInfo, 0, len(ipfsBootstrapAddrs))
	for _, s := range ipfsBootstrapAddrs {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			return nil, fmt.Errorf("ship/transport: bootstrap addr %q: %w", s, err)
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			return nil, fmt.Errorf("ship/transport: bootstrap addr %q: %w", s, err)
		}
		out = append(out, *info)
	}
	return out, nil
}
