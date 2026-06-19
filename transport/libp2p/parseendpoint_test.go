package libp2p

import (
	"crypto/rand"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// TestParseEndpoint_BarePeerID covers the dial form the web gateway
// uses: "/p2p/<peer-id>" with no transport addrs. parseEndpoint must
// yield the id with an empty address set, so Connect resolves it via
// the DHT (routedhost). The "libp2p:" scheme prefix is also accepted.
func TestParseEndpoint_BarePeerID(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("id from key: %v", err)
	}

	for _, ep := range []string{"/p2p/" + id.String(), Scheme + ":/p2p/" + id.String()} {
		info, err := parseEndpoint(ep)
		if err != nil {
			t.Fatalf("parseEndpoint(%q): %v", ep, err)
		}
		if info.ID != id {
			t.Errorf("parseEndpoint(%q) id = %s, want %s", ep, info.ID, id)
		}
		if len(info.Addrs) != 0 {
			t.Errorf("parseEndpoint(%q) addrs = %v, want none (bare id)", ep, info.Addrs)
		}
	}
}

// TestParseEndpoint_FullMultiaddr confirms a full multiaddr still
// carries its dialable address (the no-DHT path).
func TestParseEndpoint_FullMultiaddr(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("id from key: %v", err)
	}

	ep := "/ip4/192.0.2.1/tcp/4001/p2p/" + id.String()
	info, err := parseEndpoint(ep)
	if err != nil {
		t.Fatalf("parseEndpoint(%q): %v", ep, err)
	}
	if info.ID != id {
		t.Errorf("id = %s, want %s", info.ID, id)
	}
	if len(info.Addrs) != 1 {
		t.Fatalf("addrs = %v, want exactly one", info.Addrs)
	}
}
