package websocket_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/transport"
	wsbackend "github.com/firefly-engineering/mosey/transport/websocket"
)

const testProto = "/mosey/test/1.0.0"

// TestBackend_DialEchoesBytes is the round-trip smoke test: the
// server handler echoes whatever it reads; the client writes a
// payload then closes; the test asserts the echo arrived.
func TestBackend_DialEchoesBytes(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server, endpoint := newServer(t, ctx, nil)
	server.Handle(testProto, func(s transport.Stream) {
		defer s.Close()
		// Single-frame echo. The client will end the stream after
		// receiving this — no need to loop.
		buf := make([]byte, 4096)
		n, err := s.Read(buf)
		if err != nil && err != io.EOF {
			return
		}
		_, _ = s.Write(buf[:n])
	})

	client, err := wsbackend.New(ctx, wsbackend.Options{})
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	defer func() { _ = client.Close() }()

	stream, err := client.Dial(ctx, endpoint, testProto)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer stream.Close()

	const sent = "hello mosey websocket"
	if _, err := stream.Write([]byte(sent)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, len(sent))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != sent {
		t.Errorf("echo = %q, want %q", got, sent)
	}
}

// TestBackend_RemoteIDStableAcrossDials proves the server-side
// RemoteID is the same across two streams from the same backend.
// This is the property [auth.Wrap] depends on to correlate the
// auth handshake with the subsequent application stream.
func TestBackend_RemoteIDStableAcrossDials(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server, endpoint := newServer(t, ctx, nil)

	var (
		seen   []string
		seenMu sync.Mutex
		ready  = make(chan struct{}, 2)
	)
	server.Handle(testProto, func(s transport.Stream) {
		seenMu.Lock()
		seen = append(seen, s.RemoteID())
		seenMu.Unlock()
		// Sync byte so the client can be sure the handler ran
		// before closing — closing too eagerly races the WS
		// handshake completion.
		_, _ = s.Write([]byte{0x01})
		ready <- struct{}{}
		_, _ = io.Copy(io.Discard, s)
		_ = s.Close()
	})

	client, err := wsbackend.New(ctx, wsbackend.Options{})
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	defer func() { _ = client.Close() }()

	for i := 0; i < 2; i++ {
		s, err := client.Dial(ctx, endpoint, testProto)
		if err != nil {
			t.Fatalf("Dial #%d: %v", i, err)
		}
		var ack [1]byte
		if _, err := io.ReadFull(s, ack[:]); err != nil {
			t.Fatalf("read ack #%d: %v", i, err)
		}
		_ = s.Close()
		select {
		case <-ready:
		case <-time.After(2 * time.Second):
			t.Fatalf("handler #%d didn't fire", i)
		}
	}

	seenMu.Lock()
	defer seenMu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("seen %d RemoteIDs, want 2: %v", len(seen), seen)
	}
	if seen[0] != seen[1] {
		t.Errorf("RemoteID changed between dials: %q vs %q", seen[0], seen[1])
	}
	if !strings.HasPrefix(seen[0], "ws-peer:") {
		t.Errorf("RemoteID shape = %q, want ws-peer:<token>", seen[0])
	}
}

// TestBackend_TwoBackendsHaveDifferentTokens covers the negative:
// two separate dialer backends mint independent tokens, so the
// server sees different RemoteIDs. Without this property,
// auth.Wrap would alias unrelated peers.
func TestBackend_TwoBackendsHaveDifferentTokens(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server, endpoint := newServer(t, ctx, nil)

	var (
		seen   []string
		seenMu sync.Mutex
		ready  = make(chan struct{}, 2)
	)
	server.Handle(testProto, func(s transport.Stream) {
		seenMu.Lock()
		seen = append(seen, s.RemoteID())
		seenMu.Unlock()
		_, _ = s.Write([]byte{0x01})
		ready <- struct{}{}
		_, _ = io.Copy(io.Discard, s)
		_ = s.Close()
	})

	for i := 0; i < 2; i++ {
		client, err := wsbackend.New(ctx, wsbackend.Options{})
		if err != nil {
			t.Fatalf("client #%d New: %v", i, err)
		}
		s, err := client.Dial(ctx, endpoint, testProto)
		if err != nil {
			t.Fatalf("Dial #%d: %v", i, err)
		}
		var ack [1]byte
		if _, err := io.ReadFull(s, ack[:]); err != nil {
			t.Fatalf("read ack #%d: %v", i, err)
		}
		_ = s.Close()
		_ = client.Close()
		select {
		case <-ready:
		case <-time.After(2 * time.Second):
			t.Fatalf("handler #%d didn't fire", i)
		}
	}

	seenMu.Lock()
	defer seenMu.Unlock()
	if seen[0] == seen[1] {
		t.Errorf("distinct backends produced the same RemoteID %q", seen[0])
	}
}

// TestBackend_UnregisteredProtocolReturns404 verifies the server
// 404s when no handler matches the requested protocol id. Client
// surface: Dial returns an error containing 404 details. Mirrors
// libp2p's "protocol not supported" so the attach-side graceful-
// degradation path keeps working.
func TestBackend_UnregisteredProtocolReturns404(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, endpoint := newServer(t, ctx, nil) // no Handle registration

	client, err := wsbackend.New(ctx, wsbackend.Options{})
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Dial(ctx, endpoint, "/mosey/unknown/1.0.0")
	if err == nil {
		t.Fatal("Dial against unregistered protocol must error")
	}
}

// TestBackend_TLSEndpoint covers wss:// end-to-end: self-signed
// cert on the server, InsecureSkipVerify on the client.
func TestBackend_TLSEndpoint(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tlsCfg := selfSignedTLSConfig(t, "mosey-ws-test")
	server, endpoint := newServer(t, ctx, tlsCfg)
	if !strings.HasPrefix(endpoint, "wss://") {
		t.Errorf("Endpoint = %q, want wss:// prefix", endpoint)
	}
	server.Handle(testProto, func(s transport.Stream) {
		defer s.Close()
		_, _ = s.Write([]byte("tls ok"))
	})

	client, err := wsbackend.New(ctx, wsbackend.Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	defer func() { _ = client.Close() }()

	stream, err := client.Dial(ctx, endpoint, testProto)
	if err != nil {
		t.Fatalf("Dial wss: %v", err)
	}
	defer stream.Close()

	buf := make([]byte, len("tls ok"))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "tls ok" {
		t.Errorf("got %q, want %q", buf, "tls ok")
	}
}

// TestBackend_EndpointsAdvertisesScheme covers the Multi-router
// contract: Endpoints() returns URIs whose scheme is in Schemes().
func TestBackend_EndpointsAdvertisesScheme(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, endpoint := newServer(t, ctx, nil)
	endpoints := server.Endpoints()
	if len(endpoints) != 1 {
		t.Fatalf("Endpoints = %v, want exactly one entry", endpoints)
	}
	if endpoints[0] != endpoint {
		t.Errorf("Endpoints[0] = %q, want %q", endpoints[0], endpoint)
	}
	schemes := server.Schemes()
	if len(schemes) != 2 || schemes[0] != "ws" || schemes[1] != "wss" {
		t.Errorf("Schemes = %v, want [ws wss]", schemes)
	}
}

// newServer binds a WebSocket backend on localhost:0 with the given
// TLS config (nil = plain ws), registers cleanup, returns the
// backend + its dialable endpoint.
func newServer(t *testing.T, ctx context.Context, tlsCfg *tls.Config) (*wsbackend.Backend, string) {
	t.Helper()
	b, err := wsbackend.New(ctx, wsbackend.Options{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsCfg,
	})
	if err != nil {
		t.Fatalf("server New: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	eps := b.Endpoints()
	if len(eps) == 0 {
		t.Fatal("server published no endpoints")
	}
	return b, eps[0]
}

// selfSignedTLSConfig builds a one-shot TLS config for wss://
// tests. ECDSA P-256 keeps the keygen + signing fast; CN doesn't
// matter because the client uses InsecureSkipVerify.
func selfSignedTLSConfig(t *testing.T, cn string) *tls.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshalkey: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	}
}
