package http2_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/transport"
	"github.com/firefly-engineering/mosey/transport/http2"
)

// TestBackend_TLSRoundTrip stands up a TLS-listening backend with
// a self-signed cert and exercises a bidi exchange via an
// https:// dial. The client uses InsecureSkipVerify because the
// cert isn't in any trust store.
func TestBackend_TLSRoundTrip(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tlsConfig, err := selfSignedTLSConfig("mosey-test")
	if err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}

	server, err := http2.New(ctx, http2.Options{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  tlsConfig,
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	defer func() { _ = server.Close() }()

	endpoints := server.Endpoints()
	if len(endpoints) != 1 || !strings.HasPrefix(endpoints[0], "https://") {
		t.Fatalf("expected https:// endpoint, got %v", endpoints)
	}

	const proto = "/test/echo/1.0.0"
	server.Handle(proto, func(s transport.Stream) {
		defer func() { _ = s.Close() }()
		buf := make([]byte, 1024)
		for {
			n, err := s.Read(buf)
			if n > 0 {
				_, _ = s.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	})

	client, err := http2.New(ctx, http2.Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer func() { _ = client.Close() }()

	stream, err := client.Dial(ctx, endpoints[0], proto)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = stream.Close() }()

	const sent = "tls-hello"
	if _, err := stream.Write([]byte(sent)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(sent))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != sent {
		t.Errorf("echo = %q, want %q", got, sent)
	}
}

// TestBackend_HTTPSDialAgainstH2CServerFails sanity-checks that a
// client dialing https:// against an h2c-only server doesn't
// silently succeed. We expect the TLS handshake to fail (h2c
// listener has no cert).
func TestBackend_HTTPSDialAgainstH2CServerFails(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := http2.New(ctx, http2.Options{ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	defer func() { _ = server.Close() }()

	client, err := http2.New(ctx, http2.Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Force an https:// dial against the h2c endpoint by replacing
	// the scheme. TLS handshake should fail.
	h2cEndpoint := server.Endpoints()[0]
	httpsEndpoint := "https://" + strings.TrimPrefix(h2cEndpoint, "http://")

	_, err = client.Dial(ctx, httpsEndpoint, "/test/whatever/1.0.0")
	if err == nil {
		t.Fatal("expected TLS handshake failure dialing https:// against h2c server")
	}
}

// selfSignedTLSConfig builds a one-off ECDSA-P256 cert valid for
// 127.0.0.1 and returns a TLSConfig suitable for an http.Server.
// Test-only — produces a fresh keypair every call.
func selfSignedTLSConfig(commonName string) (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{derBytes},
			PrivateKey:  priv,
		}},
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	}, nil
}
