// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// writeTestTLSPair mints self-signed loopback certificate for the listener
func writeTestTLSPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "lota-connlimit-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// startCapTestServer brings up the attestation listener over cfg,
// filling in only the fields every server needs, and returns its address
func startCapTestServer(t *testing.T, cfg ServerConfig) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	cfg.Address = addr
	cfg.CertFile, cfg.KeyFile = writeTestTLSPair(t)
	cfg.Logger = logging.Nop()

	vcfg := verify.DefaultConfig()
	vcfg.Metrics = metrics.New()
	v := verify.NewVerifier(vcfg, store.NewMemoryStore())

	srv, err := NewServer(cfg, v)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(srv.Stop)
	return addr
}

// challengedConns opens n concurrent TLS connections and returns how many were served challenge.
// Accepted connections get the 48-byte challenge;
// ones the listener turns away are closed before that, so the count is the live cap
func challengedConns(t *testing.T, addr string, n int) int {
	t.Helper()
	tlsCfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13} // #nosec G402 -- self-signed loopback listener under test

	served := 0
	open := make([]net.Conn, 0, n)
	t.Cleanup(func() {
		for _, c := range open {
			c.Close()
		}
	})

	for range n {
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			continue
		}
		open = append(open, conn)
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			continue
		}
		var challenge [48]byte
		if _, err := readFullConn(conn, challenge[:]); err == nil {
			served++
		}
	}
	return served
}

func readFullConn(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Attestation listener must never run uncapped:
// every accepted connection costs a TLS handshake and full report verification,
// so unbounded port lets a client stampede exhaust the verifier with no policy
// or crypto failure in sight.
// Config that says nothing about the cap must still get one
func TestListenerCapsConcurrentConnections(t *testing.T) {
	const attempts = 300

	addr := startCapTestServer(t, ServerConfig{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 10 * time.Second,
	})

	served := challengedConns(t, addr, attempts)
	if served == attempts {
		t.Fatalf("listener served all %d concurrent connections: no cap in effect", served)
	}
	if served == 0 {
		t.Fatal("listener served no connections at all")
	}
}

// Explicit cap is honoured exactly, so operators can size the listener
func TestListenerHonoursExplicitCap(t *testing.T) {
	const cap = 8

	addr := startCapTestServer(t, ServerConfig{
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxConnections: cap,
	})

	if served := challengedConns(t, addr, cap*3); served != cap {
		t.Errorf("served %d concurrent connections, want the configured cap %d", served, cap)
	}
}
