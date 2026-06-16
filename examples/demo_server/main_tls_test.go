// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeKeypair writes a self-signed ECDSA cert and its key to dir and
// returns the two paths, for exercising buildTLSConfig's load paths.
func writeKeypair(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "PRIVATE KEY", keyDER)
	return certPath, keyPath
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestBuildTLSConfigPlainHTTP(t *testing.T) {
	cfg, err := buildTLSConfig("", "", "")
	if err != nil || cfg != nil {
		t.Fatalf("plain HTTP: cfg=%v err=%v", cfg, err)
	}
	if transportLabel(cfg) != "http" {
		t.Fatalf("transport label = %q", transportLabel(cfg))
	}
}

func TestBuildTLSConfigServerOnly(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeypair(t, dir, "server")
	cfg, err := buildTLSConfig(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("server TLS: %v", err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("server-only must not require a client cert")
	}
	if transportLabel(cfg) != "https" {
		t.Fatalf("transport label = %q", transportLabel(cfg))
	}
}

func TestBuildTLSConfigMutual(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeypair(t, dir, "server")
	caPath, _ := writeKeypair(t, dir, "ca")
	cfg, err := buildTLSConfig(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("mTLS: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("mTLS must require and verify a client cert")
	}
	if cfg.ClientCAs == nil {
		t.Fatal("mTLS must pin a client CA pool")
	}
	if transportLabel(cfg) != "https+mtls" {
		t.Fatalf("transport label = %q", transportLabel(cfg))
	}
}

func TestBuildTLSConfigRejectsBadCombos(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeypair(t, dir, "server")

	if _, err := buildTLSConfig(certPath, "", ""); err == nil {
		t.Fatal("accepted -tls-cert without -tls-key")
	}
	if _, err := buildTLSConfig("", "", "ca.crt"); err == nil {
		t.Fatal("accepted -client-ca without server keypair")
	}
	if _, err := buildTLSConfig(certPath, keyPath, filepath.Join(dir, "missing.crt")); err == nil {
		t.Fatal("accepted a missing -client-ca file")
	}
	// -client-ca file with no certificate must be rejected
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("not a cert\n"), 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	if _, err := buildTLSConfig(certPath, keyPath, empty); err == nil {
		t.Fatal("accepted a -client-ca with no certificate")
	}
}
