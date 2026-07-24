// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
//go:build pkcs11

// Integration test for the PKCS#11-backed CA signer.
//
// It needs a live PKCS#11 token (SoftHSM in CI, a real HSM for an operator)
// and is skipped unless the token is provided through the environment:
//
//	LOTA_TEST_PKCS11_MODULE  path to the PKCS#11 module (.so)
//	LOTA_TEST_PKCS11_TOKEN   initialised token label
//	LOTA_CA_PKCS11_PIN       token user PIN
//
// It generates a CA key inside the token, loads it back through the
// production newPKCS11Signer path, mints a CA certificate bound to that key,
// and checks that an issued AIK certificate chains to it -- proving the
// token key signs without the private key ever leaving the device.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ThalesGroup/crypto11"

	"github.com/szymonwilczek/lota/attestca/ca"
)

func TestPKCS11SignerIssuesAIK(t *testing.T) {
	module := os.Getenv("LOTA_TEST_PKCS11_MODULE")
	token := os.Getenv("LOTA_TEST_PKCS11_TOKEN")
	pin := os.Getenv("LOTA_CA_PKCS11_PIN")
	if module == "" || token == "" || pin == "" {
		t.Skip("set LOTA_TEST_PKCS11_MODULE, LOTA_TEST_PKCS11_TOKEN and LOTA_CA_PKCS11_PIN to run")
	}

	// generate the CA key inside the token, then drop the handle so the
	// load below goes through the same path the daemon uses
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("key id: %v", err)
	}
	label := "lota-ca-test-" + hex.EncodeToString(id)

	ctx, err := crypto11.Configure(&crypto11.Config{Path: module, TokenLabel: token, Pin: pin})
	if err != nil {
		t.Fatalf("configure token: %v", err)
	}
	if _, err := ctx.GenerateRSAKeyPairWithLabel(id, []byte(label), 2048); err != nil {
		_ = ctx.Close()
		t.Fatalf("generate CA key in token: %v", err)
	}
	if err := ctx.Close(); err != nil {
		t.Fatalf("close token: %v", err)
	}

	caSigner, closeToken, err := newPKCS11Signer(pkcs11KeyConfig{
		module: module, token: token, label: label, pin: pin,
	})
	if err != nil {
		t.Fatalf("load CA key from token: %v", err)
	}
	defer func() {
		if cerr := closeToken(); cerr != nil {
			t.Errorf("close token: %v", cerr)
		}
	}()

	// CA certificate bound to the token-held key
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "lota-attest-ca-hsm"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caSigner.Public(), caSigner)
	if err != nil {
		t.Fatalf("self-sign CA cert with token key: %v", err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// NewIssuer needs at least one EK root; a throwaway self-signed cert
	// satisfies the constructor without affecting the signing path
	ekRoot := mustThrowawayRootPEM(t)

	issuer, err := ca.NewIssuer(ca.IssuerConfig{
		CACertPEM:  caCertPEM,
		CASigner:   caSigner,
		EKRootPEMs: [][]byte{ekRoot},
	})
	if err != nil {
		t.Fatalf("NewIssuer with token signer: %v", err)
	}

	aikKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("AIK key: %v", err)
	}
	aikDER, err := issuer.IssueAIKCertificate(&aikKey.PublicKey, "device-hsm", "", now)
	if err != nil {
		t.Fatalf("IssueAIKCertificate via token key: %v", err)
	}

	aikCert, err := x509.ParseCertificate(aikDER)
	if err != nil {
		t.Fatalf("parse issued AIK cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(issuer.CACertDER())
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := aikCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("AIK cert signed by the token key does not chain to the CA: %v", err)
	}
}

func mustThrowawayRootPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("throwaway root key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "throwaway-ek-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("throwaway root cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
