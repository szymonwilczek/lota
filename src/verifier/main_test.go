// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/szymonwilczek/lota/verifier/store"
)

func TestGenerateTestCertIncludesLoopbackSAN(t *testing.T) {
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir(temp): %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	if err := generateTestCert(); err != nil {
		t.Fatalf("generateTestCert: %v", err)
	}

	pemBytes, err := os.ReadFile(filepath.Join(tmp, "lota-verifier.crt"))
	if err != nil {
		t.Fatalf("ReadFile(cert): %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("certificate PEM did not contain a block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if !cert.IsCA {
		t.Fatal("generated verifier certificate must be usable as a test trust anchor")
	}
	if err := cert.VerifyHostname("localhost"); err != nil {
		t.Fatalf("localhost SAN missing: %v", err)
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("127.0.0.1 IP SAN missing: %v", err)
	}
	if len(cert.IPAddresses) == 0 || !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("expected first IP SAN to be 127.0.0.1, got %#v", cert.IPAddresses)
	}
}

// writeTestCARoot generates a CA-capable certificate and returns its PEM path,
// so test can ask for certificate verification without carrying fixture
func writeTestCARoot(t *testing.T) string {
	t.Helper()

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir(temp): %v", err)
	}
	defer func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}()

	if err := generateTestCert(); err != nil {
		t.Fatalf("generateTestCert: %v", err)
	}
	return filepath.Join(dir, "lota-verifier.crt")
}

// Certificate-verifying AIK store is file-backed and independent of the backend
// that holds baselines, nonces and enforcement state, so every backend must
// be able to select it.
func TestSelectAIKStoreCertificatePathIsBackendIndependent(t *testing.T) {
	caPath := writeTestCARoot(t)

	tofuCalled := false
	tofu := func() (store.AIKStore, error) {
		tofuCalled = true
		return store.NewFileStore(t.TempDir())
	}

	aik, cs, err := selectAIKStore(aikStoreParams{
		StorePath:   t.TempDir(),
		CACerts:     []string{caPath},
		RequireCert: true,
	}, tofu)
	if err != nil {
		t.Fatalf("selectAIKStore: %v", err)
	}
	if cs == nil {
		t.Fatal("--require-cert with a trust anchor must select the certificate-backed store")
	}
	if aik != store.AIKStore(cs) {
		t.Fatal("the returned AIK store must be the certificate-backed one")
	}
	if tofuCalled {
		t.Fatal("the backend's TOFU store must not be constructed on the certificate path")
	}
}

func TestSelectAIKStoreTOFUWhenNoVerificationAsked(t *testing.T) {
	tofuCalled := false
	tofu := func() (store.AIKStore, error) {
		tofuCalled = true
		return store.NewFileStore(t.TempDir())
	}

	aik, cs, err := selectAIKStore(aikStoreParams{StorePath: t.TempDir()}, tofu)
	if err != nil {
		t.Fatalf("selectAIKStore: %v", err)
	}
	if cs != nil {
		t.Fatal("no --require-cert and no --aik-ca-cert must not select the certificate-backed store")
	}
	if !tofuCalled || aik == nil {
		t.Fatal("the backend's TOFU store must be the fallback")
	}
}

func TestSelectAIKStoreRefusals(t *testing.T) {
	caPath := writeTestCARoot(t)

	tests := []struct {
		name   string
		params aikStoreParams
		want   error
	}{
		{
			name:   "require-cert without a trust anchor",
			params: aikStoreParams{RequireCert: true},
			want:   store.ErrNoTrustedCAs,
		},
		{
			name:   "CRL without a trust anchor",
			params: aikStoreParams{CRLs: []string{"unused.crl"}},
			want:   errCRLWithoutCARoot,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.params.StorePath = t.TempDir()
			tofu := func() (store.AIKStore, error) {
				t.Fatal("a refused selection must not construct the TOFU store")
				return nil, nil
			}
			_, _, err := selectAIKStore(tc.params, tofu)
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}

	// the same CRL flag is accepted once a root is present,
	// so the refusal above is about the missing anchor and not about CRLs at all
	_, cs, err := selectAIKStore(aikStoreParams{
		StorePath: t.TempDir(),
		CACerts:   []string{caPath},
	}, func() (store.AIKStore, error) {
		t.Fatal("a trust anchor alone must select the certificate-backed store")
		return nil, nil
	})
	if err != nil || cs == nil {
		t.Fatalf("--aik-ca-cert alone must select the certificate-backed store: cs=%v err=%v", cs, err)
	}
}
