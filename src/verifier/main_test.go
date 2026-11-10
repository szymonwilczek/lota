// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
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

func TestSelectAIKVerifierWithRoot(t *testing.T) {
	cv, err := selectAIKVerifier(aikVerifierParams{
		CACerts:     []string{writeTestCARoot(t)},
		RequireCert: true,
	})
	if err != nil {
		t.Fatalf("selectAIKVerifier: %v", err)
	}
	if cv == nil {
		t.Fatal("a trust anchor must select the certificate verifier")
	}
}

func TestSelectAIKVerifierNoneWithoutARoot(t *testing.T) {
	cv, err := selectAIKVerifier(aikVerifierParams{})
	if err != nil {
		t.Fatalf("selectAIKVerifier: %v", err)
	}
	if cv != nil {
		t.Fatal("no --aik-ca-cert must leave no verifier")
	}
}

func TestSelectAIKVerifierRefusals(t *testing.T) {
	tests := []struct {
		name   string
		params aikVerifierParams
		want   error
	}{
		{
			name:   "require-cert without a trust anchor",
			params: aikVerifierParams{RequireCert: true},
			want:   store.ErrNoTrustedCAs,
		},
		{
			name:   "CRL without a trust anchor",
			params: aikVerifierParams{CRLs: []string{"unused.crl"}},
			want:   errCRLWithoutCARoot,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := selectAIKVerifier(tc.params); !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

// Without a database, a ban survives reopening the state file.
func TestEnforcementStoresOutliveTheProcessThatWroteThem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verifier-state.sqlite")
	hwid := [32]byte{0xab, 0xcd}

	db, err := store.OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	first := sqliteEnforcementStores(db, slog.New(slog.NewTextHandler(io.Discard, nil)), metrics.New())
	if err := first.bans.BanHardware("default", hwid, store.RevocationCheating, "ops", ""); err != nil {
		t.Fatalf("BanHardware: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := store.OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB(reopen): %v", err)
	}
	defer reopened.Close()
	second := sqliteEnforcementStores(reopened, slog.New(slog.NewTextHandler(io.Discard, nil)), metrics.New())
	_, banned, err := second.bans.IsBanned("default", hwid)
	if err != nil || !banned {
		t.Errorf("the ban did not survive a reopen of the state "+
			"database: %v", err)
	}
	if entries := second.audit.Query(10); len(entries) != 1 || entries[0].Action != "ban" {
		t.Errorf("audit entries after a reopen = %+v, want the ban", entries)
	}
}

// With no durable state, no enforcement store is installed,
// so the API answers 503.
func TestNoDurableStateInstallsNoEnforcementStore(t *testing.T) {
	cfg := verify.DefaultConfig()

	var none enforcementStores
	none.install(&cfg)

	if cfg.RevocationStore != nil {
		t.Error("revocation store installed for an instance keeping no durable state")
	}
	if cfg.BanStore != nil {
		t.Error("ban store installed for an instance keeping no durable state")
	}
	if cfg.AttestationLog != nil {
		t.Error("attestation log installed for an instance keeping no durable state")
	}
	if none.audit != nil {
		t.Error("audit log installed for an instance keeping no durable state")
	}
}

// A file that already exists takes perm too:
// a key regenerated over a world-readable copy ends up 0600.
func TestWritePEMFileTightensAnExistingFile(t *testing.T) {
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}
	dir := t.TempDir()

	for _, tc := range []struct {
		name string
		seed bool
	}{{"existing", true}, {"fresh", false}} {
		path := filepath.Join(dir, tc.name+".key")
		if tc.seed {
			if err := os.WriteFile(path, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := writePEMFile(path, 0o600, block); err != nil {
			t.Fatalf("%s: writePEMFile: %v", tc.name, err)
		}
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != 0o600 {
			t.Errorf("%s: mode %o, want 600", tc.name, got)
		}
	}
}
