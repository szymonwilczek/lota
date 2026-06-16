// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package ca

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeBundle materializes a bundle directory: one PEM file per root and a
// manifest pinning each by its true SHA-256. The caller mutates the result
// to exercise the fail-closed paths.
func writeBundle(t *testing.T, roots map[string]certAndKey) string {
	t.Helper()
	dir := t.TempDir()
	var manifest []byte
	for name, rk := range roots {
		pemBytes := pemBlock("CERTIFICATE", rk.der)
		if err := os.WriteFile(filepath.Join(dir, name), pemBytes, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		sum := sha256.Sum256(rk.der)
		line := hex.EncodeToString(sum[:]) + "  " + name + "  vendor " + name + "\n"
		manifest = append(manifest, line...)
	}
	if err := os.WriteFile(filepath.Join(dir, EKBundleManifestName), manifest, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return dir
}

func TestLoadEKRootBundleAcceptsPinnedRoots(t *testing.T) {
	roots := map[string]certAndKey{
		"infineon.pem": makeRoot(t, "infineon-root"),
		"intel.pem":    makeRoot(t, "intel-root"),
		"stm.pem":      makeRoot(t, "stm-root"),
	}
	dir := writeBundle(t, roots)

	pems, err := LoadEKRootBundle(dir)
	if err != nil {
		t.Fatalf("LoadEKRootBundle: %v", err)
	}
	if len(pems) != len(roots) {
		t.Fatalf("loaded %d roots, want %d", len(pems), len(roots))
	}

	// loaded bundle must wire straight into an Issuer and verify an EK
	// minted under one of the bundled roots
	caCertPEM, caKeyPEM := makeLOTACAPEM(t)
	is, err := NewIssuer(IssuerConfig{CACertPEM: caCertPEM, CAKeyPEM: caKeyPEM, EKRootPEMs: pems})
	if err != nil {
		t.Fatalf("NewIssuer with bundle: %v", err)
	}
	ekDER, _ := makeEKCert(t, roots["intel.pem"], nil)
	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); err != nil {
		t.Fatalf("bundled root did not verify its EK: %v", err)
	}
}

func TestLoadEKRootBundleRejectsTamperedRoot(t *testing.T) {
	roots := map[string]certAndKey{"infineon.pem": makeRoot(t, "infineon-root")}
	dir := writeBundle(t, roots)

	// swap the file contents for a different root while leaving the pin
	rogue := makeRoot(t, "rogue-root")
	if err := os.WriteFile(filepath.Join(dir, "infineon.pem"), pemBlock("CERTIFICATE", rogue.der), 0o644); err != nil {
		t.Fatalf("overwrite root: %v", err)
	}
	if _, err := LoadEKRootBundle(dir); err == nil {
		t.Fatal("accepted a root whose fingerprint does not match its pin")
	}
}

func TestLoadEKRootBundleRejectsUnpinnedStray(t *testing.T) {
	roots := map[string]certAndKey{"infineon.pem": makeRoot(t, "infineon-root")}
	dir := writeBundle(t, roots)

	stray := makeRoot(t, "stray-root")
	if err := os.WriteFile(filepath.Join(dir, "stray.pem"), pemBlock("CERTIFICATE", stray.der), 0o644); err != nil {
		t.Fatalf("write stray: %v", err)
	}
	if _, err := LoadEKRootBundle(dir); err == nil {
		t.Fatal("accepted a bundle with an unpinned stray certificate")
	}
}

func TestLoadEKRootBundleRejectsMissingFile(t *testing.T) {
	roots := map[string]certAndKey{"infineon.pem": makeRoot(t, "infineon-root")}
	dir := writeBundle(t, roots)

	if err := os.Remove(filepath.Join(dir, "infineon.pem")); err != nil {
		t.Fatalf("remove root: %v", err)
	}
	if _, err := LoadEKRootBundle(dir); err == nil {
		t.Fatal("accepted a manifest pinning a missing root file")
	}
}

func TestLoadEKRootBundleRejectsMissingManifest(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadEKRootBundle(dir); err == nil {
		t.Fatal("accepted a bundle directory with no manifest")
	}
}

func TestLoadEKRootBundleRejectsEmptyManifest(t *testing.T) {
	dir := t.TempDir()
	body := "# only comments here\n\n"
	if err := os.WriteFile(filepath.Join(dir, EKBundleManifestName), []byte(body), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := LoadEKRootBundle(dir); err == nil {
		t.Fatal("accepted a manifest that pins no roots")
	}
}

func TestLoadEKRootBundleRejectsMalformedPin(t *testing.T) {
	roots := map[string]certAndKey{"infineon.pem": makeRoot(t, "infineon-root")}
	dir := writeBundle(t, roots)
	body := "nothex  infineon.pem  vendor\n"
	if err := os.WriteFile(filepath.Join(dir, EKBundleManifestName), []byte(body), 0o644); err != nil {
		t.Fatalf("rewrite manifest: %v", err)
	}
	if _, err := LoadEKRootBundle(dir); err == nil {
		t.Fatal("accepted a manifest with a non-hex pin")
	}
}

func TestLoadEKRootBundleRejectsDuplicatePin(t *testing.T) {
	root := makeRoot(t, "infineon-root")
	dir := t.TempDir()
	pemBytes := pemBlock("CERTIFICATE", root.der)
	for _, n := range []string{"a.pem", "b.pem"} {
		if err := os.WriteFile(filepath.Join(dir, n), pemBytes, 0o644); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
	}
	sum := sha256.Sum256(root.der)
	pin := hex.EncodeToString(sum[:])
	body := pin + "  a.pem  vendor\n" + pin + "  b.pem  vendor\n"
	if err := os.WriteFile(filepath.Join(dir, EKBundleManifestName), []byte(body), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := LoadEKRootBundle(dir); err == nil {
		t.Fatal("accepted a manifest with a duplicate pin")
	}
}

func TestLoadEKRootBundleRejectsMultiCertFile(t *testing.T) {
	r1 := makeRoot(t, "root-1")
	r2 := makeRoot(t, "root-2")
	dir := t.TempDir()
	two := append(pemBlock("CERTIFICATE", r1.der), pemBlock("CERTIFICATE", r2.der)...)
	if err := os.WriteFile(filepath.Join(dir, "pair.pem"), two, 0o644); err != nil {
		t.Fatalf("write pair: %v", err)
	}
	sum := sha256.Sum256(r1.der)
	body := hex.EncodeToString(sum[:]) + "  pair.pem  vendor\n"
	if err := os.WriteFile(filepath.Join(dir, EKBundleManifestName), []byte(body), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := LoadEKRootBundle(dir); err == nil {
		t.Fatal("accepted a pinned file carrying more than one certificate")
	}
}
