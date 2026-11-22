// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - CRL load and revocation tests
//
// These exercise the CertificateVerifier wiring around the shared crl
// module (load at construction, lookup in the verify paths, SIGHUP
// hot-swap).
//
// Unit tests for the canonicalisation and per-CRL gates live in the
// crl module itself.

package store

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/crl"
)

// buildCA returns a self-signed CA cert + key suitable for issuing AIK
// leaves and signing CRLs in the same chain.
func buildCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xCA),
		Subject: pkix.Name{
			CommonName:   "LOTA CRL Test CA",
			Organization: []string{"LOTA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ca parse: %v", err)
	}
	return cert, key
}

// buildAIKLeaf issues an AIK certificate and returns the key it certifies.
func buildAIKLeaf(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, serial int64) (*rsa.PublicKey, []byte) {
	t.Helper()
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: "device-pseudonym",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(12 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf create: %v", err)
	}
	return &leafKey.PublicKey, der
}

// writeCRL emits a PEM-encoded CRL covering revokedSerials, signed by ca.
// nextUpdate is honored so callers can construct stale CRLs.
func writeCRL(t *testing.T, dir string, ca *x509.Certificate, caKey *rsa.PrivateKey, nextUpdate time.Time, revokedSerials ...int64) string {
	t.Helper()

	var entries []x509.RevocationListEntry
	for _, s := range revokedSerials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(s),
			RevocationTime: time.Now().Add(-time.Minute),
		})
	}

	tmpl := &x509.RevocationList{
		SignatureAlgorithm:        x509.SHA256WithRSA,
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}

	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, caKey)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}

	path := filepath.Join(dir, "crl.pem")
	buf := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write crl: %v", err)
	}
	return path
}

// writeCert PEM-encodes a CA cert so NewCertificateVerifier can pick
// it up from a file path the same way the production loader does.
func writeCert(t *testing.T, dir string, ca *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(dir, "ca.pem")
	buf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	return path
}

func TestCRL_LoadRejectsUnknownIssuer(t *testing.T) {
	dir := t.TempDir()

	good, goodKey := buildCA(t)
	other, otherKey := buildCA(t)

	goodPath := writeCert(t, dir, good)
	// CRL signed by "other" CA - signature must not validate against the
	// store's trusted root set
	crlPath := writeCRL(t, dir, other, otherKey, time.Now().Add(time.Hour))

	_, err := NewCertificateVerifier([]string{goodPath}, []string{crlPath})
	if err == nil {
		t.Fatal("expected CRL load to fail: signed by untrusted CA")
	}
	if !errors.Is(err, crl.ErrCRLNoIssuer) && !errors.Is(err, crl.ErrCRLSignature) {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = goodKey
}

func TestCRL_RevokesAIKCertificate(t *testing.T) {
	dir := t.TempDir()

	ca, caKey := buildCA(t)
	caPath := writeCert(t, dir, ca)

	// revoke serial 0x42; mint a leaf with that serial
	const revokedSerial = 0x42
	leafKey, leafDER := buildAIKLeaf(t, ca, caKey, revokedSerial)

	crlPath := writeCRL(t, dir, ca, caKey, time.Now().Add(time.Hour), revokedSerial)

	cv, err := NewCertificateVerifier([]string{caPath}, []string{crlPath})
	if err != nil {
		t.Fatalf("store init: %v", err)
	}
	if cv.CRLCount() != 1 {
		t.Fatalf("expected 1 CRL, got %d", cv.CRLCount())
	}

	_, err = cv.VerifyAIKCertificate(leafKey, leafDER)
	if !errors.Is(err, crl.ErrCertificateRevoked) {
		t.Fatalf("expected ErrCertificateRevoked, got %v", err)
	}

}

func TestCRL_PassesUnrevokedAIKCertificate(t *testing.T) {
	dir := t.TempDir()

	ca, caKey := buildCA(t)
	caPath := writeCert(t, dir, ca)

	leafKey, leafDER := buildAIKLeaf(t, ca, caKey, 0x11)
	crlPath := writeCRL(t, dir, ca, caKey, time.Now().Add(time.Hour), 0x99 /* not the leaf */)

	cv, err := NewCertificateVerifier([]string{caPath}, []string{crlPath})
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	if _, err := cv.VerifyAIKCertificate(leafKey, leafDER); err != nil {
		t.Fatalf("unrevoked leaf must verify, got %v", err)
	}
}

func TestCRL_FailsClosedWhenStale(t *testing.T) {
	dir := t.TempDir()

	ca, caKey := buildCA(t)
	caPath := writeCert(t, dir, ca)

	leafKey, leafDER := buildAIKLeaf(t, ca, caKey, 0x33)

	// NextUpdate strictly in the past => every CRL for this issuer is stale
	crlPath := writeCRL(t, dir, ca, caKey, time.Now().Add(-time.Minute), 0x99)

	cv, err := NewCertificateVerifier([]string{caPath}, []string{crlPath})
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	_, err = cv.VerifyAIKCertificate(leafKey, leafDER)
	if !errors.Is(err, crl.ErrCRLStale) {
		t.Fatalf("expected ErrCRLStale, got %v", err)
	}
}

// TestCRL_ReloadHotSwapsRevocations covers the SIGHUP refresh path: a
// CRL file that originally revoked one serial is rewritten in place to
// revoke a different serial, ReloadCRLs() is invoked, and lookups
// switch over to the new feed without recreating the store.
func TestCRL_ReloadHotSwapsRevocations(t *testing.T) {
	dir := t.TempDir()

	ca, caKey := buildCA(t)
	caPath := writeCert(t, dir, ca)

	const initialSerial = 0x301
	const refreshedSerial = 0x302

	crlPath := writeCRL(t, dir, ca, caKey, time.Now().Add(time.Hour),
		initialSerial)

	cv, err := NewCertificateVerifier([]string{caPath}, []string{crlPath})
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	// initial state: initialSerial revoked, refreshedSerial accepted.
	initialLeafKey, initialLeafDER := buildAIKLeaf(t, ca, caKey, initialSerial)
	if _, err := cv.VerifyAIKCertificate(initialLeafKey, initialLeafDER); !errors.Is(err, crl.ErrCertificateRevoked) {
		t.Fatalf("pre-reload: expected ErrCertificateRevoked for serial %x, got %v",
			initialSerial, err)
	}
	refreshedLeafKey, refreshedLeafDER := buildAIKLeaf(t, ca, caKey, refreshedSerial)
	if _, err := cv.VerifyAIKCertificate(refreshedLeafKey, refreshedLeafDER); err != nil {
		t.Fatalf("pre-reload: serial %x must verify, got %v",
			refreshedSerial, err)
	}

	// rewrite the same path with a refreshed feed; writeCRL truncates
	// and re-creates the file under the same name (crl.pem).
	if _, err := os.Stat(crlPath); err != nil {
		t.Fatalf("CRL path missing before refresh: %v", err)
	}
	_ = writeCRL(t, dir, ca, caKey, time.Now().Add(time.Hour),
		refreshedSerial)

	if err := cv.ReloadCRLs(); err != nil {
		t.Fatalf("ReloadCRLs: %v", err)
	}
	if cv.CRLCount() != 1 {
		t.Fatalf("expected 1 CRL after reload, got %d", cv.CRLCount())
	}

	// post-reload: refreshedSerial rejects, initialSerial accepted.
	if _, err := cv.VerifyAIKCertificate(refreshedLeafKey, refreshedLeafDER); !errors.Is(err, crl.ErrCertificateRevoked) {
		t.Fatalf("post-reload: expected ErrCertificateRevoked for serial %x, got %v",
			refreshedSerial, err)
	}
	if _, err := cv.VerifyAIKCertificate(initialLeafKey, initialLeafDER); err != nil {
		t.Fatalf("post-reload: serial %x must verify, got %v",
			initialSerial, err)
	}
}

// TestCRL_ReloadRejectsBadFeedKeepsPreviousSet covers the failure
// path: when the refreshed CRL fails any startup gate (signature,
// NextUpdate, algorithm allow-list, ...) the previous set must remain
// active so a malformed update cannot drop revocations on the floor.
func TestCRL_ReloadRejectsBadFeedKeepsPreviousSet(t *testing.T) {
	dir := t.TempDir()

	ca, caKey := buildCA(t)
	caPath := writeCert(t, dir, ca)

	const revoked = 0x401
	crlPath := writeCRL(t, dir, ca, caKey, time.Now().Add(time.Hour), revoked)

	cv, err := NewCertificateVerifier([]string{caPath}, []string{crlPath})
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	// overwrite the file with a CRL signed by an unrelated CA: signature
	// verification must fail and ReloadCRLs() return an error.
	other, otherKey := buildCA(t)
	_ = writeCRL(t, dir, other, otherKey, time.Now().Add(time.Hour),
		revoked)

	if err := cv.ReloadCRLs(); err == nil {
		t.Fatal("expected ReloadCRLs to reject CRL signed by untrusted CA")
	}

	// previous set must still flag the originally revoked serial.
	leafKey, leafDER := buildAIKLeaf(t, ca, caKey, revoked)
	if _, err := cv.VerifyAIKCertificate(leafKey, leafDER); !errors.Is(err, crl.ErrCertificateRevoked) {
		t.Fatalf("expected ErrCertificateRevoked from preserved set, got %v", err)
	}
}

// TestCRL_ReloadWithoutPathsIsNoOp covers the SIGHUP handler contract:
// store constructed without CRL paths must treat ReloadCRLs() as
// a successful no-op so the handler can blanket-call it without
// branching on startup configuration.
func TestCRL_ReloadWithoutPathsIsNoOp(t *testing.T) {
	dir := t.TempDir()

	ca, _ := buildCA(t)
	caPath := writeCert(t, dir, ca)

	cv, err := NewCertificateVerifier([]string{caPath}, nil)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	if err := cv.ReloadCRLs(); err != nil {
		t.Fatalf("ReloadCRLs without configured paths must no-op, got %v", err)
	}
	if cv.CRLCount() != 0 {
		t.Fatalf("expected 0 CRLs after no-op reload, got %d", cv.CRLCount())
	}
}
