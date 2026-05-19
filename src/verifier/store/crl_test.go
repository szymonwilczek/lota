// SPDX-License-Identifier: MIT
// LOTA Verifier - CRL load and revocation tests

package store

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// buildCA returns a self-signed CA cert + key suitable for issuing EK
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

// buildEKLeaf issues a leaf certificate carrying the TCG EK Credential
// Profile OID so it lands in the same code path that verifyEKCertificate
// drives at runtime.
func buildEKLeaf(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, serial int64) (*x509.Certificate, []byte) {
	t.Helper()
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: "TPM EK",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(12 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidTCGEKCertificate},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("leaf parse: %v", err)
	}
	return cert, der
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

// writeCert PEM-encodes a CA cert so NewCertificateStoreWithCRL can pick
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

	_, err := NewCertificateStoreWithCRL(filepath.Join(dir, "aiks"),
		[]string{goodPath}, []string{crlPath}, false)
	if err == nil {
		t.Fatal("expected CRL load to fail: signed by untrusted CA")
	}
	if !errors.Is(err, ErrCRLNoIssuer) && !errors.Is(err, ErrCRLSignature) {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = goodKey
}

func TestCRL_RevokesEKCertificate(t *testing.T) {
	dir := t.TempDir()

	ca, caKey := buildCA(t)
	caPath := writeCert(t, dir, ca)

	// revoke serial 0x42; mint a leaf with that serial
	const revokedSerial = 0x42
	leaf, leafDER := buildEKLeaf(t, ca, caKey, revokedSerial)

	crlPath := writeCRL(t, dir, ca, caKey, time.Now().Add(time.Hour), revokedSerial)

	cs, err := NewCertificateStoreWithCRL(filepath.Join(dir, "aiks"),
		[]string{caPath}, []string{crlPath}, true)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}
	if cs.CRLCount() != 1 {
		t.Fatalf("expected 1 CRL, got %d", cs.CRLCount())
	}

	err = cs.verifyEKCertificate(leafDER)
	if !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("expected ErrCertificateRevoked, got %v", err)
	}

	_ = leaf // silence unused-warning for leaf parsed copy
}

func TestCRL_PassesUnrevokedEKCertificate(t *testing.T) {
	dir := t.TempDir()

	ca, caKey := buildCA(t)
	caPath := writeCert(t, dir, ca)

	_, leafDER := buildEKLeaf(t, ca, caKey, 0x11)
	crlPath := writeCRL(t, dir, ca, caKey, time.Now().Add(time.Hour), 0x99 /* not the leaf */)

	cs, err := NewCertificateStoreWithCRL(filepath.Join(dir, "aiks"),
		[]string{caPath}, []string{crlPath}, true)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	if err := cs.verifyEKCertificate(leafDER); err != nil {
		t.Fatalf("unrevoked leaf must verify, got %v", err)
	}
}

func TestCRL_FailsClosedWhenStale(t *testing.T) {
	dir := t.TempDir()

	ca, caKey := buildCA(t)
	caPath := writeCert(t, dir, ca)

	_, leafDER := buildEKLeaf(t, ca, caKey, 0x33)

	// NextUpdate strictly in the past => every CRL for this issuer is stale
	crlPath := writeCRL(t, dir, ca, caKey, time.Now().Add(-time.Minute), 0x99)

	cs, err := NewCertificateStoreWithCRL(filepath.Join(dir, "aiks"),
		[]string{caPath}, []string{crlPath}, true)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	err = cs.verifyEKCertificate(leafDER)
	if !errors.Is(err, ErrCRLStale) {
		t.Fatalf("expected ErrCRLStale, got %v", err)
	}
}

func TestCRL_NoCRLForIssuerIsAccepted(t *testing.T) {
	dir := t.TempDir()

	ca, caKey := buildCA(t)
	caPath := writeCert(t, dir, ca)

	_, leafDER := buildEKLeaf(t, ca, caKey, 0x55)

	// store initialized without any CRLs - revocation lookup must be a no-op
	cs, err := NewCertificateStoreWithCRL(filepath.Join(dir, "aiks"),
		[]string{caPath}, nil, true)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}
	if cs.CRLCount() != 0 {
		t.Fatalf("expected 0 CRLs, got %d", cs.CRLCount())
	}

	if err := cs.verifyEKCertificate(leafDER); err != nil {
		t.Fatalf("verifyEKCertificate must succeed when no CRL is configured, got %v", err)
	}
}

func TestCRL_AcceptsDEREncodedFile(t *testing.T) {
	dir := t.TempDir()

	ca, caKey := buildCA(t)
	caPath := writeCert(t, dir, ca)

	// emit DER directly instead of PEM
	tmpl := &x509.RevocationList{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Number:             big.NewInt(7),
		ThisUpdate:         time.Now().Add(-time.Hour),
		NextUpdate:         time.Now().Add(time.Hour),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, caKey)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}
	if bytes.HasPrefix(der, []byte("-----")) {
		t.Fatal("expected DER, got PEM-looking content")
	}
	crlPath := filepath.Join(dir, "raw.crl")
	if err := os.WriteFile(crlPath, der, 0o600); err != nil {
		t.Fatalf("write der crl: %v", err)
	}

	cs, err := NewCertificateStoreWithCRL(filepath.Join(dir, "aiks"),
		[]string{caPath}, []string{crlPath}, true)
	if err != nil {
		t.Fatalf("store init with DER CRL: %v", err)
	}
	if cs.CRLCount() != 1 {
		t.Fatalf("expected 1 DER CRL loaded, got %d", cs.CRLCount())
	}
}
