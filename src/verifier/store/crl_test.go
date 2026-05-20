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

// writeCRLNoNextUpdate emits a syntactically valid CertificateList whose
// TBSCertList omits the OPTIONAL nextUpdate field. CreateRevocationList in
// crypto/x509 refuses to do this (NextUpdate is required at the template
// layer), so the CRL is hand-marshaled via encoding/asn1. The signature is
// a placeholder: loadAndVerify rejects on the missing NextUpdate before
// reaching signature verification, which is the contract under test.
func writeCRLNoNextUpdate(t *testing.T, dir string, ca *x509.Certificate) string {
	t.Helper()

	sigAlgOID := pkix.AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, // sha256WithRSAEncryption
		Parameters: asn1.RawValue{Tag: 5},                              // NULL
	}

	tbs := struct {
		Version    int
		Signature  pkix.AlgorithmIdentifier
		Issuer     asn1.RawValue
		ThisUpdate time.Time
	}{
		Version:    1, // v2
		Signature:  sigAlgOID,
		Issuer:     asn1.RawValue{FullBytes: ca.RawSubject},
		ThisUpdate: time.Now().Add(-time.Hour).UTC(),
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("marshal tbs: %v", err)
	}

	crl := struct {
		TBSCertList        asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertList:        asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: sigAlgOID,
		SignatureValue:     asn1.BitString{Bytes: []byte{0x00}, BitLength: 8},
	}
	der, err := asn1.Marshal(crl)
	if err != nil {
		t.Fatalf("marshal crl: %v", err)
	}

	buf := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	path := filepath.Join(dir, "no-next-update.pem")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// writeBundledCRL emits a single PEM file containing two
// independently-signed CRLs concatenated back-to-back. Production
// operators receive TPM manufacturer feeds shaped this way; the
// loader must consume every BEGIN/END pair and not silently stop
// after the first one.
func writeBundledCRL(t *testing.T, dir string, ca *x509.Certificate,
	caKey *rsa.PrivateKey, nextUpdate time.Time,
	firstSerials, secondSerials []int64) string {
	t.Helper()

	encodeOne := func(number int64, entries []int64) []byte {
		var revoked []x509.RevocationListEntry
		for _, s := range entries {
			revoked = append(revoked, x509.RevocationListEntry{
				SerialNumber:   big.NewInt(s),
				RevocationTime: time.Now().Add(-time.Minute),
			})
		}
		tmpl := &x509.RevocationList{
			SignatureAlgorithm:        x509.SHA256WithRSA,
			Number:                    big.NewInt(number),
			ThisUpdate:                time.Now().Add(-time.Hour),
			NextUpdate:                nextUpdate,
			RevokedCertificateEntries: revoked,
		}
		der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, caKey)
		if err != nil {
			t.Fatalf("CreateRevocationList: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	}

	buf := append([]byte{}, encodeOne(11, firstSerials)...)
	buf = append(buf, encodeOne(12, secondSerials)...)

	path := filepath.Join(dir, "bundle.pem")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

func TestCRL_LoadAcceptsMultiBlockPEMBundle(t *testing.T) {
	dir := t.TempDir()

	ca, caKey := buildCA(t)
	caPath := writeCert(t, dir, ca)

	const firstSerial = 0xA1
	const secondSerial = 0xB2

	bundlePath := writeBundledCRL(t, dir, ca, caKey,
		time.Now().Add(time.Hour),
		[]int64{firstSerial}, []int64{secondSerial})

	cs, err := NewCertificateStoreWithCRL(filepath.Join(dir, "aiks"),
		[]string{caPath}, []string{bundlePath}, true)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}
	if cs.CRLCount() != 2 {
		t.Fatalf("expected 2 CRLs loaded from bundle, got %d", cs.CRLCount())
	}

	// both serials must reject - one block alone is insufficient.
	_, leaf1 := buildEKLeaf(t, ca, caKey, firstSerial)
	if err := cs.verifyEKCertificate(leaf1); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("first-block serial: expected ErrCertificateRevoked, got %v", err)
	}
	_, leaf2 := buildEKLeaf(t, ca, caKey, secondSerial)
	if err := cs.verifyEKCertificate(leaf2); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("second-block serial: expected ErrCertificateRevoked, got %v", err)
	}
}

// writeCRLWithSigAlgOID emits a syntactically valid CertificateList
// whose signatureAlgorithm OID is caller-controlled, so the test can
// inject a CRL signed under a weakened algorithm (sha1WithRSAEncryption,
// ...) and observe the loader's allow-list rejection. NextUpdate is
// honored so the staleness gate does not short-circuit the algorithm
// check.
func writeCRLWithSigAlgOID(t *testing.T, dir string, ca *x509.Certificate,
	sigAlgOID asn1.ObjectIdentifier, name string) string {
	t.Helper()

	algID := pkix.AlgorithmIdentifier{
		Algorithm:  sigAlgOID,
		Parameters: asn1.RawValue{Tag: 5}, // NULL
	}

	tbs := struct {
		Version    int
		Signature  pkix.AlgorithmIdentifier
		Issuer     asn1.RawValue
		ThisUpdate time.Time
		NextUpdate time.Time
	}{
		Version:    1, // v2
		Signature:  algID,
		Issuer:     asn1.RawValue{FullBytes: ca.RawSubject},
		ThisUpdate: time.Now().Add(-time.Hour).UTC(),
		NextUpdate: time.Now().Add(time.Hour).UTC(),
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("marshal tbs: %v", err)
	}

	crl := struct {
		TBSCertList        asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertList:        asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: algID,
		SignatureValue:     asn1.BitString{Bytes: []byte{0x00}, BitLength: 8},
	}
	der, err := asn1.Marshal(crl)
	if err != nil {
		t.Fatalf("marshal crl: %v", err)
	}

	buf := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestCRL_LoadRejectsWeakSignatureAlgorithm(t *testing.T) {
	dir := t.TempDir()

	ca, _ := buildCA(t)
	caPath := writeCert(t, dir, ca)

	// sha1WithRSAEncryption (RFC 8017): rejected even though the rest of
	// the CRL would parse cleanly. The loader must short-circuit before
	// invoking CheckSignatureFrom so an attacker-supplied CRL under a
	// weakened algorithm never reaches the trust path.
	sha1WithRSA := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	crlPath := writeCRLWithSigAlgOID(t, dir, ca, sha1WithRSA, "sha1.pem")

	_, err := NewCertificateStoreWithCRL(filepath.Join(dir, "aiks"),
		[]string{caPath}, []string{crlPath}, false)
	if err == nil {
		t.Fatal("expected CRL load to fail: SHA-1 signature algorithm")
	}
	if !errors.Is(err, ErrCRLWeakSignature) {
		t.Fatalf("expected ErrCRLWeakSignature, got %v", err)
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

	cs, err := NewCertificateStoreWithCRL(filepath.Join(dir, "aiks"),
		[]string{caPath}, []string{crlPath}, true)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	// initial state: initialSerial revoked, refreshedSerial accepted.
	_, initialLeafDER := buildEKLeaf(t, ca, caKey, initialSerial)
	if err := cs.verifyEKCertificate(initialLeafDER); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("pre-reload: expected ErrCertificateRevoked for serial %x, got %v",
			initialSerial, err)
	}
	_, refreshedLeafDER := buildEKLeaf(t, ca, caKey, refreshedSerial)
	if err := cs.verifyEKCertificate(refreshedLeafDER); err != nil {
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

	if err := cs.ReloadCRLs(); err != nil {
		t.Fatalf("ReloadCRLs: %v", err)
	}
	if cs.CRLCount() != 1 {
		t.Fatalf("expected 1 CRL after reload, got %d", cs.CRLCount())
	}

	// post-reload: refreshedSerial rejects, initialSerial accepted.
	if err := cs.verifyEKCertificate(refreshedLeafDER); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("post-reload: expected ErrCertificateRevoked for serial %x, got %v",
			refreshedSerial, err)
	}
	if err := cs.verifyEKCertificate(initialLeafDER); err != nil {
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

	cs, err := NewCertificateStoreWithCRL(filepath.Join(dir, "aiks"),
		[]string{caPath}, []string{crlPath}, true)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	// overwrite the file with a CRL signed by an unrelated CA: signature
	// verification must fail and ReloadCRLs() return an error.
	other, otherKey := buildCA(t)
	_ = writeCRL(t, dir, other, otherKey, time.Now().Add(time.Hour),
		revoked)

	if err := cs.ReloadCRLs(); err == nil {
		t.Fatal("expected ReloadCRLs to reject CRL signed by untrusted CA")
	}

	// previous set must still flag the originally revoked serial.
	_, leafDER := buildEKLeaf(t, ca, caKey, revoked)
	if err := cs.verifyEKCertificate(leafDER); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("expected ErrCertificateRevoked from preserved set, got %v", err)
	}
}

func TestCRL_LoadRejectsMissingNextUpdate(t *testing.T) {
	dir := t.TempDir()

	ca, _ := buildCA(t)
	caPath := writeCert(t, dir, ca)

	crlPath := writeCRLNoNextUpdate(t, dir, ca)

	_, err := NewCertificateStoreWithCRL(filepath.Join(dir, "aiks"),
		[]string{caPath}, []string{crlPath}, false)
	if err == nil {
		t.Fatal("expected CRL load to fail: missing NextUpdate")
	}
	if !errors.Is(err, ErrCRLMissingNextUpdate) {
		t.Fatalf("expected ErrCRLMissingNextUpdate, got %v", err)
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
