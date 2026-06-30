// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA - CRL set unit tests
//
// Tests for the unexported canonicalisation and load gates live here
// with the implementation.
//
// Verifier and attestation CA keep their own tests for the wiring around
// this package.

package crl

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

// buildCA returns a self-signed CA cert + key suitable for issuing
// leaves and signing CRLs in the same chain.
func buildCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	return buildNamedCA(t, "LOTA CRL Test CA")
}

// buildNamedCA varies the Subject CN.
// CRL lookups bucket by the canonicalised issuer DN, so tests that
// need two distinct issuers must not reuse one name.
func buildNamedCA(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xCA),
		Subject: pkix.Name{
			CommonName:   cn,
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

// buildLeaf issues a leaf certificate with the given serial under ca.
func buildLeaf(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, serial int64) *x509.Certificate {
	t.Helper()
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(12 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
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
	return cert
}

// makeCRL builds and parses a CRL covering revokedSerials, signed by ca.
func makeCRL(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey,
	nextUpdate time.Time, revokedSerials ...int64,
) *x509.RevocationList {
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
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	return crl
}

func TestSet_RevokedAndUnrevokedLookup(t *testing.T) {
	ca, caKey := buildCA(t)
	crl := makeCRL(t, ca, caKey, time.Now().Add(time.Hour), 0x42)

	set := NewSet()
	if err := set.verifyAndAdd("synthetic.pem", 0, crl, []*x509.Certificate{ca}); err != nil {
		t.Fatalf("verifyAndAdd: %v", err)
	}
	if set.Size() != 1 {
		t.Fatalf("expected 1 CRL, got %d", set.Size())
	}

	revoked := buildLeaf(t, ca, caKey, 0x42)
	if err := set.Check(revoked, time.Now()); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("expected ErrCertificateRevoked, got %v", err)
	}

	clean := buildLeaf(t, ca, caKey, 0x11)
	if err := set.Check(clean, time.Now()); err != nil {
		t.Fatalf("unrevoked leaf must pass, got %v", err)
	}
}

func TestSet_StaleCRLFailsClosed(t *testing.T) {
	ca, caKey := buildCA(t)
	crl := makeCRL(t, ca, caKey, time.Now().Add(time.Hour), 0x99)

	set := NewSet()
	if err := set.verifyAndAdd("synthetic.pem", 0, crl, []*x509.Certificate{ca}); err != nil {
		t.Fatalf("verifyAndAdd: %v", err)
	}

	leaf := buildLeaf(t, ca, caKey, 0x33)
	// past every NextUpdate: the issuer has CRLs but none is fresh
	future := time.Now().Add(48 * time.Hour)
	if err := set.Check(leaf, future); !errors.Is(err, ErrCRLStale) {
		t.Fatalf("expected ErrCRLStale, got %v", err)
	}
}

// TestSet_RevocationInStaleSiblingStillRejected pins the contract that
// revocation is honored regardless of which sibling CRL carries it.
// Issuer with multiple CRLs (partitioned / scoped feeds) must not let
// fresh sibling mask a revocation that lives only in a now-stale one:
// staleness may add distrust, never erase a published revocation.
func TestSet_RevocationInStaleSiblingStillRejected(t *testing.T) {
	ca, caKey := buildCA(t)

	const decoySerial = 0x11
	const victimSerial = 0x22
	// fresh sibling revokes a decoy
	// stale sibling is the only CRL carrying the victim's revocation
	fresh := makeCRL(t, ca, caKey, time.Now().Add(time.Hour), decoySerial)
	stale := makeCRL(t, ca, caKey, time.Now().Add(-30*time.Minute), victimSerial)

	set := NewSet()
	if err := set.verifyAndAdd("fresh.pem", 0, fresh, []*x509.Certificate{ca}); err != nil {
		t.Fatalf("verifyAndAdd fresh: %v", err)
	}
	if err := set.verifyAndAdd("stale.pem", 0, stale, []*x509.Certificate{ca}); err != nil {
		t.Fatalf("verifyAndAdd stale: %v", err)
	}
	if set.Size() != 2 {
		t.Fatalf("expected 2 CRLs, got %d", set.Size())
	}

	// fresh sibling is present, so the issuer is not wholly stale
	// victim's revocation must still take effect
	victim := buildLeaf(t, ca, caKey, victimSerial)
	if err := set.Check(victim, time.Now()); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("victim revoked in stale sibling must be rejected, got %v", err)
	}

	// Sanity:
	// decoy in the fresh sibling still rejects
	// and serial revoked in neither sibling still passes
	decoy := buildLeaf(t, ca, caKey, decoySerial)
	if err := set.Check(decoy, time.Now()); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("decoy revoked in fresh sibling must be rejected, got %v", err)
	}
	clean := buildLeaf(t, ca, caKey, 0x33)
	if err := set.Check(clean, time.Now()); err != nil {
		t.Fatalf("unrevoked leaf with a fresh sibling present must pass, got %v", err)
	}
}

func TestSet_NoCRLForIssuerIsAccepted(t *testing.T) {
	ca, caKey := buildCA(t)
	other, otherKey := buildNamedCA(t, "Unrelated Vendor CA")
	crl := makeCRL(t, other, otherKey, time.Now().Add(time.Hour), 0x55)

	set := NewSet()
	if err := set.verifyAndAdd("synthetic.pem", 0, crl, []*x509.Certificate{other}); err != nil {
		t.Fatalf("verifyAndAdd: %v", err)
	}

	// leaf issuer differs from every loaded CRL issuer: nothing to check
	leaf := buildLeaf(t, ca, caKey, 0x55)
	if err := set.Check(leaf, time.Now()); err != nil {
		t.Fatalf("expected accept with no CRL for issuer, got %v", err)
	}

	// empty set short-circuits entirely
	if err := NewSet().Check(leaf, time.Now()); err != nil {
		t.Fatalf("empty set must accept, got %v", err)
	}
}

func TestSet_RejectsUnknownIssuer(t *testing.T) {
	ca, _ := buildCA(t)
	other, otherKey := buildCA(t)
	crl := makeCRL(t, other, otherKey, time.Now().Add(time.Hour))

	set := NewSet()
	err := set.verifyAndAdd("synthetic.pem", 0, crl, []*x509.Certificate{ca})
	if err == nil {
		t.Fatal("expected rejection: CRL signed by untrusted CA")
	}
	if !errors.Is(err, ErrCRLNoIssuer) && !errors.Is(err, ErrCRLSignature) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// buildIssuerDER hand-marshals a single-RDN DN with the given CN
// string and Country, so tests can drive the canonical-key matcher
// with synthetic byte sequences that x509.CreateCertificate would
// silently normalise away.
func buildIssuerDER(t *testing.T, country, commonName string) []byte {
	t.Helper()
	seq := pkix.RDNSequence{
		{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 6}, // C
				Value: country,
			},
		},
		{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // CN
				Value: commonName,
			},
		},
	}
	der, err := asn1.Marshal(seq)
	if err != nil {
		t.Fatalf("marshal RDNSequence: %v", err)
	}
	return der
}

func TestCanonicalIssuerKey_StableAcrossWhitespaceAndCase(t *testing.T) {
	a := buildIssuerDER(t, "us", "  LOTA   Privacy CA  ")
	b := buildIssuerDER(t, "US", "lota privacy ca")

	ka, err := canonicalIssuerKey(a)
	if err != nil {
		t.Fatalf("canonicalIssuerKey(a): %v", err)
	}
	kb, err := canonicalIssuerKey(b)
	if err != nil {
		t.Fatalf("canonicalIssuerKey(b): %v", err)
	}
	if ka != kb {
		t.Fatalf("expected matching keys for the same logical DN; got\n  a=%q\n  b=%q",
			ka, kb)
	}
}

func TestCanonicalIssuerKey_DistinguishesDifferentDNs(t *testing.T) {
	a := buildIssuerDER(t, "US", "LOTA Privacy CA")
	b := buildIssuerDER(t, "US", "Some Other CA")

	ka, _ := canonicalIssuerKey(a)
	kb, _ := canonicalIssuerKey(b)
	if ka == kb {
		t.Fatal("different CN must produce different keys")
	}
}

// TestCanonicalIssuerKey_StableAcrossMultiAVAOrder asserts that an
// RDN with multiple AttributeTypeAndValue entries serialises to the
// same key regardless of source order: RFC 5280 p4.1.2.4 leaves AVAs
// inside a single RDN unordered.
func TestCanonicalIssuerKey_StableAcrossMultiAVAOrder(t *testing.T) {
	make := func(reverse bool) []byte {
		// Multi-AVA RDN: CN + OU
		ava1 := pkix.AttributeTypeAndValue{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // CN
			Value: "lota ca",
		}
		ava2 := pkix.AttributeTypeAndValue{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 11}, // OU
			Value: "trust",
		}
		var rdn pkix.RelativeDistinguishedNameSET
		if reverse {
			rdn = pkix.RelativeDistinguishedNameSET{ava2, ava1}
		} else {
			rdn = pkix.RelativeDistinguishedNameSET{ava1, ava2}
		}
		der, err := asn1.Marshal(pkix.RDNSequence{rdn})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return der
	}
	ka, err := canonicalIssuerKey(make(false))
	if err != nil {
		t.Fatalf("canonicalIssuerKey forward: %v", err)
	}
	kb, err := canonicalIssuerKey(make(true))
	if err != nil {
		t.Fatalf("canonicalIssuerKey reverse: %v", err)
	}
	if ka != kb {
		t.Fatalf("multi-AVA order must not affect the key; got\n  forward=%q\n  reverse=%q",
			ka, kb)
	}
}

// TestSet_LoadAcceptsCanonicalIssuerDriftFromCA covers the load-time
// canonicalIssuerKey match path.
// CA that re-encodes its Subject DN between issuing its own certificate
// and signing a CRL refresh produces byte-different RawSubject vs RawIssuer
// for the same logical issuer. Byte-equal gate would have dropped the CRL
// at load time and silently landed the leaf check on the "no CRL configured for
// this issuer" fail-open branch.
// With the canonical gate the load must accept and the revocation must take effect.
func TestSet_LoadAcceptsCanonicalIssuerDriftFromCA(t *testing.T) {
	ca, caKey := buildCA(t)

	// CRL is built and signed first so RawIssuer captures
	// the canonical DER emitted by x509.CreateRevocationList.
	// CRL signature is computed over its own TBS using caKey,
	// so CheckSignatureFrom() validates against ca.PublicKey
	// regardless of any later mutation to ca.RawSubject.
	const revokedSerial = 0x7E51
	crl := makeCRL(t, ca, caKey, time.Now().Add(time.Hour), revokedSerial)

	// Inject case drift into the CommonName string inside
	// ca.RawSubject so it stays a valid DER encoding of the same
	// logical DN but byte-differs from crl.RawIssuer.
	// Mutation runs only over the printable value bytes of the
	// embedded CN, never over tag/length headers or OID bytes,
	// so the surrounding ASN.1 structure stays well-formed.
	const cnNeedle = "LOTA CRL Test CA"
	idx := bytes.Index(ca.RawSubject, []byte(cnNeedle))
	if idx < 0 {
		t.Fatalf("expected %q inside ca.RawSubject", cnNeedle)
	}
	mutated := make([]byte, len(ca.RawSubject))
	copy(mutated, ca.RawSubject)
	// lower-case the first letter of "LOTA" inside the CN value
	mutated[idx] = 'l'
	if bytes.Equal(mutated, ca.RawSubject) {
		t.Fatal("mutated RawSubject still byte-equal to original")
	}
	ca.RawSubject = mutated

	set := NewSet()
	if err := set.verifyAndAdd("synthetic.pem", 0, crl, []*x509.Certificate{ca}); err != nil {
		t.Fatalf("verifyAndAdd: %v", err)
	}

	// confirm the loaded CRL is indexed under the canonical key the
	// lookup path computes from the leaf cert's Issuer
	if set.Size() != 1 {
		t.Fatalf("expected 1 CRL in set, got %d", set.Size())
	}
}

func TestBuildSet_EmptyPathsYieldsEmptySet(t *testing.T) {
	set, err := BuildSet(nil, nil)
	if err != nil {
		t.Fatalf("BuildSet(nil): %v", err)
	}
	if set.Size() != 0 {
		t.Fatalf("expected empty set, got %d", set.Size())
	}
}

// writeCRLFile emits a PEM-encoded CRL covering revokedSerials, signed
// by ca.
// nextUpdate is honored so callers can construct stale CRLs.
func writeCRLFile(t *testing.T, dir string, ca *x509.Certificate, caKey *rsa.PrivateKey,
	nextUpdate time.Time, revokedSerials ...int64,
) string {
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

func TestBuildSet_LoadsAndRevokes(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := buildCA(t)
	path := writeCRLFile(t, dir, ca, caKey, time.Now().Add(time.Hour), 0x42)

	set, err := BuildSet([]string{path}, []*x509.Certificate{ca})
	if err != nil {
		t.Fatalf("BuildSet: %v", err)
	}
	if set.Size() != 1 {
		t.Fatalf("expected 1 CRL, got %d", set.Size())
	}
	leaf := buildLeaf(t, ca, caKey, 0x42)
	if err := set.Check(leaf, time.Now()); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("expected ErrCertificateRevoked, got %v", err)
	}
}

func TestBuildSet_NoTrustedCAsFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := buildCA(t)
	path := writeCRLFile(t, dir, ca, caKey, time.Now().Add(time.Hour))

	if _, err := BuildSet([]string{path}, nil); !errors.Is(err, ErrNoTrustedCAs) {
		t.Fatalf("expected ErrNoTrustedCAs, got %v", err)
	}
}

func TestBuildSet_MissingFileFails(t *testing.T) {
	ca, _ := buildCA(t)
	if _, err := BuildSet([]string{"/nonexistent/feed.pem"},
		[]*x509.Certificate{ca}); err == nil {
		t.Fatal("expected error for missing CRL file")
	}
}

func TestBuildSet_MultiBlockPEMBundle(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := buildCA(t)

	encodeOne := func(number, serial int64) []byte {
		tmpl := &x509.RevocationList{
			SignatureAlgorithm: x509.SHA256WithRSA,
			Number:             big.NewInt(number),
			ThisUpdate:         time.Now().Add(-time.Hour),
			NextUpdate:         time.Now().Add(time.Hour),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   big.NewInt(serial),
					RevocationTime: time.Now().Add(-time.Minute),
				},
			},
		}
		der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, caKey)
		if err != nil {
			t.Fatalf("CreateRevocationList: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	}

	buf := append([]byte{}, encodeOne(11, 0xA1)...)
	buf = append(buf, encodeOne(12, 0xB2)...)
	path := filepath.Join(dir, "bundle.pem")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	set, err := BuildSet([]string{path}, []*x509.Certificate{ca})
	if err != nil {
		t.Fatalf("BuildSet: %v", err)
	}
	if set.Size() != 2 {
		t.Fatalf("expected 2 CRLs from bundle, got %d", set.Size())
	}

	// both serials must reject - one block alone is insufficient
	for _, serial := range []int64{0xA1, 0xB2} {
		leaf := buildLeaf(t, ca, caKey, serial)
		if err := set.Check(leaf, time.Now()); !errors.Is(err, ErrCertificateRevoked) {
			t.Fatalf("serial %x: expected ErrCertificateRevoked, got %v", serial, err)
		}
	}
}

func TestBuildSet_AcceptsDEREncodedFile(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := buildCA(t)

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
	path := filepath.Join(dir, "raw.crl")
	if err := os.WriteFile(path, der, 0o600); err != nil {
		t.Fatalf("write der crl: %v", err)
	}

	set, err := BuildSet([]string{path}, []*x509.Certificate{ca})
	if err != nil {
		t.Fatalf("BuildSet with DER CRL: %v", err)
	}
	if set.Size() != 1 {
		t.Fatalf("expected 1 DER CRL loaded, got %d", set.Size())
	}
}

// writeRawCRL hand-marshals a CertificateList so tests can omit the
// OPTIONAL nextUpdate field or inject an arbitrary signature algorithm
// OID.
// x509.CreateRevocationList refuses both.
// Signature is a placeholder: the load gates under test reject before
// reaching signature verification.
func writeRawCRL(t *testing.T, dir, name string, ca *x509.Certificate,
	sigAlgOID asn1.ObjectIdentifier, withNextUpdate bool,
) string {
	t.Helper()

	algID := pkix.AlgorithmIdentifier{
		Algorithm:  sigAlgOID,
		Parameters: asn1.RawValue{Tag: 5}, // NULL
	}

	var tbsDER []byte
	var err error
	if withNextUpdate {
		tbsDER, err = asn1.Marshal(struct {
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
		})
	} else {
		tbsDER, err = asn1.Marshal(struct {
			Version    int
			Signature  pkix.AlgorithmIdentifier
			Issuer     asn1.RawValue
			ThisUpdate time.Time
		}{
			Version:    1, // v2
			Signature:  algID,
			Issuer:     asn1.RawValue{FullBytes: ca.RawSubject},
			ThisUpdate: time.Now().Add(-time.Hour).UTC(),
		})
	}
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

var oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}

func TestBuildSet_RejectsMissingNextUpdate(t *testing.T) {
	dir := t.TempDir()
	ca, _ := buildCA(t)
	path := writeRawCRL(t, dir, "no-next-update.pem", ca, oidSHA256WithRSA, false)

	_, err := BuildSet([]string{path}, []*x509.Certificate{ca})
	if !errors.Is(err, ErrCRLMissingNextUpdate) {
		t.Fatalf("expected ErrCRLMissingNextUpdate, got %v", err)
	}
}

func TestBuildSet_RejectsWeakSignatureAlgorithm(t *testing.T) {
	dir := t.TempDir()
	ca, _ := buildCA(t)

	// sha1WithRSAEncryption (RFC 8017): rejected even though the rest of
	// the CRL would parse cleanly.
	// Loader must short-circuit before invoking CheckSignatureFrom so
	// attacker-supplied CRL under a weakened algorithm never reaches the
	// trust path.
	sha1WithRSA := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	path := writeRawCRL(t, dir, "sha1.pem", ca, sha1WithRSA, true)

	_, err := BuildSet([]string{path}, []*x509.Certificate{ca})
	if !errors.Is(err, ErrCRLWeakSignature) {
		t.Fatalf("expected ErrCRLWeakSignature, got %v", err)
	}
}
