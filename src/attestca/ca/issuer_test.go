// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

	"github.com/szymonwilczek/lota/crl"
)

type certAndKey struct {
	cert *x509.Certificate
	der  []byte
	key  crypto.Signer
}

func mustSerial(tb testing.TB) *big.Int {
	tb.Helper()
	s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		tb.Fatalf("serial: %v", err)
	}
	return s
}

func makeRoot(tb testing.TB, cn string) certAndKey {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("root key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          mustSerial(tb),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		tb.Fatalf("root cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return certAndKey{cert: cert, der: der, key: key}
}

// makeEKCert mints an RSA EK leaf signed by root, carrying the TCG EK OID
// in the requested placement.
func makeEKCert(tb testing.TB, root certAndKey, opts func(*x509.Certificate)) ([]byte, *rsa.PublicKey) {
	tb.Helper()
	ekKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("EK key: %v", err)
	}
	ekPolicyOID, err := x509.OIDFromInts([]uint64{2, 23, 133, 8, 1})
	if err != nil {
		tb.Fatalf("EK policy OID: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: mustSerial(tb),
		Subject:      pkix.Name{CommonName: "tpm-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		Policies:     []x509.OID{ekPolicyOID},
	}
	if opts != nil {
		opts(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, &ekKey.PublicKey, root.key)
	if err != nil {
		tb.Fatalf("EK cert: %v", err)
	}
	return der, &ekKey.PublicKey
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func makeLOTACAPEM(tb testing.TB) (caCertPEM, caKeyPEM []byte) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          mustSerial(tb),
		Subject:               pkix.Name{CommonName: "lota-attest-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		tb.Fatalf("CA cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		tb.Fatalf("marshal CA key: %v", err)
	}
	return pemBlock("CERTIFICATE", der), pemBlock("PRIVATE KEY", keyDER)
}

func newTestIssuer(tb testing.TB, root certAndKey) *Issuer {
	tb.Helper()
	caCertPEM, caKeyPEM := makeLOTACAPEM(tb)
	is, err := NewIssuer(IssuerConfig{
		CACertPEM:  caCertPEM,
		CAKeyPEM:   caKeyPEM,
		EKRootPEMs: [][]byte{pemBlock("CERTIFICATE", root.der)},
	})
	if err != nil {
		tb.Fatalf("NewIssuer: %v", err)
	}
	return is
}

func TestVerifyEKCertificateAcceptsPolicyOID(t *testing.T) {
	root := makeRoot(t, "tpm-vendor-root")
	is := newTestIssuer(t, root)

	ekDER, _ := makeEKCert(t, root, nil)
	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); err != nil {
		t.Fatalf("rejected valid EK certificate: %v", err)
	}
}

func TestVerifyEKCertificateAcceptsEKUOID(t *testing.T) {
	root := makeRoot(t, "tpm-vendor-root")
	is := newTestIssuer(t, root)

	// EK OID carried as an unknown extended key usage instead of a policy
	ekDER, _ := makeEKCert(t, root, func(c *x509.Certificate) {
		c.Policies = nil
		c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidTCGEKCertificate}
	})
	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); err != nil {
		t.Fatalf("rejected EK certificate with EKU-placed OID: %v", err)
	}
}

// ECC endorsement key is well-formed and chains to a trusted root, but
// credential activation wraps the secret to an RSA EK, so enrollment must
// refuse it with ErrEKKeyType (not a chain or OID error) and name the type
func TestVerifyEKCertificateRejectsECCKey(t *testing.T) {
	root := makeRoot(t, "tpm-vendor-root")
	is := newTestIssuer(t, root)

	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("EK key: %v", err)
	}
	ekPolicyOID, err := x509.OIDFromInts([]uint64{2, 23, 133, 8, 1})
	if err != nil {
		t.Fatalf("EK policy OID: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: mustSerial(t),
		Subject:      pkix.Name{CommonName: "tpm-ek-ecc"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		Policies:     []x509.OID{ekPolicyOID},
	}
	ekDER, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, &ekKey.PublicKey, root.key)
	if err != nil {
		t.Fatalf("ECC EK cert: %v", err)
	}

	_, err = is.VerifyEKCertificate(ekDER, time.Now())
	if !errors.Is(err, ErrEKKeyType) {
		t.Fatalf("expected ErrEKKeyType for ECC EK, got %v", err)
	}
}

func TestVerifyEKCertificateRejectsUntrustedRoot(t *testing.T) {
	trusted := makeRoot(t, "trusted-vendor")
	rogue := makeRoot(t, "rogue-vendor")
	is := newTestIssuer(t, trusted)

	ekDER, _ := makeEKCert(t, rogue, nil)
	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); err == nil {
		t.Fatal("accepted EK certificate from an untrusted root")
	}
}

func TestVerifyEKCertificateRejectsMissingOID(t *testing.T) {
	root := makeRoot(t, "tpm-vendor-root")
	is := newTestIssuer(t, root)

	ekDER, _ := makeEKCert(t, root, func(c *x509.Certificate) { c.Policies = nil })
	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); err == nil {
		t.Fatal("accepted EK certificate without the TCG OID")
	}
}

func TestVerifyEKCertificateRejectsExpired(t *testing.T) {
	root := makeRoot(t, "tpm-vendor-root")
	is := newTestIssuer(t, root)

	ekDER, _ := makeEKCert(t, root, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-48 * time.Hour)
		c.NotAfter = time.Now().Add(-24 * time.Hour)
	})
	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); err == nil {
		t.Fatal("accepted expired EK certificate")
	}
}

func TestIssueAIKCertificateChainsToCA(t *testing.T) {
	root := makeRoot(t, "tpm-vendor-root")
	is := newTestIssuer(t, root)

	aikKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("AIK key: %v", err)
	}

	aikCertDER, err := is.IssueAIKCertificate(&aikKey.PublicKey, "device-abc123", "", time.Now())
	if err != nil {
		t.Fatalf("IssueAIKCertificate: %v", err)
	}

	aikCert, err := x509.ParseCertificate(aikCertDER)
	if err != nil {
		t.Fatalf("parse issued AIK cert: %v", err)
	}

	caCert, _ := x509.ParseCertificate(is.CACertDER())
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	if _, err := aikCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("issued AIK cert does not chain to CA: %v", err)
	}

	certPub, ok := aikCert.PublicKey.(*rsa.PublicKey)
	if !ok || certPub.N.Cmp(aikKey.N) != 0 {
		t.Fatal("issued AIK cert does not carry the AIK public key")
	}
}

func TestNewIssuerRejectsKeyMismatch(t *testing.T) {
	caCertPEM, _ := makeLOTACAPEM(t)
	_, otherKeyPEM := makeLOTACAPEM(t)
	root := makeRoot(t, "tpm-vendor-root")

	_, err := NewIssuer(IssuerConfig{
		CACertPEM:  caCertPEM,
		CAKeyPEM:   otherKeyPEM,
		EKRootPEMs: [][]byte{pemBlock("CERTIFICATE", root.der)},
	})
	if err == nil {
		t.Fatal("accepted CA cert/key mismatch")
	}
}

// signerFromPEM parses a PKCS#8 PEM key into a crypto.Signer, standing in
// for an external (HSM) signer the production path supplies.
func signerFromPEM(t *testing.T, keyPEM []byte) crypto.Signer {
	t.Helper()
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("no PEM block in test key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse PKCS#8 key: %v", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("test key is not a crypto.Signer")
	}
	return signer
}

func TestNewIssuerAcceptsExternalSigner(t *testing.T) {
	caCertPEM, caKeyPEM := makeLOTACAPEM(t)
	root := makeRoot(t, "tpm-vendor-root")

	// CASigner stands in for an HSM-held key
	// no PEM key material is given
	is, err := NewIssuer(IssuerConfig{
		CACertPEM:  caCertPEM,
		CASigner:   signerFromPEM(t, caKeyPEM),
		EKRootPEMs: [][]byte{pemBlock("CERTIFICATE", root.der)},
	})
	if err != nil {
		t.Fatalf("NewIssuer with external signer: %v", err)
	}

	aikKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("AIK key: %v", err)
	}
	aikCertDER, err := is.IssueAIKCertificate(&aikKey.PublicKey, "device-hsm", "", time.Now())
	if err != nil {
		t.Fatalf("IssueAIKCertificate via external signer: %v", err)
	}

	aikCert, err := x509.ParseCertificate(aikCertDER)
	if err != nil {
		t.Fatalf("parse issued AIK cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(is.CACertDER())
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := aikCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("AIK cert from external signer does not chain to CA: %v", err)
	}
}

func TestNewIssuerExternalSignerRejectsMismatch(t *testing.T) {
	caCertPEM, _ := makeLOTACAPEM(t)
	_, otherKeyPEM := makeLOTACAPEM(t)
	root := makeRoot(t, "tpm-vendor-root")

	// signer whose public key does not match the CA certificate
	// must be rejected just like an on-disk mismatch
	_, err := NewIssuer(IssuerConfig{
		CACertPEM:  caCertPEM,
		CASigner:   signerFromPEM(t, otherKeyPEM),
		EKRootPEMs: [][]byte{pemBlock("CERTIFICATE", root.der)},
	})
	if err == nil {
		t.Fatal("accepted external signer that does not match the CA certificate")
	}
}

func TestNewIssuerSignerTakesPrecedenceOverPEM(t *testing.T) {
	caCertPEM, caKeyPEM := makeLOTACAPEM(t)
	_, otherKeyPEM := makeLOTACAPEM(t)
	root := makeRoot(t, "tpm-vendor-root")

	// matching CASigner must win over a non-matching CAKeyPEM,
	// proving the PEM path is ignored entirely when a signer is supplied
	_, err := NewIssuer(IssuerConfig{
		CACertPEM:  caCertPEM,
		CAKeyPEM:   otherKeyPEM,
		CASigner:   signerFromPEM(t, caKeyPEM),
		EKRootPEMs: [][]byte{pemBlock("CERTIFICATE", root.der)},
	})
	if err != nil {
		t.Fatalf("external signer did not take precedence over PEM: %v", err)
	}
}

func TestNewIssuerRequiresEKRoots(t *testing.T) {
	caCertPEM, caKeyPEM := makeLOTACAPEM(t)
	_, err := NewIssuer(IssuerConfig{CACertPEM: caCertPEM, CAKeyPEM: caKeyPEM})
	if err == nil {
		t.Fatal("accepted issuer with no EK roots")
	}
}

func TestVerifyEKCertificateIgnoresTPMCriticalExtensions(t *testing.T) {
	root := makeRoot(t, "tpm-vendor-root")
	is := newTestIssuer(t, root)

	// Genuine EK certificates mark TCG extensions critical
	// Go cannot process them
	// Verifier must still accept the certificate
	ekDER, _ := makeEKCert(t, root, func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 9}, Critical: true, Value: []byte{0x30, 0x00}},
		}
	})
	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); err != nil {
		t.Fatalf("rejected EK cert with a critical TPM extension: %v", err)
	}
}

// writeEKCRL emits a PEM CRL signed by root covering revokedSerials.
// nextUpdate is honored so tests can construct stale feeds.
func writeEKCRL(tb testing.TB, dir string, root certAndKey,
	nextUpdate time.Time, revokedSerials ...*big.Int,
) string {
	tb.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range revokedSerials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   s,
			RevocationTime: time.Now().Add(-time.Minute),
		})
	}
	tmpl := &x509.RevocationList{
		SignatureAlgorithm:        x509.ECDSAWithSHA256,
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, root.cert, root.key)
	if err != nil {
		tb.Fatalf("CreateRevocationList: %v", err)
	}
	path := filepath.Join(dir, "ek.crl")
	buf := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		tb.Fatalf("write CRL: %v", err)
	}
	return path
}

func newTestIssuerWithCRLs(tb testing.TB, root certAndKey, crlPaths []string) *Issuer {
	tb.Helper()
	caCertPEM, caKeyPEM := makeLOTACAPEM(tb)
	is, err := NewIssuer(IssuerConfig{
		CACertPEM:  caCertPEM,
		CAKeyPEM:   caKeyPEM,
		EKRootPEMs: [][]byte{pemBlock("CERTIFICATE", root.der)},
		EKCRLPaths: crlPaths,
	})
	if err != nil {
		tb.Fatalf("NewIssuer: %v", err)
	}
	return is
}

func TestVerifyEKCertificateRejectsRevokedEK(t *testing.T) {
	dir := t.TempDir()
	root := makeRoot(t, "tpm-manufacturer")
	ekDER, _ := makeEKCert(t, root, nil)
	ekCert, err := x509.ParseCertificate(ekDER)
	if err != nil {
		t.Fatalf("parse EK: %v", err)
	}

	path := writeEKCRL(t, dir, root, time.Now().Add(time.Hour), ekCert.SerialNumber)
	is := newTestIssuerWithCRLs(t, root, []string{path})

	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); !errors.Is(err, crl.ErrCertificateRevoked) {
		t.Fatalf("expected crl.ErrCertificateRevoked, got %v", err)
	}
}

func TestVerifyEKCertificateAcceptsUnrevokedEK(t *testing.T) {
	dir := t.TempDir()
	root := makeRoot(t, "tpm-manufacturer")
	ekDER, _ := makeEKCert(t, root, nil)

	path := writeEKCRL(t, dir, root, time.Now().Add(time.Hour), mustSerial(t))
	is := newTestIssuerWithCRLs(t, root, []string{path})

	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); err != nil {
		t.Fatalf("unrevoked EK must verify, got %v", err)
	}
}

func TestVerifyEKCertificateStaleCRLFailsClosed(t *testing.T) {
	dir := t.TempDir()
	root := makeRoot(t, "tpm-manufacturer")
	ekDER, _ := makeEKCert(t, root, nil)

	path := writeEKCRL(t, dir, root, time.Now().Add(-time.Minute), mustSerial(t))
	is := newTestIssuerWithCRLs(t, root, []string{path})

	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); !errors.Is(err, crl.ErrCRLStale) {
		t.Fatalf("expected crl.ErrCRLStale, got %v", err)
	}
}

func TestNewIssuerRejectsCRLFromUnknownIssuer(t *testing.T) {
	dir := t.TempDir()
	root := makeRoot(t, "tpm-manufacturer")
	other := makeRoot(t, "unrelated-ca")

	// CRL signed by a CA outside the EK trust bundle must be refused at
	// startup so a misconfigured feed surfaces immediately
	path := writeEKCRL(t, dir, other, time.Now().Add(time.Hour))
	caCertPEM, caKeyPEM := makeLOTACAPEM(t)
	_, err := NewIssuer(IssuerConfig{
		CACertPEM:  caCertPEM,
		CAKeyPEM:   caKeyPEM,
		EKRootPEMs: [][]byte{pemBlock("CERTIFICATE", root.der)},
		EKCRLPaths: []string{path},
	})
	if err == nil {
		t.Fatal("expected NewIssuer to reject CRL signed outside the EK bundle")
	}
}

// TestReloadEKCRLsHotSwap covers the SIGHUP path:
// CRL file is rewritten in place with a different revoked serial,
// ReloadEKCRLs() swaps the feed, and a bad refresh keeps the previous set.
func TestReloadEKCRLsHotSwap(t *testing.T) {
	dir := t.TempDir()
	root := makeRoot(t, "tpm-manufacturer")
	ekDER, _ := makeEKCert(t, root, nil)
	ekCert, err := x509.ParseCertificate(ekDER)
	if err != nil {
		t.Fatalf("parse EK: %v", err)
	}

	// initial feed does not list the EK
	path := writeEKCRL(t, dir, root, time.Now().Add(time.Hour), mustSerial(t))
	is := newTestIssuerWithCRLs(t, root, []string{path})
	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); err != nil {
		t.Fatalf("pre-reload: EK must verify, got %v", err)
	}

	// refreshed feed revokes it (writeEKCRL reuses the same file name)
	_ = writeEKCRL(t, dir, root, time.Now().Add(time.Hour), ekCert.SerialNumber)
	if err := is.ReloadEKCRLs(); err != nil {
		t.Fatalf("ReloadEKCRLs: %v", err)
	}
	if is.EKCRLCount() != 1 {
		t.Fatalf("expected 1 CRL after reload, got %d", is.EKCRLCount())
	}
	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); !errors.Is(err, crl.ErrCertificateRevoked) {
		t.Fatalf("post-reload: expected crl.ErrCertificateRevoked, got %v", err)
	}

	// refresh signed by an untrusted CA must fail and keep the revoking set active
	other := makeRoot(t, "unrelated-ca")
	_ = writeEKCRL(t, dir, other, time.Now().Add(time.Hour))
	if err := is.ReloadEKCRLs(); err == nil {
		t.Fatal("expected ReloadEKCRLs to reject feed signed outside the EK bundle")
	}
	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); !errors.Is(err, crl.ErrCertificateRevoked) {
		t.Fatalf("after failed reload: expected preserved revocation, got %v", err)
	}
}

// makeIntermediate mints a CA certificate signed by parent, standing in
// for a manufacturer's EK-issuing intermediate.
func makeIntermediate(tb testing.TB, parent certAndKey, cn string) certAndKey {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("intermediate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          mustSerial(tb),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, key.Public(), parent.key)
	if err != nil {
		tb.Fatalf("intermediate cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return certAndKey{cert: cert, der: der, key: key}
}

// TestVerifyEKCertificateChainsThroughBundledIntermediate covers the
// common manufacturer shape leaf -> intermediate -> root:
// With both CA certificates in the bundle the leaf must verify.
// With the root alone the chain cannot build and the leaf must be refused.
func TestVerifyEKCertificateChainsThroughBundledIntermediate(t *testing.T) {
	root := makeRoot(t, "tpm-vendor-root")
	inter := makeIntermediate(t, root, "tpm-vendor-ek-intermediate")
	ekDER, _ := makeEKCert(t, inter, nil)

	caCertPEM, caKeyPEM := makeLOTACAPEM(t)
	full, err := NewIssuer(IssuerConfig{
		CACertPEM: caCertPEM,
		CAKeyPEM:  caKeyPEM,
		EKRootPEMs: [][]byte{
			pemBlock("CERTIFICATE", root.der),
			pemBlock("CERTIFICATE", inter.der),
		},
	})
	if err != nil {
		t.Fatalf("NewIssuer (root+intermediate): %v", err)
	}
	if _, err := full.VerifyEKCertificate(ekDER, time.Now()); err != nil {
		t.Fatalf("two-level chain with bundled intermediate must verify, got %v", err)
	}

	rootOnly := newTestIssuer(t, root)
	if _, err := rootOnly.VerifyEKCertificate(ekDER, time.Now()); !errors.Is(err, ErrEKChain) {
		t.Fatalf("missing intermediate must fail the chain, got %v", err)
	}
}

// TestVerifyEKCertificateAcceptsIntermediateOnlyAnchor pins only the
// issuing intermediate:
// deliberate trust narrowing (trust this manufacturer branch, not
// everything under the root) that the anchor semantics must keep working.
func TestVerifyEKCertificateAcceptsIntermediateOnlyAnchor(t *testing.T) {
	root := makeRoot(t, "tpm-vendor-root")
	inter := makeIntermediate(t, root, "tpm-vendor-ek-intermediate")
	ekDER, _ := makeEKCert(t, inter, nil)

	is := newTestIssuer(t, inter)
	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); err != nil {
		t.Fatalf("intermediate-only anchor must verify the leaf, got %v", err)
	}
}

// TestVerifyEKCertificateIntermediateSignedCRL revokes the leaf through
// a CRL signed by the bundled intermediate - the shape real
// manufacturer feeds take, since the intermediate issues the EKs.
func TestVerifyEKCertificateIntermediateSignedCRL(t *testing.T) {
	dir := t.TempDir()
	root := makeRoot(t, "tpm-vendor-root")
	inter := makeIntermediate(t, root, "tpm-vendor-ek-intermediate")
	ekDER, _ := makeEKCert(t, inter, nil)
	ekCert, err := x509.ParseCertificate(ekDER)
	if err != nil {
		t.Fatalf("parse EK: %v", err)
	}

	path := writeEKCRL(t, dir, inter, time.Now().Add(time.Hour), ekCert.SerialNumber)
	caCertPEM, caKeyPEM := makeLOTACAPEM(t)
	is, err := NewIssuer(IssuerConfig{
		CACertPEM: caCertPEM,
		CAKeyPEM:  caKeyPEM,
		EKRootPEMs: [][]byte{
			pemBlock("CERTIFICATE", root.der),
			pemBlock("CERTIFICATE", inter.der),
		},
		EKCRLPaths: []string{path},
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	if _, err := is.VerifyEKCertificate(ekDER, time.Now()); !errors.Is(err, crl.ErrCertificateRevoked) {
		t.Fatalf("expected crl.ErrCertificateRevoked via intermediate-signed CRL, got %v", err)
	}
}
