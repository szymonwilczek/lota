// SPDX-License-Identifier: MIT

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
	"testing"
	"time"
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
		KeyUsage:              x509.KeyUsageCertSign,
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

	aikCertDER, err := is.IssueAIKCertificate(&aikKey.PublicKey, "device-abc123", time.Now())
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
	aikCertDER, err := is.IssueAIKCertificate(&aikKey.PublicKey, "device-hsm", time.Now())
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
