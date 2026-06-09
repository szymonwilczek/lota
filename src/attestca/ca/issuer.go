// SPDX-License-Identifier: MIT
// LOTA Attestation CA - EK trust and AIK certificate issuance
//
// The issuer holds the operator's CA signing key and the trusted TPM
// manufacturer roots. It verifies that an Endorsement Key certificate
// chains to a manufacturer the operator trusts, and -- only after the
// agent has proven possession of the matching TPM through credential
// activation -- mints a short-lived AIK certificate. Downstream
// verifiers then trust the AIK because it chains to this CA, without
// ever seeing the EK or running an activation round-trip themselves.

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

// TCG EK Credential Profile OID for a TPM 2.0 endorsement key.
// Manufacturer EK certificates carry it either as an extended key usage
// or, far more commonly, as a certificate policy.
// Both placements are accepted
var oidTCGEKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 1}

// Critical extensions a TPM EK certificate may carry that Go's x509
// verifier does not process: the subject alternative name (TPM
// manufacturer/model/version as a directoryName) and the subject
// directory attributes.
var (
	oidSubjectAltName        = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidSubjectDirectoryAttrs = asn1.ObjectIdentifier{2, 5, 29, 9}
)

func dropTPMCriticalExtensions(oids []asn1.ObjectIdentifier) []asn1.ObjectIdentifier {
	out := oids[:0:0]
	for _, oid := range oids {
		if oid.Equal(oidSubjectAltName) || oid.Equal(oidSubjectDirectoryAttrs) {
			continue
		}
		out = append(out, oid)
	}
	return out
}

const (
	// MinEKKeyBits rejects undersized EK moduli.
	MinEKKeyBits = 2048

	// DefaultAIKCertTTL keeps issued AIK certificates short-lived so a
	// compromised key is bounded by the re-enrollment interval.
	DefaultAIKCertTTL = 24 * time.Hour
)

var (
	ErrNoEKRoots        = errors.New("no trusted EK manufacturer roots configured")
	ErrEKParse          = errors.New("failed to parse EK certificate")
	ErrEKChain          = errors.New("EK certificate does not chain to a trusted manufacturer root")
	ErrEKExpired        = errors.New("EK certificate is expired")
	ErrEKNotYet         = errors.New("EK certificate is not yet valid")
	ErrEKMissingOID     = errors.New("EK certificate missing TCG TPM 2.0 OID (2.23.133.8.1)")
	ErrEKKeyType        = errors.New("EK certificate public key is not RSA; enrollment requires an RSA endorsement key (TCG EK template H-1)")
	ErrEKKeySize        = errors.New("EK certificate RSA key too small")
	ErrCANotCA          = errors.New("CA certificate is not a certificate authority")
	ErrCAKeyMismatch    = errors.New("CA private key does not match CA certificate")
	ErrUnsupportedCAKey = errors.New("unsupported CA signing key type")
)

// Issuer verifies EK certificates and mints AIK certificates.
type Issuer struct {
	caCert  *x509.Certificate
	caKey   crypto.Signer
	ekRoots *x509.CertPool
	certTTL time.Duration
}

// IssuerConfig configures a new Issuer.
type IssuerConfig struct {
	// CACertPEM is the PEM-encoded CA certificate whose key signs AIK
	// certificates. Downstream verifiers pin this as a trust root.
	CACertPEM []byte

	// CAKeyPEM is the PEM-encoded PKCS#8 CA private key.
	// It is used only when CASigner is nil; an on-disk key
	// is the dev-only fallback.
	CAKeyPEM []byte

	// CASigner is a pre-built signer for the CA key
	// Typically backed by an HSM or other external key store that never
	// exposes the private key. When set, it takes precedence over CAKeyPEM
	// and the private key material never enters the process.
	// Its public key must match the CA certificate, the same check applied
	// to an on-disk key.
	CASigner crypto.Signer

	// EKRootPEMs are the PEM-encoded TPM manufacturer root certificates.
	EKRootPEMs [][]byte

	// AIKCertTTL is the lifetime of issued AIK certificates.
	// Zero selects DefaultAIKCertTTL.
	AIKCertTTL time.Duration
}

// NewIssuer builds an Issuer from PEM material.
func NewIssuer(cfg IssuerConfig) (*Issuer, error) {
	caCert, err := parseCertPEM(cfg.CACertPEM)
	if err != nil {
		return nil, fmt.Errorf("CA certificate: %w", err)
	}
	if !caCert.IsCA {
		return nil, ErrCANotCA
	}

	// externally held signer (HSM, KMS, ...) takes precedence
	// the on-disk PEM is the dev-only fallback.
	// Either way the signer's public key is checked against
	// the CA certificate so a misconfigured key store cannot
	// sign under the wrong identity
	caKey := cfg.CASigner
	if caKey == nil {
		caKey, err = parseSignerPEM(cfg.CAKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("CA key: %w", err)
		}
	}
	if caKey.Public() == nil {
		return nil, ErrUnsupportedCAKey
	}
	if !publicKeysMatch(caKey.Public(), caCert.PublicKey) {
		return nil, ErrCAKeyMismatch
	}

	if len(cfg.EKRootPEMs) == 0 {
		return nil, ErrNoEKRoots
	}
	ekRoots := x509.NewCertPool()
	for i, rootPEM := range cfg.EKRootPEMs {
		root, err := parseCertPEM(rootPEM)
		if err != nil {
			return nil, fmt.Errorf("EK root %d: %w", i, err)
		}
		ekRoots.AddCert(root)
	}

	ttl := cfg.AIKCertTTL
	if ttl <= 0 {
		ttl = DefaultAIKCertTTL
	}

	return &Issuer{
		caCert:  caCert,
		caKey:   caKey,
		ekRoots: ekRoots,
		certTTL: ttl,
	}, nil
}

// VerifyEKCertificate confirms an EK certificate chains to a trusted
// manufacturer root, is time-valid, carries the TCG EK OID, and holds an
// RSA key large enough to wrap an activation seed. It returns the parsed
// certificate so the caller can bind the credential to its public key.
func (is *Issuer) VerifyEKCertificate(der []byte, now time.Time) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEKParse, err)
	}

	if now.Before(cert.NotBefore) {
		return nil, ErrEKNotYet
	}
	if now.After(cert.NotAfter) {
		return nil, ErrEKExpired
	}

	// TPM EK certificates carry TCG-specific critical extensions that
	// Go's verifier does not process -- the subject alternative name
	// holding the TPM manufacturer/model/version as a directoryName
	// (the subject itself is empty per the TCG profile) and the subject
	// directory attributes. They are irrelevant to chain verification,
	// so drop them from the unhandled-critical set; EK authenticity is
	// still gated by the chain check and the TCG EK OID below. Without
	// this, x509.Verify fails with "unhandled critical extension" on
	// every genuine EK certificate.
	cert.UnhandledCriticalExtensions = dropTPMCriticalExtensions(cert.UnhandledCriticalExtensions)

	// EK certificates are leaf certificates that may omit the TLS server
	// EKU, so verify with ExtKeyUsageAny
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       is.ekRoots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEKChain, err)
	}

	if !hasTCGEKOID(cert) {
		return nil, ErrEKMissingOID
	}

	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		// Credential activation wraps the secret to an RSA EK
		// (TPM2_MakeCredential is RSA-OAEP here)
		// ECC or other EK is refused with a message that names
		// the offending algorithm so an operator knows the host
		// needs its RSA EK provisioned
		return nil, fmt.Errorf("%w: certificate carries a %s key", ErrEKKeyType, cert.PublicKeyAlgorithm)
	}
	if rsaPub.N.BitLen() < MinEKKeyBits {
		return nil, fmt.Errorf("%w: %d bits", ErrEKKeySize, rsaPub.N.BitLen())
	}

	return cert, nil
}

// IssueAIKCertificate mints a short-lived certificate for an activated
// AIK. subjectCN is an opaque, privacy-preserving device identifier
// chosen by the caller; the EK is never referenced so attestations
// across verifiers cannot be linked back to the hardware.
func (is *Issuer) IssueAIKCertificate(aikPub *rsa.PublicKey, subjectCN string, now time.Time) ([]byte, error) {
	if aikPub == nil {
		return nil, errors.New("nil AIK public key")
	}
	if aikPub.N.BitLen() < MinEKKeyBits {
		return nil, fmt.Errorf("AIK RSA key too small: %d bits", aikPub.N.BitLen())
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: subjectCN},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(is.certTTL),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, is.caCert, aikPub, is.caKey)
	if err != nil {
		return nil, fmt.Errorf("signing AIK certificate: %w", err)
	}
	return der, nil
}

// CACertDER returns the DER encoding of the CA certificate so verifiers
// can be provisioned with the trust root.
func (is *Issuer) CACertDER() []byte {
	return is.caCert.Raw
}

func hasTCGEKOID(cert *x509.Certificate) bool {
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(oidTCGEKCertificate) {
			return true
		}
	}

	for _, oid := range cert.PolicyIdentifiers {
		if oid.Equal(oidTCGEKCertificate) {
			return true
		}
	}

	want := oidTCGEKCertificate.String()
	for _, oid := range cert.Policies {
		if oid.String() == want {
			return true
		}
	}
	return false
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseSignerPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	case *rsa.PrivateKey:
		return k, nil
	default:
		return nil, ErrUnsupportedCAKey
	}
}

func publicKeysMatch(a, b crypto.PublicKey) bool {
	type equalable interface{ Equal(x crypto.PublicKey) bool }
	if ak, ok := a.(equalable); ok {
		return ak.Equal(b)
	}
	return false
}

// LoadPEMFile reads a PEM file, exposed for the CA server's startup.
func LoadPEMFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
