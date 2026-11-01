// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - AIK certificate verification
//
// Holds the attestation-CA trust anchors and the CRL engine.
// VerifyReport chain-verifies the CA-issued AIK certificate presented in every
// attestation report. Client identity is the CA-assigned device pseudonym in the
// certificate subject; verifier never sees the EK and keeps no per-client AIK.

package store

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/szymonwilczek/lota/crl"
)

// AIKCertVerifier verifies an AIK certificate on its own (no EK) and
// returns the parsed certificate. The Privacy CA model uses this: the CA
// has already bound the AIK to the EK through credential activation, so
// the verifier trusts the AIK certificate chain alone and reads the
// device pseudonym from the subject.
type AIKCertVerifier interface {
	VerifyAIKCertificate(pubKey *rsa.PublicKey, aikCertDER []byte) (*x509.Certificate, error)
}

// compares two RSA public keys
func publicKeysEqual(a, b *rsa.PublicKey) bool {
	if a.N.Cmp(b.N) != 0 {
		return false
	}
	return a.E == b.E
}

// CertificateVerifier validates AIK and EK certificates against trusted CA roots.
type CertificateVerifier struct {
	trustedCAs []*x509.Certificate
	caPool     *x509.CertPool
	// crlPaths holds the operator-configured CRL file paths captured at
	// construction. ReloadCRLs() walks the same list, re-validates every
	// CRL against the trust anchor, and atomically swaps the in-memory
	// set in via crls.Store so concurrent verify paths see the new feed
	// without holding a long lock.
	crlPaths []string
	crls     atomic.Pointer[crl.Set]
}

// CRL sentinels re-exported from the shared crl module so existing
// errors.Is callers keep matching against the store API after the
// engine moved out of this package.
var (
	ErrCertificateRevoked   = crl.ErrCertificateRevoked
	ErrCRLStale             = crl.ErrCRLStale
	ErrCRLSignature         = crl.ErrCRLSignature
	ErrCRLNoIssuer          = crl.ErrCRLNoIssuer
	ErrCRLMissingNextUpdate = crl.ErrCRLMissingNextUpdate
	ErrCRLWeakSignature     = crl.ErrCRLWeakSignature
)

// TCG EK Credential Profile OID for TPM 2.0
var oidTCGEKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 1}

// hasTCGEKOID reports whether the certificate carries the TCG EK OID in
// either an extended key usage or a certificate policy. Current Go parses
// policies into Policies; older accessors populate PolicyIdentifiers, so
// consult all three.
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

// certificate verification errors
var (
	ErrNoCertificate       = errors.New("certificate required but not provided")
	ErrInvalidCertificate  = errors.New("failed to parse certificate")
	ErrCertificateChain    = errors.New("certificate chain verification failed")
	ErrCertificateKeyMatch = errors.New("certificate public key does not match AIK")
	ErrCertificateExpired  = errors.New("certificate has expired")
	ErrCertificateNotYet   = errors.New("certificate not yet valid")
	ErrNoTrustedCAs        = errors.New("no trusted CAs configured")
	ErrCertificateEKOID    = errors.New("EK certificate missing TCG TPM 2.0 OID (2.23.133.8.1)")
)

// NewCertificateVerifier loads the trusted CA roots and the operator's CRLs.
// A CRL that does not verify against those roots is refused here; a verifier
// with no root could vouch for nothing and is refused as well.
func NewCertificateVerifier(caCertPaths, crlPaths []string) (*CertificateVerifier, error) {
	if len(caCertPaths) == 0 {
		return nil, ErrNoTrustedCAs
	}

	cv := &CertificateVerifier{
		trustedCAs: make([]*x509.Certificate, 0, len(caCertPaths)),
		caPool:     x509.NewCertPool(),
		crlPaths:   append([]string(nil), crlPaths...),
	}
	cv.crls.Store(crl.NewSet())

	for _, path := range caCertPaths {
		cert, err := loadCertificate(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA cert %s: %w", path, err)
		}
		cv.trustedCAs = append(cv.trustedCAs, cert)
		cv.caPool.AddCert(cert)
	}

	if len(cv.crlPaths) > 0 {
		set, err := crl.BuildSet(cv.crlPaths, cv.trustedCAs)
		if err != nil {
			return nil, err
		}
		cv.crls.Store(set)
	}

	return cv, nil
}

// ReloadCRLs re-parses every CRL path configured at construction time,
// validates the new feed against the trusted CA pool, and atomically
// swaps the active revocation set on success. Verify paths reading via
// cv.crls.Load() continue against the previous set during the rebuild
// and pick up the new one on their next call; failure to validate
// leaves the previous set untouched so a malformed update cannot drop
// revocations on the floor.
//
// The verifier daemon wires this to SIGHUP so operators can install a
// refreshed manufacturer feed without restarting the process.
func (cv *CertificateVerifier) ReloadCRLs() error {
	if len(cv.crlPaths) == 0 {
		// nothing to refresh; treat as a successful no-op so the SIGHUP
		// handler can blanket-call ReloadCRLs() without branching on
		// whether the operator configured any CRLs at startup.
		cv.crls.Store(crl.NewSet())
		return nil
	}
	set, err := crl.BuildSet(cv.crlPaths, cv.trustedCAs)
	if err != nil {
		return err
	}
	cv.crls.Store(set)
	return nil
}

// CRLCount returns the number of CRLs loaded. Exported
// for startup logging; the value is informational only.
func (cv *CertificateVerifier) CRLCount() int { return cv.crls.Load().Size() }

func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}

// VerifyAIKCertificate verifies that aikCertDER chains to a trusted root,
// is time-valid, not revoked, and certifies pubKey, then returns the
// parsed certificate. Under the Privacy CA model this is the verifier's
// sole AIK trust anchor: the certificate's subject carries the CA-issued
// device pseudonym used as the durable client identity, and the EK is
// never seen by the verifier.
func (cv *CertificateVerifier) VerifyAIKCertificate(pubKey *rsa.PublicKey, aikCertDER []byte) (*x509.Certificate, error) {
	if pubKey == nil {
		return nil, errors.New("nil AIK public key")
	}
	if len(aikCertDER) == 0 {
		return nil, ErrNoCertificate
	}
	if err := cv.verifyAIKCertificate(aikCertDER, pubKey); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(aikCertDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}
	return cert, nil
}

func (cv *CertificateVerifier) VerifyCertificatesForAIK(pubKey *rsa.PublicKey, aikCertDER, ekCertDER []byte) error {
	if pubKey == nil {
		return errors.New("nil AIK public key")
	}
	if len(aikCertDER) == 0 && len(ekCertDER) == 0 {
		return ErrNoCertificate
	}
	if len(aikCertDER) > 0 {
		if err := cv.verifyAIKCertificate(aikCertDER, pubKey); err != nil {
			return fmt.Errorf("AIK certificate verification failed: %w", err)
		}
	}
	if len(ekCertDER) > 0 {
		if err := cv.verifyEKCertificate(ekCertDER); err != nil {
			return fmt.Errorf("EK certificate verification failed: %w", err)
		}
	}
	return nil
}

// validates AIK certificate against trusted CAs
func (cv *CertificateVerifier) verifyAIKCertificate(certDER []byte, expectedPubKey *rsa.PublicKey) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	// verify certificate time validity
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return ErrCertificateNotYet
	}
	if now.After(cert.NotAfter) {
		return ErrCertificateExpired
	}

	// verify certificate chain against trusted CAs
	opts := x509.VerifyOptions{
		Roots:       cv.caPool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("%w: %v", ErrCertificateChain, err)
	}

	// verify that certificate public key matches the AIK from attestation
	certRSAPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: certificate does not contain RSA key", ErrCertificateKeyMatch)
	}

	if !publicKeysEqual(certRSAPubKey, expectedPubKey) {
		return fmt.Errorf("%w: public key mismatch", ErrCertificateKeyMatch)
	}

	// consult operator-supplied CRLs after chain + key checks pass
	if err := cv.crls.Load().Check(cert, now); err != nil {
		return err
	}

	return nil
}

// validates EK certificate (proves TPM authenticity)
func (cv *CertificateVerifier) verifyEKCertificate(certDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	// verify certificate time validity
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return ErrCertificateNotYet
	}
	if now.After(cert.NotAfter) {
		return ErrCertificateExpired
	}

	// verify certificate chain against trusted CAs (TPM manufacturer CAs)
	opts := x509.VerifyOptions{
		Roots:       cv.caPool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("%w: %v", ErrCertificateChain, err)
	}

	// EK certificate must carry the TCG EK Credential Profile OID
	// (2.23.133.8.1) to prove TPM 2.0 origin. Genuine manufacturer EK
	// certificates almost always place it in a certificate policy rather
	// than an extended key usage, so accept either location; checking
	// only the EKU rejects real hardware.
	if !hasTCGEKOID(cert) {
		return ErrCertificateEKOID
	}

	// consult operator-supplied CRLs (TPM manufacturer revocation feeds)
	if err := cv.crls.Load().Check(cert, now); err != nil {
		return err
	}

	return nil
}
