// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - AIK certificate verification

package store

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/szymonwilczek/lota/crl"
)

// AIKCertVerifier verifies an AIK certificate and returns it parsed.
// The CA bound the AIK to the EK at enrollment, so the chain alone
// vouches for it.
type AIKCertVerifier interface {
	VerifyAIKCertificate(pubKey *rsa.PublicKey, aikCertDER []byte) (*x509.Certificate, error)
}

func publicKeysEqual(a, b *rsa.PublicKey) bool {
	if a.N.Cmp(b.N) != 0 {
		return false
	}
	return a.E == b.E
}

// CertificateVerifier validates AIK certificates against trusted CA roots.
type CertificateVerifier struct {
	trustedCAs []*x509.Certificate
	caPool     *x509.CertPool
	// ReloadCRLs rebuilds crls from crlPaths
	crlPaths []string
	crls     atomic.Pointer[crl.Set]
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
)

// NewCertificateVerifier loads the trusted CA roots and the CRLs. It fails
// without a root, when any root fails to load, or when crl.BuildSet refuses
// a CRL.
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

// ReloadCRLs rebuilds the CRL set from the paths given at construction
// and swaps it in whole. A failed rebuild keeps the previous set.
func (cv *CertificateVerifier) ReloadCRLs() error {
	if len(cv.crlPaths) == 0 {
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

// CRLCount returns the number of CRLs loaded.
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

// VerifyAIKCertificate checks that aikCertDER is within its validity, chains
// to a trusted root, certifies pubKey and is not revoked, and returns it
// parsed.
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

func (cv *CertificateVerifier) verifyAIKCertificate(certDER []byte, expectedPubKey *rsa.PublicKey) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return ErrCertificateNotYet
	}
	if now.After(cert.NotAfter) {
		return ErrCertificateExpired
	}

	opts := x509.VerifyOptions{
		Roots:       cv.caPool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("%w: %v", ErrCertificateChain, err)
	}

	certRSAPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: certificate does not contain RSA key", ErrCertificateKeyMatch)
	}

	if !publicKeysEqual(certRSAPubKey, expectedPubKey) {
		return fmt.Errorf("%w: public key mismatch", ErrCertificateKeyMatch)
	}

	if err := cv.crls.Load().Check(cert, now); err != nil {
		return err
	}

	return nil
}
