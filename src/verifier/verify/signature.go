// SPDX-License-Identifier: MIT
// LOTA Verifier - Signature verification module
//
// This module is intentionally separated from certificate chain validation
// to allow easy substitution of trust models:
//   - TOFU (Trust On First Use) - current MVP
//   - CA-based certificate chain - future production
//   - Privacy CA (DAA) - advanced privacy-preserving

package verify

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/szymonwilczek/lota/verifier/types"
)

// handles TPM quote signature verification
// interface allows swapping verification strategies
type SignatureVerifier interface {
	// verifies the TPM quote signature
	// attestData: raw TPMS_ATTEST from TPM
	// signature: signature over attestData
	// aikPubKey: AIK public key (from TOFU store or certificate)
	VerifyQuoteSignature(attestData, signature []byte, aikPubKey *rsa.PublicKey) error

	// returns verifier name for logging
	Name() string
}

// implements RSASSA-PKCS1-v1_5 verification
type RSASSAVerifier struct{}

func NewRSASSAVerifier() *RSASSAVerifier {
	return &RSASSAVerifier{}
}

func (v *RSASSAVerifier) Name() string {
	return "RSASSA-PKCS1-v1_5"
}

func (v *RSASSAVerifier) VerifyQuoteSignature(attestData, signature []byte, aikPubKey *rsa.PublicKey) error {
	if aikPubKey == nil {
		return errors.New("AIK public key is nil")
	}

	// TPM signs SHA-256 hash of attestData
	hash := sha256.Sum256(attestData)

	err := rsa.VerifyPKCS1v15(aikPubKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// implements RSASSA-PSS verification
type RSAPSSVerifier struct{}

func NewRSAPSSVerifier() *RSAPSSVerifier {
	return &RSAPSSVerifier{}
}

func (v *RSAPSSVerifier) Name() string {
	return "RSASSA-PSS"
}

func (v *RSAPSSVerifier) VerifyQuoteSignature(attestData, signature []byte, aikPubKey *rsa.PublicKey) error {
	if aikPubKey == nil {
		return errors.New("AIK public key is nil")
	}

	hash := sha256.Sum256(attestData)

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}

	err := rsa.VerifyPSS(aikPubKey, crypto.SHA256, hash[:], signature, opts)
	if err != nil {
		return fmt.Errorf("PSS signature verification failed: %w", err)
	}

	return nil
}

// returns appropriate verifier based on signature algorithm
func SelectVerifier(sigAlg uint16) (SignatureVerifier, error) {
	switch sigAlg {
	case 0x0014: // TPM_ALG_RSASSA
		return NewRSASSAVerifier(), nil
	case 0x0016: // TPM_ALG_RSAPSS
		return NewRSAPSSVerifier(), nil
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: 0x%04X", sigAlg)
	}
}

// verifies the TPM quote signature in the report
//
// Verification flow:
// - Extract signature and attest_data from report
// - Hash attest_data with SHA-256
// - Verify signature over hash using AIK public key
func VerifyReportSignature(report *types.AttestationReport, aikPubKey *rsa.PublicKey) error {
	if report.TPM.QuoteSigSize == 0 {
		return errors.New("no signature in report")
	}

	if report.TPM.AttestSize == 0 {
		return errors.New("no attestation data in report")
	}

	if aikPubKey == nil {
		return errors.New("AIK public key is nil")
	}

	if aikPubKey.N.BitLen() < 2048 {
		return fmt.Errorf("RSA key too small: %d bits, minimum 2048", aikPubKey.N.BitLen())
	}

	// extract actual data
	attestData := report.TPM.AttestData[:report.TPM.AttestSize]
	signature := report.TPM.QuoteSignature[:report.TPM.QuoteSigSize]

	// wire format does not carry sig_alg, so try RSASSA first then PSS
	rsassaErr := NewRSASSAVerifier().VerifyQuoteSignature(attestData, signature, aikPubKey)
	if rsassaErr == nil {
		return nil
	}

	pssErr := NewRSAPSSVerifier().VerifyQuoteSignature(attestData, signature, aikPubKey)
	if pssErr == nil {
		return nil
	}

	return fmt.Errorf("TPM quote signature invalid (tried RSASSA: %v, PSS: %v)", rsassaErr, pssErr)
}

// parses RSA public key from DER-encoded PKIX/SPKI format
func ParseRSAPublicKey(keyData []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	if rsaPub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key too small: %d bits, minimum 2048", rsaPub.N.BitLen())
	}

	return rsaPub, nil
}

// returns SHA-256 fingerprint of AIK public key (PKIX/SPKI encoding)
// used for tofu identification
func AIKFingerprint(aikPubKey *rsa.PublicKey) string {
	keyBytes, err := x509.MarshalPKIXPublicKey(aikPubKey)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(keyBytes)
	return hex.EncodeToString(hash[:])
}
