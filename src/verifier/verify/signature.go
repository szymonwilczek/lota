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
	return v.VerifyQuoteSignatureWithHash(attestData, signature, aikPubKey, crypto.SHA256)
}

func (v *RSASSAVerifier) VerifyQuoteSignatureWithHash(attestData, signature []byte, aikPubKey *rsa.PublicKey, hashAlg crypto.Hash) error {
	if aikPubKey == nil {
		return errors.New("AIK public key is nil")
	}
	if !hashAlg.Available() {
		return fmt.Errorf("hash algorithm unavailable: %v", hashAlg)
	}

	h := hashAlg.New()
	if _, err := h.Write(attestData); err != nil {
		return fmt.Errorf("failed to hash attestation data: %w", err)
	}
	digest := h.Sum(nil)

	err := rsa.VerifyPKCS1v15(aikPubKey, hashAlg, digest, signature)
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
	return v.VerifyQuoteSignatureWithHash(attestData, signature, aikPubKey, crypto.SHA256)
}

func (v *RSAPSSVerifier) VerifyQuoteSignatureWithHash(attestData, signature []byte, aikPubKey *rsa.PublicKey, hashAlg crypto.Hash) error {
	if aikPubKey == nil {
		return errors.New("AIK public key is nil")
	}
	if !hashAlg.Available() {
		return fmt.Errorf("hash algorithm unavailable: %v", hashAlg)
	}

	h := hashAlg.New()
	if _, err := h.Write(attestData); err != nil {
		return fmt.Errorf("failed to hash attestation data: %w", err)
	}
	digest := h.Sum(nil)

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hashAlg,
	}

	err := rsa.VerifyPSS(aikPubKey, hashAlg, digest, signature, opts)
	if err != nil {
		return fmt.Errorf("PSS signature verification failed: %w", err)
	}

	return nil
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

	if int(report.TPM.AttestSize) > len(report.TPM.AttestData) {
		return fmt.Errorf("invalid attest size: %d > %d", report.TPM.AttestSize, len(report.TPM.AttestData))
	}

	if int(report.TPM.QuoteSigSize) > len(report.TPM.QuoteSignature) {
		return fmt.Errorf("invalid quote signature size: %d > %d", report.TPM.QuoteSigSize, len(report.TPM.QuoteSignature))
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
	hashAlg, hashSource, err := selectQuoteHashAlgorithm(attestData)
	if err != nil {
		return err
	}

	// wire format does not carry sig_alg, so try RSASSA first then PSS
	rsassaErr := NewRSASSAVerifier().VerifyQuoteSignatureWithHash(attestData, signature, aikPubKey, hashAlg)
	if rsassaErr == nil {
		return nil
	}

	pssErr := NewRSAPSSVerifier().VerifyQuoteSignatureWithHash(attestData, signature, aikPubKey, hashAlg)
	if pssErr == nil {
		return nil
	}

	return fmt.Errorf("TPM quote signature invalid (hash=%s source=%s, tried RSASSA: %v, PSS: %v)", hashName(hashAlg), hashSource, rsassaErr, pssErr)
}

const (
	tpmAlgSHA1   = 0x0004
	tpmAlgSHA256 = 0x000B
	tpmAlgSHA384 = 0x000C
	tpmAlgSHA512 = 0x000D
)

func tpmAlgToCryptoHash(tpmAlg uint16) (crypto.Hash, error) {
	switch tpmAlg {
	case tpmAlgSHA256:
		return crypto.SHA256, nil
	case tpmAlgSHA384:
		return crypto.SHA384, nil
	case tpmAlgSHA512:
		return crypto.SHA512, nil
	case tpmAlgSHA1:
		return 0, fmt.Errorf("TPM hash algorithm SHA-1 (0x%04X) is not allowed", tpmAlg)
	default:
		return 0, fmt.Errorf("unsupported TPM hash algorithm: 0x%04X", tpmAlg)
	}
}

func selectQuoteHashAlgorithm(attestData []byte) (crypto.Hash, string, error) {
	attest, err := ParseTPMSAttest(attestData)
	if err != nil {
		return 0, "tpms_attest.pcr_hash_alg", fmt.Errorf("failed to parse TPMS_ATTEST for hash selection: %w", err)
	}
	if attest == nil || attest.QuoteInfo == nil || attest.QuoteInfo.PCRHashAlg == 0 {
		return 0, "tpms_attest.pcr_hash_alg", errors.New("TPMS_ATTEST missing PCR hash algorithm metadata")
	}

	h, mapErr := tpmAlgToCryptoHash(attest.QuoteInfo.PCRHashAlg)
	if mapErr != nil {
		return 0, "tpms_attest.pcr_hash_alg", mapErr
	}
	if !h.Available() {
		return 0, "tpms_attest.pcr_hash_alg", fmt.Errorf("hash algorithm unavailable: %s", hashName(h))
	}
	return h, "tpms_attest.pcr_hash_alg", nil
}

func hashName(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "SHA-256"
	case crypto.SHA384:
		return "SHA-384"
	case crypto.SHA512:
		return "SHA-512"
	default:
		return fmt.Sprintf("hash(%d)", int(h))
	}
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
	h := sha256.Sum256(keyBytes)
	return hex.EncodeToString(h[:])
}
