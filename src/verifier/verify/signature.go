// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Signature verification module

package verify

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/szymonwilczek/lota/verifier/types"
)

// RSASSAVerifier verifies RSASSA-PKCS1-v1_5 quote signatures.
type RSASSAVerifier struct{}

func NewRSASSAVerifier() *RSASSAVerifier {
	return &RSASSAVerifier{}
}

func (v *RSASSAVerifier) VerifyQuoteSignature(attestData, signature []byte, aikPubKey *rsa.PublicKey, hashAlg crypto.Hash) error {
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

// RSAPSSVerifier verifies RSASSA-PSS quote signatures whose salt is as long
// as the hash.
type RSAPSSVerifier struct{}

func NewRSAPSSVerifier() *RSAPSSVerifier {
	return &RSAPSSVerifier{}
}

func (v *RSAPSSVerifier) VerifyQuoteSignature(attestData, signature []byte, aikPubKey *rsa.PublicKey, hashAlg crypto.Hash) error {
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

// VerifyReportSignature verifies the quote signature over the report's
// TPMS_ATTEST with aikPubKey, an RSA key of at least 2048 bits, by the
// report's scheme (RSASSA or RSA-PSS) and hash (SHA-256, SHA-384 or SHA-512).
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

	attestData := report.TPM.AttestData[:report.TPM.AttestSize]
	signature := report.TPM.QuoteSignature[:report.TPM.QuoteSigSize]
	hashAlg, err := selectQuoteHashAlgorithm(report)
	if err != nil {
		return err
	}

	switch report.TPM.QuoteSigAlg {
	case 0:
		return errors.New("TPM quote signature scheme missing (quote_sig_alg=0)")

	case types.TPMAlgRSASSA:
		if verr := NewRSASSAVerifier().VerifyQuoteSignature(attestData, signature, aikPubKey, hashAlg); verr != nil {
			return fmt.Errorf("TPM quote signature invalid (sig_alg=RSASSA hash=%s): %v", hashName(hashAlg), verr)
		}
		return nil

	case types.TPMAlgRSAPSS:
		if verr := NewRSAPSSVerifier().VerifyQuoteSignature(attestData, signature, aikPubKey, hashAlg); verr != nil {
			return fmt.Errorf("TPM quote signature invalid (sig_alg=RSAPSS hash=%s): %v", hashName(hashAlg), verr)
		}
		return nil
	}
	return fmt.Errorf("unsupported TPM quote signature scheme: 0x%04X", report.TPM.QuoteSigAlg)
}

func tpmAlgToCryptoHash(tpmAlg uint16) (crypto.Hash, error) {
	switch tpmAlg {
	case types.TPMAlgSHA256:
		return crypto.SHA256, nil
	case types.TPMAlgSHA384:
		return crypto.SHA384, nil
	case types.TPMAlgSHA512:
		return crypto.SHA512, nil
	case types.TPMAlgSHA1:
		return 0, fmt.Errorf("TPM hash algorithm SHA-1 (0x%04X) is not allowed", tpmAlg)
	default:
		return 0, fmt.Errorf("unsupported TPM hash algorithm: 0x%04X", tpmAlg)
	}
}

func selectQuoteHashAlgorithm(report *types.AttestationReport) (crypto.Hash, error) {
	if report == nil {
		return 0, errors.New("report is nil")
	}
	if report.TPM.QuoteSigHashAlg == 0 {
		return 0, errors.New("TPM quote signature hash algorithm missing")
	}

	h, mapErr := tpmAlgToCryptoHash(report.TPM.QuoteSigHashAlg)
	if mapErr != nil {
		return 0, mapErr
	}
	if !h.Available() {
		return 0, fmt.Errorf("hash algorithm unavailable: %s", hashName(h))
	}
	return h, nil
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
		return fmt.Sprintf("hash(%d)", uint(h))
	}
}

// ParseRSAPublicKey parses a DER PKIX RSA key of at least 2048 bits.
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
