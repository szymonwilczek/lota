// SPDX-License-Identifier: MIT
// LOTA Verifier - Signature verification module
//
// The signature verifier validates the TPM quote (TPMS_ATTEST +
// signature) against an AIK public key. It is intentionally
// decoupled from the AIK trust model so the same verifier handles
// every supported source for the public key:
//   - Certificate-backed AIK chain via CertificateStore. The
//     production default (VerifierConfig.RequireCert=true) takes
//     this path: the AIK and EK certificates have already been
//     chain-verified against the configured trust roots and the
//     hardware ID has been bound to the EK modulus before the
//     signature is checked.
//   - Legacy TOFU pin via MemoryStore / FileStore for hosts that
//     opted out of --require-cert. The AIK was pinned on first use
//     and subsequent quotes must verify against the same key.
//   - Optional future Privacy CA / DAA flow. The interface stays
//     intentionally minimal so a new strategy can be plugged in
//     without touching the quote-verification fast path.

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
	// aikPubKey: AIK public key; provided by the caller after it
	//   has been resolved through the active trust model (cert
	//   chain on the production path, legacy TOFU pin under
	//   --no-require-cert).
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
	hashAlg, hashSource, err := selectQuoteHashAlgorithm(report)
	if err != nil {
		return err
	}

	switch report.TPM.QuoteSigAlg {
	case 0:
		return errors.New("TPM quote signature scheme missing (quote_sig_alg=0)")

	case types.TPMAlgRSASSA:
		if verr := NewRSASSAVerifier().VerifyQuoteSignatureWithHash(attestData, signature, aikPubKey, hashAlg); verr != nil {
			return fmt.Errorf("TPM quote signature invalid (sig_alg=RSASSA hash=%s source=%s): %v", hashName(hashAlg), hashSource, verr)
		}
		return nil

	case types.TPMAlgRSAPSS:
		if verr := NewRSAPSSVerifier().VerifyQuoteSignatureWithHash(attestData, signature, aikPubKey, hashAlg); verr != nil {
			return fmt.Errorf("TPM quote signature invalid (sig_alg=RSAPSS hash=%s source=%s): %v", hashName(hashAlg), hashSource, verr)
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

func selectQuoteHashAlgorithm(report *types.AttestationReport) (crypto.Hash, string, error) {
	if report == nil {
		return 0, "report.tpm.quote_sig_hash_alg", errors.New("report is nil")
	}
	if report.TPM.QuoteSigHashAlg == 0 {
		return 0, "report.tpm.quote_sig_hash_alg", errors.New("TPM quote signature hash algorithm missing")
	}

	h, mapErr := tpmAlgToCryptoHash(report.TPM.QuoteSigHashAlg)
	if mapErr != nil {
		return 0, "report.tpm.quote_sig_hash_alg", mapErr
	}
	if !h.Available() {
		return 0, "report.tpm.quote_sig_hash_alg", fmt.Errorf("hash algorithm unavailable: %s", hashName(h))
	}
	return h, "report.tpm.quote_sig_hash_alg", nil
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
