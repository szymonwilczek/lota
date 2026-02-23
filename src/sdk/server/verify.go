// SPDX-License-Identifier: MIT
//
// LOTA Server-Side Token Verification SDK (Go)
//
// Provides game servers with the ability to verify attestation tokens
// received from game clients running the LOTA Gaming SDK.
//
// Usage:
//
//	claims, err := server.VerifyToken(tokenBytes, aikPub, nil)
//	if err != nil {
//	    log.Printf("attestation failed: %v", err)
//	    rejectClient()
//	    return
//	}
//	if claims.Expired {
//	    log.Printf("token expired, requesting re-attestation")
//	    requestNewToken()
//	    return
//	}
//	allowClient()

package server

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Token wire format constants
const (
	TokenMagic      uint32 = 0x4B544F4C // "LOTK" in memory (little-endian)
	TokenVersion    uint16 = 0x0002
	TokenHeaderSize        = 96
	TokenMaxSize           = TokenHeaderSize + 1024 + 512 // 1632 bytes

	MaxAttestSize = 1024
	MaxSigSize    = 512
)

// Token freshness policy defaults (see: include/lota_server.h)
const (
	// Maximum acceptable age (in seconds) for a token.
	// Tokens older than this are flagged as TooOld.
	DefaultMaxTokenAge = 300 // 5 minutes

	// Maximum allowed clock skew (in seconds) between issuer and verifier.
	// Tokens issued further in the future are flagged as IssuedInFuture.
	MaxClockSkew = 60 // 1 minute
)

// TPM algorithm identifiers
const (
	TPMAlgRSASSA uint16 = 0x0014
	TPMAlgRSAPSS uint16 = 0x0016
)

// TPM constants for TPMS_ATTEST parsing
const (
	tpmGeneratedValue uint32 = 0xff544347
	tpmSTAttestQuote  uint16 = 0x8018
)

// Errors returned by verification functions
var (
	ErrInvalidArg   = errors.New("lota: invalid argument")
	ErrBadToken     = errors.New("lota: malformed token")
	ErrBadVersion   = errors.New("lota: unsupported token version")
	ErrSigFail      = errors.New("lota: signature verification failed")
	ErrNonceFail    = errors.New("lota: nonce mismatch")
	ErrExpired      = errors.New("lota: token expired")
	ErrTooOld       = errors.New("lota: token too old")
	ErrFutureToken  = errors.New("lota: token issued in the future")
	ErrAttestParse  = errors.New("lota: failed to parse TPMS_ATTEST")
	ErrNotQuote     = errors.New("lota: TPMS_ATTEST is not a quote")
	ErrBadMagic     = errors.New("lota: invalid TPM magic in TPMS_ATTEST")
	ErrNoSignature  = errors.New("lota: token contains no signature")
	ErrNoAttestData = errors.New("lota: token contains no attestation data")
)

// represents the verified claims extracted from a LOTA attestation token
// after successful VerifyToken(), all fields are cryptographically validated
type Claims struct {
	// when the token expires
	ExpiresAt time.Time

	// contains the LOTA_FLAG_* bitmask at issue time
	Flags uint32

	// 32-byte client nonce included in the token
	Nonce [32]byte

	// indicates which TPM PCRs were included in the quote
	PCRMask uint32

	// SHA-256 over startup enforcement policy state (includes allowlist)
	PolicyDigest [32]byte

	// composite hash of the selected PCR values
	// from the TPMS_ATTEST QuoteInfo (empty if not a Quote)
	PCRDigest []byte

	// TPM signature algorithm used (0x0014=RSASSA, 0x0016=PSS)
	SigAlg uint16

	// TPM hash algorithm used (0x000B=SHA-256)
	HashAlg uint16

	// true if the token has passed its ExpiresAt time
	Expired bool
}

// represents the parsed wire-format header
type tokenWire struct {
	magic      uint32
	version    uint16
	totalSize  uint16
	validUntil uint64
	flags      uint32
	nonce      [32]byte
	sigAlg     uint16
	hashAlg    uint16
	pcrMask    uint32
	policy     [32]byte
	attestSize uint16
	sigSize    uint16
}

// Verifies a serialized LOTA token against an AIK public key
//
// Parameters:
//   - tokenData: serialized token bytes (from lota_token_serialize on client)
//   - aikPub: AIK RSA public key (from trusted source, NOT from client)
//   - expectedNonce: optional 32-byte nonce to verify (nil = skip nonce check)
//
// Returns verified Claims on success. Returns error if cryptographic
// verification fails or the token is expired/too old/issued in future.
func VerifyToken(tokenData []byte, aikPub *rsa.PublicKey, expectedNonce []byte) (*Claims, error) {
	if aikPub == nil {
		return nil, ErrInvalidArg
	}

	// parse wire format
	hdr, err := parseWireHeader(tokenData)
	if err != nil {
		return nil, err
	}

	if hdr.attestSize == 0 {
		return nil, ErrNoAttestData
	}
	if hdr.sigSize == 0 {
		return nil, ErrNoSignature
	}

	attestData := tokenData[TokenHeaderSize : TokenHeaderSize+int(hdr.attestSize)]
	signature := tokenData[TokenHeaderSize+int(hdr.attestSize) : TokenHeaderSize+int(hdr.attestSize)+int(hdr.sigSize)]

	// verify RSA signature over attest_data
	if err := verifyRSASignature(attestData, signature, hdr.sigAlg, aikPub); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigFail, err)
	}

	// parse TPMS_ATTEST - extract extraData and PCR digest
	extraData, pcrDigest, err := parseTPMSAttest(attestData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestParse, err)
	}

	// verify nonce binding: extraData == SHA256(valid_until||flags||pcr_mask||nonce||policy_digest)
	computedNonce := computeExpectedNonce(hdr.validUntil, hdr.flags, hdr.pcrMask, hdr.nonce, hdr.policy)
	if !bytes.Equal(extraData, computedNonce[:]) {
		return nil, fmt.Errorf("%w: extraData does not match SHA256(metadata||nonce)", ErrNonceFail)
	}

	// verify client nonce if expected
	if expectedNonce != nil {
		if len(expectedNonce) != 32 || !bytes.Equal(hdr.nonce[:], expectedNonce) {
			return nil, fmt.Errorf("%w: client nonce does not match expected", ErrNonceFail)
		}
	}

	claims := &Claims{
		ExpiresAt:    time.Unix(int64(hdr.validUntil), 0),
		Flags:        hdr.flags,
		Nonce:        hdr.nonce,
		PCRMask:      hdr.pcrMask,
		PolicyDigest: hdr.policy,
		PCRDigest:    pcrDigest,
		SigAlg:       hdr.sigAlg,
		HashAlg:      hdr.hashAlg,
	}

	// check expiry
	now := time.Now()
	if hdr.validUntil > 0 && now.Unix() > int64(hdr.validUntil) {
		claims.Expired = true
	}

	// return claims with error for temporal violations
	if claims.Expired {
		return claims, ErrExpired
	}

	return claims, nil
}

// parses a serialized LOTA token WITHOUT cryptographic verification
// Claims are UNTRUSTED.
func ParseToken(tokenData []byte) (*Claims, error) {
	hdr, err := parseWireHeader(tokenData)
	if err != nil {
		return nil, err
	}

	claims := &Claims{
		ExpiresAt:    time.Unix(int64(hdr.validUntil), 0),
		Flags:        hdr.flags,
		Nonce:        hdr.nonce,
		PCRMask:      hdr.pcrMask,
		PolicyDigest: hdr.policy,
		SigAlg:       hdr.sigAlg,
		HashAlg:      hdr.hashAlg,
	}

	// try to extract PCR digest from TPMS_ATTEST (best-effort)
	if hdr.attestSize > 0 {
		attestData := tokenData[TokenHeaderSize : TokenHeaderSize+int(hdr.attestSize)]
		_, pcrDigest, err := parseTPMSAttest(attestData)
		if err == nil {
			claims.PCRDigest = pcrDigest
		}
	}

	if hdr.validUntil > 0 && time.Now().Unix() > int64(hdr.validUntil) {
		claims.Expired = true
	}

	return claims, nil
}

// creates the wire-format representation of a token
// This is the Go equivalent of lota_token_serialize() from the C gaming SDK.
// For more information see: include/lota_gaming.h
func SerializeToken(validUntil uint64, flags uint32, nonce [32]byte,
	sigAlg, hashAlg uint16, pcrMask uint32, policyDigest [32]byte,
	attestData, signature []byte,
) ([]byte, error) {
	if len(attestData) > MaxAttestSize {
		return nil, fmt.Errorf("attest_data too large: %d > %d", len(attestData), MaxAttestSize)
	}
	if len(signature) > MaxSigSize {
		return nil, fmt.Errorf("signature too large: %d > %d", len(signature), MaxSigSize)
	}

	totalSize := TokenHeaderSize + len(attestData) + len(signature)
	buf := make([]byte, totalSize)

	// header
	binary.LittleEndian.PutUint32(buf[0:4], TokenMagic)
	binary.LittleEndian.PutUint16(buf[4:6], TokenVersion)
	binary.LittleEndian.PutUint16(buf[6:8], uint16(totalSize))
	binary.LittleEndian.PutUint64(buf[8:16], validUntil)
	binary.LittleEndian.PutUint32(buf[16:20], flags)
	copy(buf[20:52], nonce[:])
	binary.LittleEndian.PutUint16(buf[52:54], sigAlg)
	binary.LittleEndian.PutUint16(buf[54:56], hashAlg)
	binary.LittleEndian.PutUint32(buf[56:60], pcrMask)
	copy(buf[60:92], policyDigest[:])
	binary.LittleEndian.PutUint16(buf[92:94], uint16(len(attestData)))
	binary.LittleEndian.PutUint16(buf[94:96], uint16(len(signature)))

	// variable data
	copy(buf[TokenHeaderSize:], attestData)
	copy(buf[TokenHeaderSize+len(attestData):], signature)

	return buf, nil
}

// parses the wire-format token header
func parseWireHeader(data []byte) (*tokenWire, error) {
	if len(data) < TokenHeaderSize {
		return nil, fmt.Errorf("%w: too short (%d bytes, need %d)", ErrBadToken, len(data), TokenHeaderSize)
	}

	hdr := &tokenWire{}
	hdr.magic = binary.LittleEndian.Uint32(data[0:4])
	if hdr.magic != TokenMagic {
		return nil, fmt.Errorf("%w: bad magic 0x%08X (expected 0x%08X)", ErrBadToken, hdr.magic, TokenMagic)
	}

	hdr.version = binary.LittleEndian.Uint16(data[4:6])
	if hdr.version != TokenVersion {
		return nil, fmt.Errorf("%w: version %d (expected %d)", ErrBadVersion, hdr.version, TokenVersion)
	}

	hdr.totalSize = binary.LittleEndian.Uint16(data[6:8])
	if int(hdr.totalSize) > len(data) || hdr.totalSize < TokenHeaderSize {
		return nil, fmt.Errorf("%w: total_size %d invalid (have %d bytes)", ErrBadToken, hdr.totalSize, len(data))
	}

	hdr.validUntil = binary.LittleEndian.Uint64(data[8:16])
	hdr.flags = binary.LittleEndian.Uint32(data[16:20])
	copy(hdr.nonce[:], data[20:52])
	hdr.sigAlg = binary.LittleEndian.Uint16(data[52:54])
	hdr.hashAlg = binary.LittleEndian.Uint16(data[54:56])
	hdr.pcrMask = binary.LittleEndian.Uint32(data[56:60])
	copy(hdr.policy[:], data[60:92])
	hdr.attestSize = binary.LittleEndian.Uint16(data[92:94])
	hdr.sigSize = binary.LittleEndian.Uint16(data[94:96])

	// validate sizes
	expected := int(TokenHeaderSize) + int(hdr.attestSize) + int(hdr.sigSize)
	if expected > int(hdr.totalSize) {
		return nil, fmt.Errorf("%w: data sizes exceed total_size", ErrBadToken)
	}
	if hdr.attestSize > MaxAttestSize || hdr.sigSize > MaxSigSize {
		return nil, fmt.Errorf("%w: attest_size=%d sig_size=%d exceed limits", ErrBadToken, hdr.attestSize, hdr.sigSize)
	}

	return hdr, nil
}

// verifies the TPM RSA signature over attest_data
func verifyRSASignature(attestData, signature []byte, sigAlg uint16, aikPub *rsa.PublicKey) error {
	hash := sha256.Sum256(attestData)

	switch sigAlg {
	case TPMAlgRSAPSS:
		opts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}
		return rsa.VerifyPSS(aikPub, crypto.SHA256, hash[:], signature, opts)

	case TPMAlgRSASSA:
		return rsa.VerifyPKCS1v15(aikPub, crypto.SHA256, hash[:], signature)

	default:
		return fmt.Errorf("unsupported signature algorithm: 0x%04X", sigAlg)
	}
}

func computeExpectedNonce(validUntil uint64, flags uint32, pcrMask uint32, nonce [32]byte, policyDigest [32]byte) [32]byte {
	var buf [80]byte // 8 + 4 + 4 + 32 + 32
	binary.LittleEndian.PutUint64(buf[0:8], validUntil)
	binary.LittleEndian.PutUint32(buf[8:12], flags)
	binary.LittleEndian.PutUint32(buf[12:16], pcrMask)
	copy(buf[16:48], nonce[:])
	copy(buf[48:80], policyDigest[:])
	return sha256.Sum256(buf[:])
}

// computes the token quote nonce used in the token verification domain:
//
//	SHA256(valid_until_LE || flags_LE || pcr_mask_LE || client_nonce || policy_digest)
//
// This value is expected to match TPMS_ATTEST.extraData in the token format.
//
// NOTE: This is intentionally different from the attestation report binding
// nonce used by the remote attestation verifier/agent report path.
func ComputeTokenQuoteNonce(validUntil uint64, flags uint32, pcrMask uint32, nonce [32]byte, policyDigest [32]byte) [32]byte {
	return computeExpectedNonce(validUntil, flags, pcrMask, nonce, policyDigest)
}

// parses a raw TPMS_ATTEST blob and extracts:
//   - extraData (the nonce embedded by the TPM)
//   - pcrDigest (the PCR composite hash, only for Quote type)
func parseTPMSAttest(data []byte) (extraData []byte, pcrDigest []byte, err error) {
	if len(data) < 10 {
		return nil, nil, fmt.Errorf("attest data too short: %d bytes", len(data))
	}

	r := bytes.NewReader(data)

	// magic (4 bytes, big-endian)
	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return nil, nil, fmt.Errorf("read magic: %w", err)
	}
	if magic != tpmGeneratedValue {
		return nil, nil, fmt.Errorf("%w: got 0x%08X", ErrBadMagic, magic)
	}

	// type (2 bytes, big-endian)
	var attestType uint16
	if err := binary.Read(r, binary.BigEndian, &attestType); err != nil {
		return nil, nil, fmt.Errorf("read type: %w", err)
	}

	// qualifiedSigner (TPM2B_NAME: 2-byte size + data)
	var signerSize uint16
	if err := binary.Read(r, binary.BigEndian, &signerSize); err != nil {
		return nil, nil, fmt.Errorf("read signer size: %w", err)
	}
	signerBuf := make([]byte, signerSize)
	if _, err := r.Read(signerBuf); err != nil {
		return nil, nil, fmt.Errorf("read signer: %w", err)
	}

	// extraData (TPM2B_DATA: 2-byte size + data)
	var extraSize uint16
	if err := binary.Read(r, binary.BigEndian, &extraSize); err != nil {
		return nil, nil, fmt.Errorf("read extraData size: %w", err)
	}
	extraData = make([]byte, extraSize)
	if _, err := r.Read(extraData); err != nil {
		return nil, nil, fmt.Errorf("read extraData: %w", err)
	}

	// clockInfo: clock(8) + resetCount(4) + restartCount(4) + safe(1) = 17 bytes
	clockBuf := make([]byte, 17)
	if _, err := r.Read(clockBuf); err != nil {
		return nil, nil, fmt.Errorf("read clockInfo: %w", err)
	}

	// firmwareVersion (8 bytes)
	fwBuf := make([]byte, 8)
	if _, err := r.Read(fwBuf); err != nil {
		return nil, nil, fmt.Errorf("read firmwareVersion: %w", err)
	}

	if attestType == tpmSTAttestQuote {
		// TPML_PCR_SELECTION: count(4) + array
		var pcrSelCount uint32
		if err := binary.Read(r, binary.BigEndian, &pcrSelCount); err != nil {
			return extraData, nil, nil // partial success - have extraData
		}

		if pcrSelCount > 16 {
			return extraData, nil, nil
		}

		for i := uint32(0); i < pcrSelCount; i++ {
			var hashAlg uint16
			var selectSize uint8
			if err := binary.Read(r, binary.BigEndian, &hashAlg); err != nil {
				return extraData, nil, nil
			}
			if err := binary.Read(r, binary.BigEndian, &selectSize); err != nil {
				return extraData, nil, nil
			}
			selectBuf := make([]byte, selectSize)
			if _, err := r.Read(selectBuf); err != nil {
				return extraData, nil, nil
			}
		}

		// pcrDigest (TPM2B_DIGEST: 2-byte size + data)
		var digestSize uint16
		if err := binary.Read(r, binary.BigEndian, &digestSize); err != nil {
			return extraData, nil, nil
		}
		pcrDigest = make([]byte, digestSize)
		if _, err := r.Read(pcrDigest); err != nil {
			return extraData, nil, nil
		}
	}

	return extraData, pcrDigest, nil
}

// parses a DER-encoded RSA public key in PKIX/SPKI format (SubjectPublicKeyInfo)
func ParseRSAPublicKey(der []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	if rsaPub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key too small: %d bits (minimum 2048)", rsaPub.N.BitLen())
	}

	return rsaPub, nil
}
