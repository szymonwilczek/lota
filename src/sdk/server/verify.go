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
	"io"
	"time"
)

// Token wire format constants
const (
	TokenMagic      uint32 = 0x4B544F4C // "LOTK" in memory (little-endian)
	TokenVersion    uint16 = 0x0003
	TokenHeaderSize        = 144
	TokenMaxSize           = TokenHeaderSize + (1024 * 4) + 1024 + 512 // 5776 bytes

	MaxAttestSize  = 1024
	MaxSigSize     = 512
	MaxProtectPIDs = 1024
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

	TPMAlgSHA256 uint16 = 0x000B
	TPMAlgSHA384 uint16 = 0x000C
	TPMAlgSHA512 uint16 = 0x000D
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

	// SHA-256 over canonical runtime protected PID set
	RuntimeProtectDigest [32]byte

	// number of protected runtime PIDs covered by RuntimeProtectDigest
	ProtectPIDCount uint32

	// monotonic runtime protected PID-set mutation identifier
	RuntimeProtectEpoch uint64

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
	magic                uint32
	version              uint16
	totalSize            uint16
	validUntil           uint64
	flags                uint32
	nonce                [32]byte
	sigAlg               uint16
	hashAlg              uint16
	pcrMask              uint32
	policy               [32]byte
	runtimeProtectDigest [32]byte
	protectPIDCount      uint32
	runtimeProtectEpoch  uint64
	pidListSize          uint16
	attestSize           uint16
	sigSize              uint16
	reserved             uint16
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

	pidListData := tokenData[TokenHeaderSize : TokenHeaderSize+int(hdr.pidListSize)]
	attestData := tokenData[TokenHeaderSize+int(hdr.pidListSize) : TokenHeaderSize+int(hdr.pidListSize)+int(hdr.attestSize)]
	signature := tokenData[TokenHeaderSize+int(hdr.pidListSize)+int(hdr.attestSize) : TokenHeaderSize+int(hdr.pidListSize)+int(hdr.attestSize)+int(hdr.sigSize)]

	protectedPIDs, err := parseProtectedPIDs(pidListData, hdr.protectPIDCount)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadToken, err)
	}
	runtimeDigest := computeRuntimeProtectDigest(protectedPIDs)
	if !bytes.Equal(runtimeDigest[:], hdr.runtimeProtectDigest[:]) {
		return nil, fmt.Errorf("%w: runtime protected PID digest mismatch", ErrNonceFail)
	}

	// verify RSA signature over attest_data
	if err := verifyRSASignature(attestData, signature, hdr.sigAlg, hdr.hashAlg, aikPub); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigFail, err)
	}

	// parse TPMS_ATTEST - extract extraData, signed PCR selection and PCR digest
	extraData, quotedPCRMask, pcrDigest, err := parseTPMSAttest(attestData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestParse, err)
	}
	if quotedPCRMask != hdr.pcrMask {
		return nil, fmt.Errorf("%w: pcr_mask header does not match signed quote", ErrNonceFail)
	}

	// verify nonce binding: extraData == SHA256(valid_until||flags||pcr_mask||nonce||policy_digest||runtime_protect_digest||runtime_protect_epoch)
	computedNonce := computeExpectedNonce(hdr.validUntil, hdr.flags, hdr.pcrMask, hdr.nonce, hdr.policy, hdr.runtimeProtectDigest, hdr.runtimeProtectEpoch)
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
		ExpiresAt:            time.Unix(int64(hdr.validUntil), 0),
		Flags:                hdr.flags,
		Nonce:                hdr.nonce,
		PCRMask:              hdr.pcrMask,
		PolicyDigest:         hdr.policy,
		RuntimeProtectDigest: hdr.runtimeProtectDigest,
		ProtectPIDCount:      hdr.protectPIDCount,
		RuntimeProtectEpoch:  hdr.runtimeProtectEpoch,
		PCRDigest:            pcrDigest,
		SigAlg:               hdr.sigAlg,
		HashAlg:              hdr.hashAlg,
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

func tpmHashAlgToCryptoHash(hashAlg uint16) (crypto.Hash, error) {
	switch hashAlg {
	case TPMAlgSHA256:
		return crypto.SHA256, nil
	case TPMAlgSHA384:
		return crypto.SHA384, nil
	case TPMAlgSHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: 0x%04X", hashAlg)
	}
}

// parses a serialized LOTA token WITHOUT cryptographic verification
// Claims are UNTRUSTED.
func ParseToken(tokenData []byte) (*Claims, error) {
	hdr, err := parseWireHeader(tokenData)
	if err != nil {
		return nil, err
	}

	claims := &Claims{
		ExpiresAt:            time.Unix(int64(hdr.validUntil), 0),
		Flags:                hdr.flags,
		Nonce:                hdr.nonce,
		PCRMask:              hdr.pcrMask,
		PolicyDigest:         hdr.policy,
		RuntimeProtectDigest: hdr.runtimeProtectDigest,
		ProtectPIDCount:      hdr.protectPIDCount,
		SigAlg:               hdr.sigAlg,
		HashAlg:              hdr.hashAlg,
	}

	// try to extract PCR digest from TPMS_ATTEST (best-effort)
	if hdr.attestSize > 0 {
		attestData := tokenData[TokenHeaderSize+int(hdr.pidListSize) : TokenHeaderSize+int(hdr.pidListSize)+int(hdr.attestSize)]
		_, _, pcrDigest, err := parseTPMSAttest(attestData)
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
	runtimeProtectDigest [32]byte, protectedPIDs []uint32,
	attestData, signature []byte,
) ([]byte, error) {
	if len(attestData) > MaxAttestSize {
		return nil, fmt.Errorf("attest_data too large: %d > %d", len(attestData), MaxAttestSize)
	}
	if len(signature) > MaxSigSize {
		return nil, fmt.Errorf("signature too large: %d > %d", len(signature), MaxSigSize)
	}

	if len(protectedPIDs) > MaxProtectPIDs {
		return nil, fmt.Errorf("protected_pids too large: %d > %d", len(protectedPIDs), MaxProtectPIDs)
	}
	if err := validateCanonicalPIDList(protectedPIDs); err != nil {
		return nil, fmt.Errorf("invalid protected_pids: %w", err)
	}

	pidListSize := len(protectedPIDs) * 4
	totalSize := TokenHeaderSize + len(attestData) + len(signature)
	totalSize += pidListSize
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
	copy(buf[92:124], runtimeProtectDigest[:])
	binary.LittleEndian.PutUint32(buf[124:128], uint32(len(protectedPIDs)))
	binary.LittleEndian.PutUint64(buf[128:136], 0)
	binary.LittleEndian.PutUint16(buf[136:138], uint16(pidListSize))
	binary.LittleEndian.PutUint16(buf[138:140], uint16(len(attestData)))
	binary.LittleEndian.PutUint16(buf[140:142], uint16(len(signature)))
	binary.LittleEndian.PutUint16(buf[142:144], 0)

	// variable data
	off := TokenHeaderSize
	for _, pid := range protectedPIDs {
		binary.LittleEndian.PutUint32(buf[off:off+4], pid)
		off += 4
	}
	copy(buf[off:], attestData)
	off += len(attestData)
	copy(buf[off:], signature)

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
	copy(hdr.runtimeProtectDigest[:], data[92:124])
	hdr.protectPIDCount = binary.LittleEndian.Uint32(data[124:128])
	hdr.runtimeProtectEpoch = binary.LittleEndian.Uint64(data[128:136])
	hdr.pidListSize = binary.LittleEndian.Uint16(data[136:138])
	hdr.attestSize = binary.LittleEndian.Uint16(data[138:140])
	hdr.sigSize = binary.LittleEndian.Uint16(data[140:142])
	hdr.reserved = binary.LittleEndian.Uint16(data[142:144])
	if hdr.reserved != 0 {
		return nil, fmt.Errorf("%w: reserved field must be zero", ErrBadToken)
	}
	if hdr.protectPIDCount > MaxProtectPIDs {
		return nil, fmt.Errorf("%w: protect_pid_count too large", ErrBadToken)
	}
	if hdr.pidListSize != uint16(hdr.protectPIDCount*4) {
		return nil, fmt.Errorf("%w: pid list size mismatch", ErrBadToken)
	}

	// validate sizes
	expected := int(TokenHeaderSize) + int(hdr.pidListSize) + int(hdr.attestSize) + int(hdr.sigSize)
	if expected > int(hdr.totalSize) {
		return nil, fmt.Errorf("%w: data sizes exceed total_size", ErrBadToken)
	}
	if hdr.attestSize > MaxAttestSize || hdr.sigSize > MaxSigSize {
		return nil, fmt.Errorf("%w: attest_size=%d sig_size=%d exceed limits", ErrBadToken, hdr.attestSize, hdr.sigSize)
	}

	return hdr, nil
}

// verifies the TPM RSA signature over attest_data
func verifyRSASignature(attestData, signature []byte, sigAlg uint16, hashAlg uint16, aikPub *rsa.PublicKey) error {
	h, err := tpmHashAlgToCryptoHash(hashAlg)
	if err != nil {
		return err
	}
	if !h.Available() {
		return fmt.Errorf("hash algorithm unavailable: %v", h)
	}

	digest := h.New()
	_, _ = digest.Write(attestData)
	sum := digest.Sum(nil)

	switch sigAlg {
	case TPMAlgRSAPSS:
		opts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       h,
		}
		return rsa.VerifyPSS(aikPub, h, sum, signature, opts)

	case TPMAlgRSASSA:
		return rsa.VerifyPKCS1v15(aikPub, h, sum, signature)

	default:
		return fmt.Errorf("unsupported signature algorithm: 0x%04X", sigAlg)
	}
}

func computeExpectedNonce(validUntil uint64, flags uint32, pcrMask uint32, nonce [32]byte, policyDigest [32]byte, runtimeProtectDigest [32]byte, runtimeProtectEpoch uint64) [32]byte {
	var buf [120]byte // 8 + 4 + 4 + 32 + 32 + 32 + 8
	binary.LittleEndian.PutUint64(buf[0:8], validUntil)
	binary.LittleEndian.PutUint32(buf[8:12], flags)
	binary.LittleEndian.PutUint32(buf[12:16], pcrMask)
	copy(buf[16:48], nonce[:])
	copy(buf[48:80], policyDigest[:])
	copy(buf[80:112], runtimeProtectDigest[:])
	binary.LittleEndian.PutUint64(buf[112:120], runtimeProtectEpoch)
	return sha256.Sum256(buf[:])
}

// computes the token quote nonce used in the token verification domain:
//
//	SHA256(valid_until_LE || flags_LE || pcr_mask_LE || client_nonce || policy_digest || runtime_protect_digest || runtime_protect_epoch_LE)
//
// This value is expected to match TPMS_ATTEST.extraData in the token format.
//
// NOTE: This is intentionally different from the attestation report binding
// nonce used by the remote attestation verifier/agent report path.
func ComputeTokenQuoteNonce(validUntil uint64, flags uint32, pcrMask uint32, nonce [32]byte, policyDigest [32]byte, runtimeProtectDigest [32]byte, runtimeProtectEpoch uint64) [32]byte {
	return computeExpectedNonce(validUntil, flags, pcrMask, nonce, policyDigest, runtimeProtectDigest, runtimeProtectEpoch)
}

func validateCanonicalPIDList(pids []uint32) error {
	for i := 1; i < len(pids); i++ {
		if pids[i-1] >= pids[i] {
			return fmt.Errorf("pid list must be strictly increasing")
		}
	}
	return nil
}

func parseProtectedPIDs(data []byte, count uint32) ([]uint32, error) {
	if len(data) != int(count)*4 {
		return nil, fmt.Errorf("pid list byte size mismatch")
	}
	pids := make([]uint32, count)
	for i := 0; i < int(count); i++ {
		off := i * 4
		pids[i] = binary.LittleEndian.Uint32(data[off : off+4])
	}
	if err := validateCanonicalPIDList(pids); err != nil {
		return nil, err
	}
	return pids, nil
}

func computeRuntimeProtectDigest(pids []uint32) [32]byte {
	var countLE [4]byte
	h := sha256.New()
	_, _ = h.Write([]byte("lota-runtime-protect-pids:v1\x00"))
	binary.LittleEndian.PutUint32(countLE[:], uint32(len(pids)))
	_, _ = h.Write(countLE[:])
	for _, pid := range pids {
		binary.LittleEndian.PutUint32(countLE[:], pid)
		_, _ = h.Write(countLE[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// parses a raw TPMS_ATTEST blob and extracts:
//   - extraData (the nonce embedded by the TPM)
//   - pcrMask from signed TPML_PCR_SELECTION (only lower 24 PCR bits supported)
//   - pcrDigest (the PCR composite hash, only for Quote type)
func parseTPMSAttest(data []byte) (extraData []byte, pcrMask uint32, pcrDigest []byte, err error) {
	if len(data) < 10 {
		return nil, 0, nil, fmt.Errorf("attest data too short: %d bytes", len(data))
	}

	r := bytes.NewReader(data)

	// magic (4 bytes, big-endian)
	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return nil, 0, nil, fmt.Errorf("read magic: %w", err)
	}
	if magic != tpmGeneratedValue {
		return nil, 0, nil, fmt.Errorf("%w: got 0x%08X", ErrBadMagic, magic)
	}

	// type (2 bytes, big-endian)
	var attestType uint16
	if err := binary.Read(r, binary.BigEndian, &attestType); err != nil {
		return nil, 0, nil, fmt.Errorf("read type: %w", err)
	}

	// qualifiedSigner (TPM2B_NAME: 2-byte size + data)
	var signerSize uint16
	if err := binary.Read(r, binary.BigEndian, &signerSize); err != nil {
		return nil, 0, nil, fmt.Errorf("read signer size: %w", err)
	}
	if int(signerSize) > r.Len() {
		return nil, 0, nil, fmt.Errorf("qualifiedSigner truncated: need %d bytes, have %d", signerSize, r.Len())
	}
	signerBuf := make([]byte, signerSize)
	if _, err := io.ReadFull(r, signerBuf); err != nil {
		return nil, 0, nil, fmt.Errorf("read signer: %w", err)
	}

	// extraData (TPM2B_DATA: 2-byte size + data)
	var extraSize uint16
	if err := binary.Read(r, binary.BigEndian, &extraSize); err != nil {
		return nil, 0, nil, fmt.Errorf("read extraData size: %w", err)
	}
	if int(extraSize) > r.Len() {
		return nil, 0, nil, fmt.Errorf("extraData truncated: need %d bytes, have %d", extraSize, r.Len())
	}
	extraData = make([]byte, extraSize)
	if _, err := io.ReadFull(r, extraData); err != nil {
		return nil, 0, nil, fmt.Errorf("read extraData: %w", err)
	}

	// clockInfo: clock(8) + resetCount(4) + restartCount(4) + safe(1) = 17 bytes
	clockBuf := make([]byte, 17)
	if _, err := io.ReadFull(r, clockBuf); err != nil {
		return nil, 0, nil, fmt.Errorf("read clockInfo: %w", err)
	}

	// firmwareVersion (8 bytes)
	fwBuf := make([]byte, 8)
	if _, err := io.ReadFull(r, fwBuf); err != nil {
		return nil, 0, nil, fmt.Errorf("read firmwareVersion: %w", err)
	}

	if attestType == tpmSTAttestQuote {
		// TPML_PCR_SELECTION: count(4) + array
		var pcrSelCount uint32
		if err := binary.Read(r, binary.BigEndian, &pcrSelCount); err != nil {
			return extraData, 0, nil, fmt.Errorf("read pcr selection count: %w", err)
		}

		if pcrSelCount > 16 {
			return extraData, 0, nil, fmt.Errorf("pcr selection count too large: %d", pcrSelCount)
		}

		for i := uint32(0); i < pcrSelCount; i++ {
			var hashAlg uint16
			var selectSize uint8
			if err := binary.Read(r, binary.BigEndian, &hashAlg); err != nil {
				return extraData, 0, nil, fmt.Errorf("read pcr selection hash alg: %w", err)
			}
			if err := binary.Read(r, binary.BigEndian, &selectSize); err != nil {
				return extraData, 0, nil, fmt.Errorf("read pcr selection sizeofSelect: %w", err)
			}
			if int(selectSize) > r.Len() {
				return extraData, 0, nil, fmt.Errorf("pcr selection truncated: need %d bytes, have %d", selectSize, r.Len())
			}
			selectBuf := make([]byte, selectSize)
			if _, err := io.ReadFull(r, selectBuf); err != nil {
				return extraData, 0, nil, fmt.Errorf("read pcr selection: %w", err)
			}

			for j, sel := range selectBuf {
				if j < 3 {
					pcrMask |= uint32(sel) << (8 * j)
				} else if sel != 0 {
					return extraData, 0, nil, fmt.Errorf("pcr selection contains unsupported PCR index >= 24")
				}
			}
		}

		// pcrDigest (TPM2B_DIGEST: 2-byte size + data)
		var digestSize uint16
		if err := binary.Read(r, binary.BigEndian, &digestSize); err != nil {
			return extraData, 0, nil, fmt.Errorf("read pcrDigest size: %w", err)
		}
		if int(digestSize) > r.Len() {
			return extraData, 0, nil, fmt.Errorf("pcrDigest truncated: need %d bytes, have %d", digestSize, r.Len())
		}
		pcrDigest = make([]byte, digestSize)
		if _, err := io.ReadFull(r, pcrDigest); err != nil {
			return extraData, 0, nil, fmt.Errorf("read pcrDigest: %w", err)
		}
	}

	return extraData, pcrMask, pcrDigest, nil
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
