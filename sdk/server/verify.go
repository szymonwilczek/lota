// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

// Package server verifies LOTA attestation tokens on a relying party.
package server

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

// Token wire format; the layout is in include/lota_token.h.
const (
	TokenMagic      uint32 = 0x4B544F4C // "LOTK" in memory (little-endian)
	TokenVersion    uint16 = 0x0001
	TokenHeaderSize        = 152

	MaxAttestSize = 1024
	MaxSigSize    = 512

	RegistryDigestSize = 32 // per protected PID

	MaxProtectPIDs = 180 // LOTA_TOKEN_MAX_PROTECT_PIDS

	// TokenMaxSize is the size of a token with every list and buffer full.
	TokenMaxSize = TokenHeaderSize + (MaxProtectPIDs * 4) +
		(MaxProtectPIDs * RegistryDigestSize) + MaxAttestSize +
		MaxSigSize
)

// VerifyToken refuses a token whose expiry lies more than DefaultMaxTokenAge
// plus MaxClockSkew seconds ahead. Neither is configurable.
const (
	DefaultMaxTokenAge = 300
	MaxClockSkew       = 60
)

// TPM_ALG_* identifiers of the token's signature scheme and hash.
const (
	TPMAlgRSASSA uint16 = 0x0014
	TPMAlgRSAPSS uint16 = 0x0016

	TPMAlgSHA256 uint16 = 0x000B
	TPMAlgSHA384 uint16 = 0x000C
	TPMAlgSHA512 uint16 = 0x000D
)

const (
	tpmGeneratedValue uint32 = 0xff544347
	tpmSTAttestQuote  uint16 = 0x8018

	// MaxPCRSelectSize caps a quote's sizeofSelect; a set bit past PCR 23
	// is refused.
	MaxPCRSelectSize = 8
	// MaxPCRDigestSize caps a quote's PCR digest, SHA-512 wide.
	MaxPCRDigestSize = 64

	// sizeof(TPMT_HA), the cap on qualifiedSigner and extraData
	maxTPMHASize = 2 + 64
)

// Errors returned by the functions of this package.
var (
	ErrInvalidArg   = errors.New("lota: invalid argument")
	ErrBadToken     = errors.New("lota: malformed token")
	ErrBadVersion   = errors.New("lota: unsupported token version")
	ErrSigFail      = errors.New("lota: signature verification failed")
	ErrNonceFail    = errors.New("lota: nonce mismatch")
	ErrExpired      = errors.New("lota: token expired")
	ErrFutureToken  = errors.New("lota: token validity exceeds the freshness window")
	ErrAttestParse  = errors.New("lota: failed to parse TPMS_ATTEST")
	ErrBadMagic     = errors.New("lota: invalid TPM magic in TPMS_ATTEST")
	ErrNoSignature  = errors.New("lota: token contains no signature")
	ErrNoAttestData = errors.New("lota: token contains no attestation data")
	ErrRuntimeImage = errors.New("lota: runtime image measurement does not match the quote")
	ErrBadEvidence  = errors.New("lota: boot evidence does not match the token")
)

// Claims are the fields of a token. From VerifyToken every field but Expired
// is covered by the AIK signature; from ParseToken nothing is.
type Claims struct {
	ExpiresAt            time.Time // Unix 0 when the token never expires
	Flags                uint32    // LOTA_FLAG_*
	Nonce                [32]byte
	PCRMask              uint32
	PolicyDigest         [32]byte
	RuntimeProtectDigest [32]byte
	ProtectPIDCount      uint32
	RuntimeProtectEpoch  uint64
	StoppedMS            uint64

	// PCR digest of the quote; empty when the attestation is no quote
	PCRDigest []byte

	// VerifyToken accepts RSASSA or RSAPSS with SHA-256, SHA-384 or SHA-512
	SigAlg  uint16
	HashAlg uint16

	Expired bool // a nonzero expiry has passed
}

type tokenWire struct {
	magic                 uint32
	version               uint16
	totalSize             uint16
	validUntil            uint64
	flags                 uint32
	nonce                 [32]byte
	sigAlg                uint16
	hashAlg               uint16
	pcrMask               uint32
	policy                [32]byte
	runtimeProtectDigest  [32]byte
	protectPIDCount       uint32
	runtimeProtectEpoch   uint64
	pidListSize           uint16
	attestSize            uint16
	sigSize               uint16
	runtimeProtectVersion uint16
	stoppedMS             uint64
}

const (
	runtimeProtectV1   = 1 // PID set + per-PID registry digest
	registryDigestSize = 32
)

// VerifyToken verifies a serialized token against aikPub, which must come
// from a trusted source and not from the client, and the 32-byte nonce the
// caller issued.
//
// It recomputes the runtime digest from the token's PID list and registry
// digests, checks the signature over the quote, the quoted PCR mask against
// the header, extraData against ComputeTokenQuoteNonce over the header,
// and the nonce. A token with expiry 0 never expires.
//
// On ErrExpired and ErrFutureToken the verified claims are returned with the
// error; on any other error the claims are nil. A PCR mask that differs from
// the quote's is reported as ErrNonceFail.
func VerifyToken(tokenData []byte, aikPub *rsa.PublicKey, expectedNonce []byte) (*Claims, error) {
	if aikPub == nil || len(expectedNonce) != 32 {
		return nil, ErrInvalidArg
	}

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

	registryListSize := int(hdr.protectPIDCount) * registryDigestSize

	pidListEnd := TokenHeaderSize + int(hdr.pidListSize)
	registryListEnd := pidListEnd + registryListSize
	pidListData := tokenData[TokenHeaderSize:pidListEnd]
	registryListData := tokenData[pidListEnd:registryListEnd]
	attestEnd := registryListEnd + int(hdr.attestSize)
	attestData := tokenData[registryListEnd:attestEnd]
	signature := tokenData[attestEnd : attestEnd+int(hdr.sigSize)]

	protectedPIDs, err := parseProtectedPIDs(pidListData, hdr.protectPIDCount)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadToken, err)
	}

	runtimeDigest := computeRuntimeProtectDigest(protectedPIDs,
		registryListData)
	if subtle.ConstantTimeCompare(runtimeDigest[:],
		hdr.runtimeProtectDigest[:]) != 1 {
		return nil, fmt.Errorf("%w: recomputed from the token's own "+
			"pid list and registry digests", ErrRuntimeImage)
	}

	if err := verifyRSASignature(attestData, signature, hdr.sigAlg, hdr.hashAlg, aikPub); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigFail, err)
	}

	extraData, quotedPCRMask, pcrDigest, err := parseTPMSAttest(attestData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestParse, err)
	}
	if quotedPCRMask != hdr.pcrMask {
		return nil, fmt.Errorf("%w: pcr_mask header does not match signed quote", ErrNonceFail)
	}

	computedNonce := computeExpectedNonce(hdr.validUntil, hdr.flags, hdr.pcrMask, hdr.nonce, hdr.policy, hdr.runtimeProtectDigest, hdr.runtimeProtectEpoch, hdr.stoppedMS)
	if subtle.ConstantTimeCompare(extraData, computedNonce[:]) != 1 {
		return nil, fmt.Errorf("%w: extraData does not match SHA256(metadata||nonce)", ErrNonceFail)
	}

	if subtle.ConstantTimeCompare(hdr.nonce[:], expectedNonce) != 1 {
		return nil, fmt.Errorf("%w: client nonce does not match expected", ErrNonceFail)
	}

	// time.Unix and the comparisons below need an int64
	if hdr.validUntil > math.MaxInt64 {
		return nil, fmt.Errorf("%w: valid_until out of range", ErrBadToken)
	}
	validUntil := int64(hdr.validUntil) // #nosec G115 -- bounded above

	claims := &Claims{
		ExpiresAt:            time.Unix(validUntil, 0),
		Flags:                hdr.flags,
		Nonce:                hdr.nonce,
		PCRMask:              hdr.pcrMask,
		PolicyDigest:         hdr.policy,
		RuntimeProtectDigest: hdr.runtimeProtectDigest,
		ProtectPIDCount:      hdr.protectPIDCount,
		StoppedMS:            hdr.stoppedMS,
		RuntimeProtectEpoch:  hdr.runtimeProtectEpoch,
		PCRDigest:            pcrDigest,
		SigAlg:               hdr.sigAlg,
		HashAlg:              hdr.hashAlg,
	}

	now := time.Now()
	if hdr.validUntil > 0 && now.Unix() > validUntil {
		claims.Expired = true
	}

	if claims.Expired {
		return claims, ErrExpired
	}

	// the token has no issue time, so its expiry bounds its age
	if hdr.validUntil > 0 &&
		validUntil > now.Unix()+DefaultMaxTokenAge+MaxClockSkew {
		return claims, ErrFutureToken
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

// ParseToken decodes a token without verifying it, so its claims prove
// nothing. PCRDigest is filled when the quote parses.
func ParseToken(tokenData []byte) (*Claims, error) {
	hdr, err := parseWireHeader(tokenData)
	if err != nil {
		return nil, err
	}

	if hdr.validUntil > math.MaxInt64 {
		return nil, fmt.Errorf("%w: valid_until out of range", ErrBadToken)
	}
	validUntil := int64(hdr.validUntil) // #nosec G115 -- bounded above

	claims := &Claims{
		ExpiresAt:            time.Unix(validUntil, 0),
		Flags:                hdr.flags,
		Nonce:                hdr.nonce,
		PCRMask:              hdr.pcrMask,
		PolicyDigest:         hdr.policy,
		RuntimeProtectDigest: hdr.runtimeProtectDigest,
		RuntimeProtectEpoch:  hdr.runtimeProtectEpoch,
		ProtectPIDCount:      hdr.protectPIDCount,
		StoppedMS:            hdr.stoppedMS,
		SigAlg:               hdr.sigAlg,
		HashAlg:              hdr.hashAlg,
	}

	if hdr.attestSize > 0 {
		registryListSize := int(hdr.protectPIDCount) *
			registryDigestSize
		attestStart := TokenHeaderSize + int(hdr.pidListSize) +
			registryListSize
		attestData := tokenData[attestStart : attestStart+int(hdr.attestSize)]
		_, _, pcrDigest, err := parseTPMSAttest(attestData)
		if err == nil {
			claims.PCRDigest = pcrDigest
		}
	}

	if hdr.validUntil > 0 && time.Now().Unix() > validUntil {
		claims.Expired = true
	}

	return claims, nil
}

// SerializeToken encodes a token, as lota_token_serialize() does in C.
// protectedPIDs must be strictly increasing with one registry digest
// each, and runtimeProtectDigest must be ComputeRuntimeProtectDigest
// over them; the digest is not checked here.
func SerializeToken(validUntil uint64, flags uint32, nonce [32]byte,
	sigAlg, hashAlg uint16, pcrMask uint32, policyDigest [32]byte,
	runtimeProtectDigest [32]byte, runtimeProtectEpoch, stoppedMS uint64,
	protectedPIDs []uint32, registryDigests [][32]byte,
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
	if len(registryDigests) != len(protectedPIDs) {
		return nil, fmt.Errorf(
			"registry digest count %d != pid count %d",
			len(registryDigests), len(protectedPIDs))
	}
	if err := validateCanonicalPIDList(protectedPIDs); err != nil {
		return nil, fmt.Errorf("invalid protected_pids: %w", err)
	}

	pidListSize := len(protectedPIDs) * 4
	registryListSize := len(protectedPIDs) * registryDigestSize
	totalSize := TokenHeaderSize + pidListSize + registryListSize +
		len(attestData) + len(signature)
	buf := make([]byte, totalSize)

	binary.LittleEndian.PutUint32(buf[0:4], TokenMagic)
	binary.LittleEndian.PutUint16(buf[4:6], TokenVersion)
	binary.LittleEndian.PutUint16(buf[6:8], uint16(totalSize)) // #nosec G115 -- bounded by the size checks above
	binary.LittleEndian.PutUint64(buf[8:16], validUntil)
	binary.LittleEndian.PutUint32(buf[16:20], flags)
	copy(buf[20:52], nonce[:])
	binary.LittleEndian.PutUint16(buf[52:54], sigAlg)
	binary.LittleEndian.PutUint16(buf[54:56], hashAlg)
	binary.LittleEndian.PutUint32(buf[56:60], pcrMask)
	copy(buf[60:92], policyDigest[:])
	copy(buf[92:124], runtimeProtectDigest[:])
	binary.LittleEndian.PutUint32(buf[124:128], uint32(len(protectedPIDs))) // #nosec G115 -- bounded by MaxProtectPIDs above
	binary.LittleEndian.PutUint64(buf[128:136], runtimeProtectEpoch)
	binary.LittleEndian.PutUint16(buf[136:138], uint16(pidListSize))     // #nosec G115 -- bounded by MaxProtectPIDs above
	binary.LittleEndian.PutUint16(buf[138:140], uint16(len(attestData))) // #nosec G115 -- bounded by MaxAttestSize above
	binary.LittleEndian.PutUint16(buf[140:142], uint16(len(signature)))  // #nosec G115 -- bounded by MaxSigSize above
	binary.LittleEndian.PutUint16(buf[142:144], runtimeProtectV1)
	binary.LittleEndian.PutUint64(buf[144:152], stoppedMS)

	off := TokenHeaderSize
	for _, pid := range protectedPIDs {
		binary.LittleEndian.PutUint32(buf[off:off+4], pid)
		off += 4
	}
	for _, d := range registryDigests {
		copy(buf[off:off+registryDigestSize], d[:])
		off += registryDigestSize
	}
	copy(buf[off:], attestData)
	off += len(attestData)
	copy(buf[off:], signature)

	return buf, nil
}

// ComputeRuntimeProtectDigest returns the runtime protect digest of the PID
// set and its registry digests, the value a token's header carries.
func ComputeRuntimeProtectDigest(pids []uint32,
	registryDigests [][32]byte,
) [32]byte {
	registryList := make([]byte, len(registryDigests)*registryDigestSize)
	for i, d := range registryDigests {
		copy(registryList[i*registryDigestSize:], d[:])
	}
	return computeRuntimeProtectDigest(pids, registryList)
}

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
	hdr.runtimeProtectVersion = binary.LittleEndian.Uint16(data[142:144])
	hdr.stoppedMS = binary.LittleEndian.Uint64(data[144:152])
	if hdr.runtimeProtectVersion != runtimeProtectV1 {
		return nil, fmt.Errorf("%w: unsupported runtime protect version", ErrBadToken)
	}
	if hdr.protectPIDCount > MaxProtectPIDs {
		return nil, fmt.Errorf("%w: protect_pid_count too large", ErrBadToken)
	}
	if uint32(hdr.pidListSize) != hdr.protectPIDCount*4 {
		return nil, fmt.Errorf("%w: pid list size mismatch", ErrBadToken)
	}

	registryListSize := int(hdr.protectPIDCount) * registryDigestSize
	expected := int(TokenHeaderSize) + int(hdr.pidListSize) +
		registryListSize + int(hdr.attestSize) + int(hdr.sigSize)
	if expected > int(hdr.totalSize) {
		return nil, fmt.Errorf("%w: data sizes exceed total_size", ErrBadToken)
	}
	if hdr.attestSize > MaxAttestSize || hdr.sigSize > MaxSigSize {
		return nil, fmt.Errorf("%w: attest_size=%d sig_size=%d exceed limits", ErrBadToken, hdr.attestSize, hdr.sigSize)
	}

	return hdr, nil
}

func verifyRSASignature(attestData, signature []byte, sigAlg, hashAlg uint16, aikPub *rsa.PublicKey) error {
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

func computeExpectedNonce(validUntil uint64, flags, pcrMask uint32, nonce, policyDigest, runtimeProtectDigest [32]byte, runtimeProtectEpoch, stoppedMS uint64) [32]byte {
	var buf [128]byte // 8 + 4 + 4 + 32 + 32 + 32 + 8 + 8
	binary.LittleEndian.PutUint64(buf[0:8], validUntil)
	binary.LittleEndian.PutUint32(buf[8:12], flags)
	binary.LittleEndian.PutUint32(buf[12:16], pcrMask)
	copy(buf[16:48], nonce[:])
	copy(buf[48:80], policyDigest[:])
	copy(buf[80:112], runtimeProtectDigest[:])
	binary.LittleEndian.PutUint64(buf[112:120], runtimeProtectEpoch)
	binary.LittleEndian.PutUint64(buf[120:128], stoppedMS)
	return sha256.Sum256(buf[:])
}

// ComputeTokenQuoteNonce returns the extraData a token's quote must carry:
//
//	SHA256(valid_until || flags || pcr_mask || nonce || policy_digest ||
//	       runtime_protect_digest || runtime_protect_epoch || stopped_ms)
//
// with the integers little-endian. It differs from the binding nonce of an
// attestation report.
func ComputeTokenQuoteNonce(validUntil uint64, flags, pcrMask uint32, nonce, policyDigest, runtimeProtectDigest [32]byte, runtimeProtectEpoch, stoppedMS uint64) [32]byte {
	return computeExpectedNonce(validUntil, flags, pcrMask, nonce, policyDigest, runtimeProtectDigest, runtimeProtectEpoch, stoppedMS)
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

// computeRuntimeProtectDigest mirrors lota_compute_runtime_protect_digest().
// registryList holds one 32-byte digest per PID, in PID order.
func computeRuntimeProtectDigest(pids []uint32, registryList []byte) [32]byte {
	var le [4]byte
	h := sha256.New()
	_, _ = h.Write([]byte("lota-runtime-protect-pids:v1\x00"))
	// #nosec G115 -- the PID list is a wire field capped at MaxProtectPIDs
	binary.LittleEndian.PutUint32(le[:], uint32(len(pids)))
	_, _ = h.Write(le[:])
	for i, pid := range pids {
		binary.LittleEndian.PutUint32(le[:], pid)
		_, _ = h.Write(le[:])
		off := i * registryDigestSize
		_, _ = h.Write(registryList[off : off+registryDigestSize])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// parseTPMSAttest returns extraData and, for a quote, its PCR mask and PCR
// digest. A selection of a bank other than SHA-256 is refused.
func parseTPMSAttest(data []byte) (extraData []byte, pcrMask uint32, pcrDigest []byte, err error) {
	if len(data) < 10 {
		return nil, 0, nil, fmt.Errorf("attest data too short: %d bytes", len(data))
	}

	r := bytes.NewReader(data)

	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return nil, 0, nil, fmt.Errorf("read magic: %w", err)
	}
	if magic != tpmGeneratedValue {
		return nil, 0, nil, fmt.Errorf("%w: got 0x%08X", ErrBadMagic, magic)
	}

	var attestType uint16
	if err := binary.Read(r, binary.BigEndian, &attestType); err != nil {
		return nil, 0, nil, fmt.Errorf("read type: %w", err)
	}

	var signerSize uint16
	if err := binary.Read(r, binary.BigEndian, &signerSize); err != nil {
		return nil, 0, nil, fmt.Errorf("read signer size: %w", err)
	}
	if signerSize > maxTPMHASize {
		return nil, 0, nil, fmt.Errorf("qualifiedSigner too large: %d > %d", signerSize, maxTPMHASize)
	}
	if int(signerSize) > r.Len() {
		return nil, 0, nil, fmt.Errorf("qualifiedSigner truncated: need %d bytes, have %d", signerSize, r.Len())
	}
	signerBuf := make([]byte, signerSize)
	if _, err := io.ReadFull(r, signerBuf); err != nil {
		return nil, 0, nil, fmt.Errorf("read signer: %w", err)
	}

	var extraSize uint16
	if err := binary.Read(r, binary.BigEndian, &extraSize); err != nil {
		return nil, 0, nil, fmt.Errorf("read extraData size: %w", err)
	}
	if extraSize > maxTPMHASize {
		return nil, 0, nil, fmt.Errorf("extraData too large: %d > %d", extraSize, maxTPMHASize)
	}
	if int(extraSize) > r.Len() {
		return nil, 0, nil, fmt.Errorf("extraData truncated: need %d bytes, have %d", extraSize, r.Len())
	}
	extraData = make([]byte, extraSize)
	if _, err := io.ReadFull(r, extraData); err != nil {
		return nil, 0, nil, fmt.Errorf("read extraData: %w", err)
	}

	// clockInfo
	clockBuf := make([]byte, 17)
	if _, err := io.ReadFull(r, clockBuf); err != nil {
		return nil, 0, nil, fmt.Errorf("read clockInfo: %w", err)
	}

	fwBuf := make([]byte, 8)
	if _, err := io.ReadFull(r, fwBuf); err != nil {
		return nil, 0, nil, fmt.Errorf("read firmwareVersion: %w", err)
	}

	if attestType == tpmSTAttestQuote {
		var pcrSelCount uint32
		if err := binary.Read(r, binary.BigEndian, &pcrSelCount); err != nil {
			return nil, 0, nil, fmt.Errorf("read pcr selection count: %w", err)
		}

		if pcrSelCount > 16 {
			return nil, 0, nil, fmt.Errorf("pcr selection count too large: %d", pcrSelCount)
		}

		for i := uint32(0); i < pcrSelCount; i++ {
			var hashAlg uint16
			var selectSize uint8
			if err := binary.Read(r, binary.BigEndian, &hashAlg); err != nil {
				return nil, 0, nil, fmt.Errorf("read pcr selection hash alg: %w", err)
			}
			if hashAlg != TPMAlgSHA256 {
				return nil, 0, nil, fmt.Errorf("unsupported/mixed PCR bank hash alg: 0x%04X", hashAlg)
			}
			if err := binary.Read(r, binary.BigEndian, &selectSize); err != nil {
				return nil, 0, nil, fmt.Errorf("read pcr selection sizeofSelect: %w", err)
			}
			if selectSize > MaxPCRSelectSize {
				return nil, 0, nil, fmt.Errorf("pcr selection too large: %d > %d", selectSize, MaxPCRSelectSize)
			}
			if int(selectSize) > r.Len() {
				return nil, 0, nil, fmt.Errorf("pcr selection truncated: need %d bytes, have %d", selectSize, r.Len())
			}
			selectBuf := make([]byte, selectSize)
			if _, err := io.ReadFull(r, selectBuf); err != nil {
				return nil, 0, nil, fmt.Errorf("read pcr selection: %w", err)
			}

			for j, sel := range selectBuf {
				if j < 3 {
					pcrMask |= uint32(sel) << (8 * j)
				} else if sel != 0 {
					return nil, 0, nil, fmt.Errorf("pcr selection contains unsupported PCR index >= 24")
				}
			}
		}

		var digestSize uint16
		if err := binary.Read(r, binary.BigEndian, &digestSize); err != nil {
			return nil, 0, nil, fmt.Errorf("read pcrDigest size: %w", err)
		}
		if digestSize > MaxPCRDigestSize {
			return nil, 0, nil, fmt.Errorf("pcrDigest too large: %d > %d", digestSize, MaxPCRDigestSize)
		}
		if int(digestSize) > r.Len() {
			return nil, 0, nil, fmt.Errorf("pcrDigest truncated: need %d bytes, have %d", digestSize, r.Len())
		}
		pcrDigest = make([]byte, digestSize)
		if _, err := io.ReadFull(r, pcrDigest); err != nil {
			return nil, 0, nil, fmt.Errorf("read pcrDigest: %w", err)
		}
	}

	return extraData, pcrMask, pcrDigest, nil
}

// ParseRSAPublicKey parses a DER SubjectPublicKeyInfo RSA key of at least
// 2048 bits.
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
