// SPDX-License-Identifier: MIT
package server

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// creates a minimal valid TPMS_ATTEST blob with the given extraData (nonce) and PCR digest
func buildFakeTPMSAttest(extraData []byte, pcrDigest []byte) []byte {
	var buf bytes.Buffer

	// magic (4 bytes, big-endian): TPM_GENERATED_VALUE
	binary.Write(&buf, binary.BigEndian, uint32(0xff544347))

	// type (2 bytes): TPM_ST_ATTEST_QUOTE
	binary.Write(&buf, binary.BigEndian, uint16(0x8018))

	// qualifiedSigner (TPM2B_NAME): short fake
	binary.Write(&buf, binary.BigEndian, uint16(4)) // size
	buf.Write([]byte{0x00, 0x0B, 0xAA, 0xBB})       // hash alg + 2 bytes

	// extraData (TPM2B_DATA)
	binary.Write(&buf, binary.BigEndian, uint16(len(extraData)))
	buf.Write(extraData)

	// clockInfo: clock(8) + resetCount(4) + restartCount(4) + safe(1) = 17
	buf.Write(make([]byte, 17))

	// firmwareVersion (8 bytes)
	buf.Write(make([]byte, 8))

	// TPMS_QUOTE_INFO:
	// TPML_PCR_SELECTION: count=1
	binary.Write(&buf, binary.BigEndian, uint32(1))
	// TPMS_PCR_SELECTION: hash=SHA-256(0x000B), sizeOfSelect=3, select=PCR0+14
	binary.Write(&buf, binary.BigEndian, uint16(0x000B))
	buf.WriteByte(3)                    // sizeOfSelect
	buf.Write([]byte{0x01, 0x00, 0x40}) // PCR 0 and PCR 14

	// pcrDigest (TPM2B_DIGEST)
	binary.Write(&buf, binary.BigEndian, uint16(len(pcrDigest)))
	buf.Write(pcrDigest)

	return buf.Bytes()
}

// signs the attest data with RSASSA-PKCS1v15(SHA-256)
func signAttest(t *testing.T, priv *rsa.PrivateKey, attestData []byte) []byte {
	t.Helper()
	hash := sha256.Sum256(attestData)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15 failed: %v", err)
	}
	return sig
}

// builds a complete serialized token for testing
func buildTestToken(t *testing.T, priv *rsa.PrivateKey, issuedAt, validUntil uint64,
	flags uint32, nonce [32]byte, pcrMask uint32, pcrDigest []byte,
) []byte {
	t.Helper()

	// compute expected nonce = SHA256(issued_at||valid_until||flags||nonce)
	expectedNonce := computeExpectedNonce(issuedAt, validUntil, flags, nonce)

	// build TPMS_ATTEST with the expected nonce as extraData
	attestData := buildFakeTPMSAttest(expectedNonce[:], pcrDigest)

	// sign
	signature := signAttest(t, priv, attestData)

	// serialize
	tok, err := SerializeToken(issuedAt, validUntil, flags, nonce,
		TPMAlgRSASSA, 0x000B, pcrMask, attestData, signature)
	if err != nil {
		t.Fatalf("SerializeToken: %v", err)
	}

	return tok
}

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func TestSerializeParseRoundtrip(t *testing.T) {
	nonce := [32]byte{1, 2, 3, 4, 5}
	issuedAt := uint64(time.Now().Unix())
	validUntil := uint64(time.Now().Add(time.Hour).Unix())
	flags := uint32(0x07) // ATTESTED|TPM_OK|IOMMU_OK

	attestData := []byte("fake-attest-data-for-testing")
	signature := []byte("fake-signature-for-testing")

	tok, err := SerializeToken(issuedAt, validUntil, flags, nonce,
		TPMAlgRSASSA, 0x000B, 0x4001, attestData, signature)
	if err != nil {
		t.Fatalf("SerializeToken: %v", err)
	}

	// verify header magic
	magic := binary.LittleEndian.Uint32(tok[0:4])
	if magic != TokenMagic {
		t.Fatalf("magic = 0x%08X, want 0x%08X", magic, TokenMagic)
	}

	// parse (untrusted)
	claims, err := ParseToken(tok)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}

	if claims.IssuedAt.Unix() != int64(issuedAt) {
		t.Errorf("IssuedAt = %d, want %d", claims.IssuedAt.Unix(), issuedAt)
	}
	if claims.ExpiresAt.Unix() != int64(validUntil) {
		t.Errorf("ExpiresAt = %d, want %d", claims.ExpiresAt.Unix(), validUntil)
	}
	if claims.Flags != flags {
		t.Errorf("Flags = 0x%X, want 0x%X", claims.Flags, flags)
	}
	if claims.Nonce != nonce {
		t.Errorf("Nonce mismatch")
	}
	if claims.PCRMask != 0x4001 {
		t.Errorf("PCRMask = 0x%X, want 0x4001", claims.PCRMask)
	}
	if claims.SigAlg != TPMAlgRSASSA {
		t.Errorf("SigAlg = 0x%04X, want 0x%04X", claims.SigAlg, TPMAlgRSASSA)
	}
}

func TestVerifyToken_Success(t *testing.T) {
	key := generateTestKey(t)

	nonce := [32]byte{}
	rand.Read(nonce[:])

	issuedAt := uint64(time.Now().Unix())
	validUntil := uint64(time.Now().Add(time.Hour).Unix())
	flags := uint32(0x07)
	pcrDigest := make([]byte, 32)
	rand.Read(pcrDigest)

	tok := buildTestToken(t, key, issuedAt, validUntil, flags, nonce, 0x4001, pcrDigest)

	claims, err := VerifyToken(tok, &key.PublicKey, nil)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}

	if claims.IssuedAt.Unix() != int64(issuedAt) {
		t.Errorf("IssuedAt = %d, want %d", claims.IssuedAt.Unix(), issuedAt)
	}
	if claims.Expired {
		t.Errorf("token should not be expired")
	}
	if claims.Flags != flags {
		t.Errorf("Flags = 0x%X, want 0x%X", claims.Flags, flags)
	}
	if !bytes.Equal(claims.PCRDigest, pcrDigest) {
		t.Errorf("PCRDigest mismatch")
	}
}

func TestVerifyToken_WithExpectedNonce(t *testing.T) {
	key := generateTestKey(t)

	nonce := [32]byte{0xAA, 0xBB, 0xCC}
	issuedAt := uint64(time.Now().Unix())
	validUntil := uint64(time.Now().Add(time.Hour).Unix())

	tok := buildTestToken(t, key, issuedAt, validUntil, 0, nonce, 0, nil)

	// correct nonce
	claims, err := VerifyToken(tok, &key.PublicKey, nonce[:])
	if err != nil {
		t.Fatalf("VerifyToken with correct nonce: %v", err)
	}
	if claims.Nonce != nonce {
		t.Errorf("nonce mismatch in claims")
	}

	// wrong nonce
	wrongNonce := [32]byte{0xFF, 0xFF, 0xFF}
	_, err = VerifyToken(tok, &key.PublicKey, wrongNonce[:])
	if err == nil {
		t.Fatal("expected error for wrong nonce")
	}
}

func TestVerifyToken_BadSignature(t *testing.T) {
	key := generateTestKey(t)
	otherKey := generateTestKey(t)

	nonce := [32]byte{}
	issuedAt := uint64(time.Now().Unix())
	validUntil := uint64(time.Now().Add(time.Hour).Unix())

	tok := buildTestToken(t, key, issuedAt, validUntil, 0, nonce, 0, nil)

	// verify with wrong key
	_, err := VerifyToken(tok, &otherKey.PublicKey, nil)
	if err == nil {
		t.Fatal("expected signature verification failure")
	}
}

func TestVerifyToken_TamperedToken(t *testing.T) {
	key := generateTestKey(t)

	nonce := [32]byte{}
	issuedAt := uint64(time.Now().Unix())
	validUntil := uint64(time.Now().Add(time.Hour).Unix())

	tok := buildTestToken(t, key, issuedAt, validUntil, 0x07, nonce, 0, nil)

	// tamper with flags field (offset 24-28)
	tampered := make([]byte, len(tok))
	copy(tampered, tok)
	binary.LittleEndian.PutUint32(tampered[24:28], 0xFF) // change flags

	// signature is still valid over original attest_data, but nonce check fails
	// because SHA256(...ORIGINAL_flags...) != SHA256(...NEW_flags...)
	_, err := VerifyToken(tampered, &key.PublicKey, nil)
	if err == nil {
		t.Fatal("expected failure for tampered token")
	}
}

func TestVerifyToken_ExpiredToken(t *testing.T) {
	key := generateTestKey(t)

	nonce := [32]byte{}
	issuedAt := uint64(time.Now().Add(-2 * time.Hour).Unix())
	validUntil := uint64(time.Now().Add(-1 * time.Hour).Unix()) // expired 1h ago

	tok := buildTestToken(t, key, issuedAt, validUntil, 0, nonce, 0, nil)

	claims, err := VerifyToken(tok, &key.PublicKey, nil)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got: %v", err)
	}
	if claims == nil {
		t.Fatal("expected claims to be returned with ErrExpired")
	}
	if !claims.Expired {
		t.Error("expected Expired=true")
	}
}

func TestVerifyToken_StaleToken(t *testing.T) {
	key := generateTestKey(t)

	nonce := [32]byte{0xAA}
	// issued 1 hour ago, still valid (valid_until in future)
	issuedAt := uint64(time.Now().Add(-1 * time.Hour).Unix())
	validUntil := uint64(time.Now().Add(1 * time.Hour).Unix())

	tok := buildTestToken(t, key, issuedAt, validUntil, 0x07, nonce, 0, nil)

	claims, err := VerifyToken(tok, &key.PublicKey, nil)
	if !errors.Is(err, ErrTooOld) {
		t.Fatalf("expected ErrTooOld, got: %v", err)
	}
	if claims == nil {
		t.Fatal("expected claims to be returned with ErrTooOld")
	}
	if !claims.TooOld {
		t.Errorf("expected TooOld=true (age=%d)", claims.AgeSeconds)
	}
	if claims.Expired {
		t.Error("should not be expired (valid_until is future)")
	}
	if claims.AgeSeconds < 3500 {
		t.Errorf("AgeSeconds=%d, expected ~3600", claims.AgeSeconds)
	}
}

func TestVerifyToken_FutureToken(t *testing.T) {
	key := generateTestKey(t)

	nonce := [32]byte{0xBB}
	// issued 10 minutes in the future
	issuedAt := uint64(time.Now().Add(10 * time.Minute).Unix())
	validUntil := uint64(time.Now().Add(2 * time.Hour).Unix())

	tok := buildTestToken(t, key, issuedAt, validUntil, 0, nonce, 0, nil)

	claims, err := VerifyToken(tok, &key.PublicKey, nil)
	if !errors.Is(err, ErrFutureToken) {
		t.Fatalf("expected ErrFutureToken, got: %v", err)
	}
	if claims == nil {
		t.Fatal("expected claims to be returned with ErrFutureToken")
	}
	if !claims.IssuedInFuture {
		t.Errorf("expected IssuedInFuture=true (age=%d)", claims.AgeSeconds)
	}
	if claims.AgeSeconds >= 0 {
		t.Errorf("AgeSeconds=%d, expected negative", claims.AgeSeconds)
	}
}

func TestVerifyToken_FreshToken(t *testing.T) {
	key := generateTestKey(t)

	nonce := [32]byte{0xCC}
	// issued just now
	issuedAt := uint64(time.Now().Unix())
	validUntil := uint64(time.Now().Add(1 * time.Hour).Unix())

	tok := buildTestToken(t, key, issuedAt, validUntil, 0x07, nonce, 0x4001, nil)

	claims, err := VerifyToken(tok, &key.PublicKey, nil)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.TooOld {
		t.Errorf("fresh token should not be TooOld (age=%d)", claims.AgeSeconds)
	}
	if claims.IssuedInFuture {
		t.Errorf("fresh token should not be IssuedInFuture (age=%d)", claims.AgeSeconds)
	}
	if claims.Expired {
		t.Error("fresh token should not be Expired")
	}
	if claims.AgeSeconds < 0 || claims.AgeSeconds > 5 {
		t.Errorf("AgeSeconds=%d, expected ~0", claims.AgeSeconds)
	}
}

func TestVerifyToken_NilAIK(t *testing.T) {
	_, err := VerifyToken([]byte("whatever"), nil, nil)
	if err != ErrInvalidArg {
		t.Errorf("expected ErrInvalidArg, got %v", err)
	}
}

func TestVerifyToken_TooShort(t *testing.T) {
	key := generateTestKey(t)
	_, err := VerifyToken([]byte("short"), &key.PublicKey, nil)
	if err == nil {
		t.Fatal("expected error for short token")
	}
}

func TestVerifyToken_BadMagic(t *testing.T) {
	key := generateTestKey(t)
	tok := make([]byte, TokenHeaderSize+10)
	binary.LittleEndian.PutUint32(tok[0:4], 0xDEADBEEF)

	_, err := VerifyToken(tok, &key.PublicKey, nil)
	if err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestVerifyToken_BadVersion(t *testing.T) {
	key := generateTestKey(t)
	tok := make([]byte, TokenHeaderSize+10)
	binary.LittleEndian.PutUint32(tok[0:4], TokenMagic)
	binary.LittleEndian.PutUint16(tok[4:6], 0x9999)

	_, err := VerifyToken(tok, &key.PublicKey, nil)
	if err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestVerifyToken_RSAPSS(t *testing.T) {
	key := generateTestKey(t)

	nonce := [32]byte{0x42}
	issuedAt := uint64(time.Now().Unix())
	validUntil := uint64(time.Now().Add(time.Hour).Unix())
	flags := uint32(0x07)
	pcrDigest := make([]byte, 32)
	rand.Read(pcrDigest)

	expectedNonce := computeExpectedNonce(issuedAt, validUntil, flags, nonce)
	attestData := buildFakeTPMSAttest(expectedNonce[:], pcrDigest)

	// sign with PSS
	hash := sha256.Sum256(attestData)
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}
	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], opts)
	if err != nil {
		t.Fatalf("SignPSS: %v", err)
	}

	tok, err := SerializeToken(issuedAt, validUntil, flags, nonce,
		TPMAlgRSAPSS, 0x000B, 0x4001, attestData, signature)
	if err != nil {
		t.Fatalf("SerializeToken: %v", err)
	}

	claims, err := VerifyToken(tok, &key.PublicKey, nil)
	if err != nil {
		t.Fatalf("VerifyToken (PSS): %v", err)
	}
	if claims.SigAlg != TPMAlgRSAPSS {
		t.Errorf("SigAlg = 0x%04X, want 0x%04X", claims.SigAlg, TPMAlgRSAPSS)
	}
}

func TestSerializeToken_Limits(t *testing.T) {
	nonce := [32]byte{}

	// attest_data too large
	bigAttest := make([]byte, MaxAttestSize+1)
	_, err := SerializeToken(0, 0, 0, nonce, 0, 0, 0, bigAttest, nil)
	if err == nil {
		t.Fatal("expected error for too-large attest_data")
	}

	// signature too large
	bigSig := make([]byte, MaxSigSize+1)
	_, err = SerializeToken(0, 0, 0, nonce, 0, 0, 0, nil, bigSig)
	if err == nil {
		t.Fatal("expected error for too-large signature")
	}
}

func TestParseToken_NoAttest(t *testing.T) {
	nonce := [32]byte{}
	tok, err := SerializeToken(100, 200, 0x03, nonce, TPMAlgRSASSA, 0x000B, 0x4001, nil, nil)
	if err != nil {
		t.Fatalf("SerializeToken: %v", err)
	}

	claims, err := ParseToken(tok)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if claims.Flags != 0x03 {
		t.Errorf("Flags = 0x%X, want 0x03", claims.Flags)
	}
}

func TestComputeExpectedNonce_Deterministic(t *testing.T) {
	nonce := [32]byte{1, 2, 3}
	n1 := computeExpectedNonce(100, 200, 7, nonce)
	n2 := computeExpectedNonce(100, 200, 7, nonce)
	if n1 != n2 {
		t.Error("computeExpectedNonce should be deterministic")
	}

	// different flags -> different result
	n3 := computeExpectedNonce(100, 200, 8, nonce)
	if n1 == n3 {
		t.Error("different flags should produce different nonce")
	}
}

func TestParseTPMSAttest_InvalidMagic(t *testing.T) {
	data := make([]byte, 64)
	binary.BigEndian.PutUint32(data[0:4], 0xDEADBEEF)
	_, _, err := parseTPMSAttest(data)
	if err == nil {
		t.Fatal("expected error for invalid TPM magic")
	}
}

func TestParseTPMSAttest_TooShort(t *testing.T) {
	_, _, err := parseTPMSAttest([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
}

func TestParseRSAPublicKey(t *testing.T) {
	key := generateTestKey(t)

	// PKIX format must be accepted
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	parsed, err := ParseRSAPublicKey(der)
	if err != nil {
		t.Fatalf("ParseRSAPublicKey (PKIX): %v", err)
	}
	if parsed.N.Cmp(key.PublicKey.N) != 0 {
		t.Error("parsed key N doesn't match")
	}

	// PKCS#1 format must be rejected
	derPKCS1 := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	_, err = ParseRSAPublicKey(derPKCS1)
	if err == nil {
		t.Fatal("ParseRSAPublicKey should reject PKCS#1 format")
	}
}
