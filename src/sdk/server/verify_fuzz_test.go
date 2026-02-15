// SPDX-License-Identifier: MIT
// LOTA SDK - Fuzz Tests for token parsing and TPMS_ATTEST parsing

package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"
)

// fuzzes ParseToken (untrusted binary token from network)
func FuzzParseToken(f *testing.F) {
	// seed 1: valid serialized token (no crypto, just wire format)
	nonce := [32]byte{0xAA, 0xBB, 0xCC}
	issuedAt := uint64(time.Now().Unix())
	validUntil := uint64(time.Now().Add(time.Hour).Unix())
	attestData := []byte("fake-attest")
	sig := []byte("fake-sig")
	validTok, _ := SerializeToken(issuedAt, validUntil, 0x07, nonce,
		TPMAlgRSASSA, 0x000B, 0x4001, attestData, sig)
	f.Add(validTok)

	// seed 2: header-only (no attest/sig)
	headerOnly, _ := SerializeToken(100, 200, 0, [32]byte{}, 0, 0, 0, nil, nil)
	f.Add(headerOnly)

	// seed 3: too short
	f.Add([]byte{0x4C, 0x4F, 0x54, 0x4B})

	// seed 4: empty
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		claims, err := ParseToken(data)
		if err != nil {
			if claims != nil {
				t.Error("ParseToken returned non-nil claims with error")
			}
			return
		}
		if claims == nil {
			t.Error("ParseToken returned nil claims without error")
		}
	})
}

// fuzzes parseWireHeader directly (72-byte binary header)
func FuzzParseWireHeader(f *testing.F) {
	nonce := [32]byte{}
	tok, _ := SerializeToken(0, 0, 0, nonce, 0, 0, 0, nil, nil)
	f.Add(tok)

	// with payload
	tok2, _ := SerializeToken(100, 200, 0x07, nonce, TPMAlgRSASSA, 0x000B, 0x4001,
		make([]byte, 64), make([]byte, 32))
	f.Add(tok2)

	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		hdr, err := parseWireHeader(data)
		if err != nil {
			if hdr != nil {
				t.Error("parseWireHeader returned non-nil header with error")
			}
			return
		}
		if hdr == nil {
			t.Error("parseWireHeader returned nil without error")
			return
		}

		// invariants: magic and version must be correct
		if hdr.magic != TokenMagic {
			t.Errorf("accepted token with wrong magic: 0x%08X", hdr.magic)
		}
		if hdr.version != TokenVersion {
			t.Errorf("accepted token with wrong version: %d", hdr.version)
		}
		// totalSize must be >= header
		if hdr.totalSize < TokenHeaderSize {
			t.Errorf("totalSize %d < header size %d", hdr.totalSize, TokenHeaderSize)
		}
		// attestSize + sigSize must fit
		if int(hdr.attestSize)+int(hdr.sigSize)+TokenHeaderSize > int(hdr.totalSize) {
			t.Error("data sizes exceed totalSize")
		}
	})
}

// fuzzes the SDK parseTPMSAttest (different impl from verifier)
func FuzzParseTPMSAttestSDK(f *testing.F) {
	// seed 1: valid TPMS_ATTEST from test helper
	pcrDigest := make([]byte, 32)
	for i := range pcrDigest {
		pcrDigest[i] = byte(i)
	}
	extraData := make([]byte, 32)
	for i := range extraData {
		extraData[i] = byte(i + 0x80)
	}
	validBlob := buildFakeTPMSAttest(extraData, pcrDigest)
	f.Add(validBlob)

	// seed 2: minimal (empty extraData, empty digest)
	minBlob := buildFakeTPMSAttest(nil, nil)
	f.Add(minBlob)

	// seed 3: truncated
	f.Add(validBlob[:10])

	// seed 4: garbage
	f.Add([]byte{0xFF, 0x54, 0x43, 0x47, 0x80, 0x18})

	f.Fuzz(func(t *testing.T, data []byte) {
		extra, digest, err := parseTPMSAttest(data)
		if err != nil {
			// on full error, both should be nil
			if extra != nil || digest != nil {
				t.Error("parseTPMSAttest returned non-nil data with error")
			}
			return
		}

		// must be non-nil (may be empty slice)
		if extra == nil {
			t.Error("parseTPMSAttest succeeded but extraData is nil")
		}
		// digest can be nil for non-quote types (partial success)
	})
}

// fuzzes the SDK ParseRSAPublicKey (CRITICAL: missing 2048-bit minimum check)
func FuzzParseRSAPublicKeySDK(f *testing.F) {
	// seed 1: valid 2048-bit RSA key in PKIX format
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	validDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	f.Add(validDER)

	// seed 2: PKCS#1 format (should be rejected)
	pkcs1DER := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	f.Add(pkcs1DER)

	// seed 3: garbage
	f.Add([]byte{0x30, 0x82, 0x00, 0x0A, 0x02, 0x03, 0x01, 0x00, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		pub, err := ParseRSAPublicKey(data)
		if err != nil {
			if pub != nil {
				t.Error("ParseRSAPublicKey returned non-nil key with error")
			}
			return
		}
		if pub == nil {
			t.Error("ParseRSAPublicKey returned nil without error")
		}
	})
}
