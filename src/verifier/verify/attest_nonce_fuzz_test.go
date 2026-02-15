// SPDX-License-Identifier: MIT
// LOTA Verifier - Fuzz Tests for nonce verification in TPMS_ATTEST

package verify

import (
	"testing"
)

// fuzzes VerifyNonceInAttest with arbitrary attest blobs and nonces
func FuzzVerifyNonceInAttest(f *testing.F) {
	// seed 1: valid attest blob with matching nonce
	f.Add(realTPMSAttestBlob, expectedNonce)

	// seed 2: valid attest blob with wrong nonce (must fail)
	wrongNonce := make([]byte, 32)
	copy(wrongNonce, expectedNonce)
	wrongNonce[0] ^= 0xFF
	f.Add(realTPMSAttestBlob, wrongNonce)

	// seed 3: truncated blob
	f.Add(realTPMSAttestBlob[:20], expectedNonce)

	f.Fuzz(func(t *testing.T, attestData, nonce []byte) {
		err := VerifyNonceInAttest(attestData, nonce)

		// if parsing fails, nonce verification must also fail
		attest, parseErr := ParseTPMSAttest(attestData)
		if parseErr != nil {
			if err == nil {
				t.Error("VerifyNonceInAttest succeeded but ParseTPMSAttest failed")
			}
			return
		}

		// if parsing succeeds and extraData matches nonce, must succeed
		if len(attest.ExtraData) == len(nonce) {
			match := true
			for i := range nonce {
				if attest.ExtraData[i] != nonce[i] {
					match = false
					break
				}
			}
			if match && err != nil {
				t.Errorf("VerifyNonceInAttest failed for matching nonce: %v", err)
			}
			if !match && err == nil {
				t.Error("VerifyNonceInAttest succeeded for non-matching nonce")
			}
		}
	})
}

// fuzzes GetNonceFromAttest with arbitrary blobs
func FuzzGetNonceFromAttest(f *testing.F) {
	f.Add(realTPMSAttestBlob)
	f.Add(realTPMSAttestBlob[:20])
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		nonce, err := GetNonceFromAttest(data)

		attest, parseErr := ParseTPMSAttest(data)
		if parseErr != nil {
			if err == nil {
				t.Error("GetNonceFromAttest succeeded but ParseTPMSAttest failed")
			}
			if nonce != nil {
				t.Error("GetNonceFromAttest returned non-nil nonce with error")
			}
			return
		}

		if err != nil {
			t.Errorf("GetNonceFromAttest failed but ParseTPMSAttest succeeded: %v", err)
			return
		}

		if len(nonce) != len(attest.ExtraData) {
			t.Errorf("nonce length %d != extraData length %d", len(nonce), len(attest.ExtraData))
		}
	})
}
