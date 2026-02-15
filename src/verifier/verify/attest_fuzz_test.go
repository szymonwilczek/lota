// SPDX-License-Identifier: MIT
// LOTA Verifier - Fuzz Tests

package verify

import (
	"crypto/sha256"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

// fuzzes the TPMS_ATTEST parser
func FuzzParseTPMSAttest(f *testing.F) {
	f.Add(realTPMSAttestBlob)

	f.Fuzz(func(t *testing.T, data []byte) {
		attest, err := ParseTPMSAttest(data)
		if err != nil {
			if attest != nil {
				t.Error("ParseTPMSAttest returned non-nil attest with error")
			}
			return
		}

		if attest == nil {
			t.Error("ParseTPMSAttest returned nil without error")
		}
	})
}

// fuzzes the PCR digest verification logic
func FuzzVerifyPCRDigest(f *testing.F) {
	pcrMask := uint32((1 << 0) | (1 << 1) | (1 << 14))
	var pcrValues [types.PCRCount][types.HashSize]byte
	for i := 0; i < types.HashSize; i++ {
		pcrValues[0][i] = byte(i)
		pcrValues[1][i] = byte(i + 0x20)
		pcrValues[14][i] = byte(i + 0x40)
	}

	h := sha256.New()
	h.Write(pcrValues[0][:])
	h.Write(pcrValues[1][:])
	h.Write(pcrValues[14][:])
	digest := h.Sum(nil)

	validBlob := buildTestAttestBlob(digest)

	f.Add(validBlob, []byte("valid args"))

	f.Fuzz(func(t *testing.T, attestData []byte, _ []byte) {
		_ = VerifyPCRDigest(attestData, pcrValues, pcrMask)
	})
}
