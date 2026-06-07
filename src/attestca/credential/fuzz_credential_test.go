// SPDX-License-Identifier: MIT
// LOTA attest-CA - Fuzz test for AIK public-area decoding.

package credential

import (
	"bytes"
	"testing"
)

// FuzzValidateAIK feeds attacker-controlled TPMT_PUBLIC bytes (the AIKPublic
// field of an enrollment BeginRequest) through ValidateAIK. A malformed area
// must return an error, never panic; on success the returned Name must carry
// a digest, since that digest is what binds the issued credential.
func FuzzValidateAIK(f *testing.F) {
	// seed: a well-formed restricted-signing AIK template
	modulus := bytes.Repeat([]byte{0xAB}, 256)
	if enc, err := aikTemplate(modulus).Encode(); err == nil {
		f.Add(enc)
	}
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add([]byte{})
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, name, err := ValidateAIK(data)
		if err != nil {
			return
		}
		if name.Digest == nil {
			t.Error("ValidateAIK returned a nil Name digest without error")
		}
	})
}
