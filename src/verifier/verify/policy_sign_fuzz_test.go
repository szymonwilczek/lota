// SPDX-License-Identifier: MIT
// LOTA Verifier - Fuzz tests for Ed25519 policy signature verification

package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func FuzzVerifyPolicySignature(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}

	// seed: valid data + valid signature
	data := []byte("require_secureboot: true\nrequire_iommu: true\n")
	sig := ed25519.Sign(priv, data)
	f.Add(data, sig, []byte(pub))

	// seed: valid data + wrong-length signature (63 bytes)
	f.Add(data, sig[:63], []byte(pub))

	// seed: empty data + valid-length signature
	f.Add([]byte{}, make([]byte, PolicySigSize), []byte(pub))

	f.Fuzz(func(t *testing.T, data, sig, keyBytes []byte) {
		if len(keyBytes) != ed25519.PublicKeySize {
			return // skip invalid key sizes
		}
		key := ed25519.PublicKey(keyBytes)
		err := VerifyPolicySignature(data, sig, key)
		if err == nil {
			// signature accepted — verify it actually checks out
			if !ed25519.Verify(key, data, sig) {
				t.Fatal("VerifyPolicySignature accepted a signature that ed25519.Verify rejects")
			}
		}
	})
}
