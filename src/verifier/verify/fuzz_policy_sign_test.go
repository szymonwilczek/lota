// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
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

		// full differential against the primitive:
		// acceptance must match correctly-sized signature that ed25519.Verify
		// also accepts, and reject must correspond to bad size or bad signature.
		// One-directional check would miss false rejects (valid signature the
		// wrapper wrongly refuses)
		want := len(sig) == PolicySigSize && ed25519.Verify(key, data, sig)
		if want && err != nil {
			t.Fatalf("VerifyPolicySignature rejected a valid signature: %v", err)
		}
		if !want && err == nil {
			t.Fatal("VerifyPolicySignature accepted an invalid signature")
		}
	})
}
