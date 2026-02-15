// SPDX-License-Identifier: MIT
// LOTA Verifier - Fuzz Tests for PCR policy YAML parsing and PEM key loading

package verify

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"gopkg.in/yaml.v3"
)

// fuzzes YAML -> PCRPolicy deserialization + ValidatePolicy pipeline
func FuzzParsePCRPolicy(f *testing.F) {
	// seed 1: minimal valid policy
	f.Add([]byte(`name: test
description: test policy
pcrs:
  0: "0000000000000000000000000000000000000000000000000000000000000000"
  14: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
kernel_hashes:
  - "aabbccdd"
require_iommu: true
require_enforce: true
`))

	// seed 2: empty policy (triggers warnings)
	f.Add([]byte(`name: empty
description: no requirements
`))

	// seed 3: garbage
	f.Add([]byte(`{{{invalid yaml`))

	// seed 4: deeply nested
	f.Add([]byte(`name: deep
pcrs:
  0: "00"
  1: "11"
  2: "22"
  3: "33"
  4: "44"
  5: "55"
  6: "66"
  7: "77"
  8: "88"
  9: "99"
  10: "aa"
  11: "bb"
  12: "cc"
  13: "dd"
  14: "ee"
  15: "ff"
  16: "00"
  17: "11"
  18: "22"
  19: "33"
  20: "44"
  21: "55"
  22: "66"
  23: "77"
`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var policy PCRPolicy
		err := yaml.Unmarshal(data, &policy)
		if err != nil {
			return
		}

		// validate must not panic on any successfully-parsed policy
		warnings := ValidatePolicy(&policy)

		// must have warnings
		hasReqs := policy.RequireIOMMU || policy.RequireEnforce ||
			policy.RequireModuleSig || policy.RequireSecureBoot || policy.RequireLockdown
		if len(policy.PCRs) == 0 && len(policy.KernelHashes) == 0 &&
			len(policy.AgentHashes) == 0 && !hasReqs {
			if len(warnings) == 0 {
				t.Error("empty policy should produce warnings")
			}
		}
	})
}

// fuzzes in-memory PEM->Ed25519 public key parsing
func FuzzParsePolicyPublicKeyPEM(f *testing.F) {
	// seed 1: valid Ed25519 PEM
	pub, _, _ := ed25519.GenerateKey(nil)
	derBytes, _ := x509.MarshalPKIXPublicKey(pub)
	validPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})
	f.Add(validPEM)

	// seed 2: not PEM at all
	f.Add([]byte("not a pem file"))

	// seed 3: PEM with garbage DER
	garbagePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte{0x30, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04},
	})
	f.Add(garbagePEM)

	f.Fuzz(func(t *testing.T, data []byte) {
		block, _ := pem.Decode(data)
		if block == nil {
			return
		}

		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return
		}

		edPub, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return
		}

		// key must be 32 bytes
		if len(edPub) != ed25519.PublicKeySize {
			t.Errorf("Ed25519 key size %d, want %d", len(edPub), ed25519.PublicKeySize)
		}
	})
}
