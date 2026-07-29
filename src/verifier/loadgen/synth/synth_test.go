// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Load Generator - Synthetic fleet acceptance tests
//
// Load numbers are only meaningful if the synthetic reports walk the same
// verification path a real agent does, so the core test drives production-configured
// Verifier (certificate-verifying AIK store, default strict config, the generated rig
// policy loaded from YAML) and requires VERIFY_OK end to end

package synth

import (
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// newRigVerifier builds a Verifier exactly the way src/verifier/main.go does for production:
// certificate-verifying AIK store trusting the rig CA,
// strict DefaultConfig,
// rig policy loaded from generated YAML
func newRigVerifier(t *testing.T, fleet *Fleet) *verify.Verifier {
	t.Helper()
	dir := t.TempDir()

	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, fleet.CA.CertPEM(), 0o600); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}
	aikStore, err := store.NewCertificateStore(filepath.Join(dir, "aiks"), []string{caPath}, true)
	if err != nil {
		t.Fatalf("NewCertificateStore: %v", err)
	}

	v := verify.NewVerifier(verify.DefaultConfig(), aikStore)
	t.Cleanup(v.Close)

	policyYAML, err := fleet.PolicyYAML()
	if err != nil {
		t.Fatalf("PolicyYAML: %v", err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, policyYAML, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := v.LoadPolicy(policyPath); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if err := v.SetActivePolicy(PolicyName); err != nil {
		t.Fatalf("SetActivePolicy: %v", err)
	}
	return v
}

func newTestFleet(t *testing.T, n, keyPool int) *Fleet {
	t.Helper()
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	fleet, err := NewFleet(ca, n, keyPool)
	if err != nil {
		t.Fatalf("NewFleet: %v", err)
	}
	return fleet
}

func attestOnce(t *testing.T, v *verify.Verifier, fleet *Fleet, a *Agent, challengeID string) *types.VerifyResult {
	t.Helper()
	ch, err := v.GenerateChallenge(challengeID)
	if err != nil {
		t.Fatalf("GenerateChallenge(%s): %v", challengeID, err)
	}
	report, err := fleet.BuildReport(a, ch.Nonce)
	if err != nil {
		t.Fatalf("BuildReport(%s): %v", a.Name, err)
	}
	result, err := v.VerifyReport(challengeID, report)
	if err != nil {
		t.Logf("VerifyReport(%s): %v", a.Name, err)
	}
	return result
}

// Full fleet passes first attestation (registration) and second steady-state
// round against the strict production configuration
func TestFleetPassesProductionVerification(t *testing.T) {
	fleet := newTestFleet(t, 3, 2)
	v := newRigVerifier(t, fleet)

	for round := range 2 {
		for i, a := range fleet.Agents {
			challengeID := AgentName(i) + "-r" + string(rune('0'+round))
			result := attestOnce(t, v, fleet, a, challengeID)
			if result.Result != types.VerifyOK {
				t.Fatalf("round %d agent %s: got %s, want ok",
					round, a.Name, types.VerifyResultString(result.Result))
			}
			if round == 1 && result.SessionToken == [32]byte{} {
				t.Errorf("agent %s: no session token on steady-state attestation", a.Name)
			}
		}
	}
}

// tampered PCR value must be rejected:
// proves the quote signature binding is live in the synthetic path,
// not bypassed
func TestTamperedReportRejected(t *testing.T) {
	fleet := newTestFleet(t, 1, 1)
	v := newRigVerifier(t, fleet)
	a := fleet.Agents[0]

	ch, err := v.GenerateChallenge("tamper")
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	report, err := fleet.BuildReport(a, ch.Nonce)
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}
	// flip one byte of PCR0 (offset 16 = first PCR value)
	report[16] ^= 0xFF

	result, _ := v.VerifyReport("tamper", report)
	if result.Result == types.VerifyOK {
		t.Fatal("tampered report accepted")
	}
}

// agent hash outside the policy allowlist must be rejected:
// rig policy actually pins agent_hashes
func TestForeignAgentHashRejected(t *testing.T) {
	fleet := newTestFleet(t, 1, 1)
	v := newRigVerifier(t, fleet)

	fleet.AgentHash[0] ^= 0xFF // report + PCR14 stay self-consistent

	result := attestOnce(t, v, fleet, fleet.Agents[0], "foreign-hash")
	if result.Result == types.VerifyOK {
		t.Fatal("report with unpinned agent hash accepted")
	}
}

// Measurement profile is deterministic across fleets, so one generated policy
// covers every rig and runs stay comparable.
// Agent identities are the opposite:
// they must be scoped to the rig, because independent rigs drive one shared
// verifier backend side by side (the dual-rig soak) and colliding pseudonyms
// silently fold two fleets onto the same baseline rows.
// Within one rig, identities must be stable across reloads so server-side state
// survives between runs.
func TestFleetProfileSharedIdentitiesRigScoped(t *testing.T) {
	f1 := newTestFleet(t, 2, 1)
	f2 := newTestFleet(t, 2, 1)

	if f1.AgentHash != f2.AgentHash || f1.KernelHash != f2.KernelHash {
		t.Error("measurement profile differs between fleets")
	}
	if f1.PCRs != f2.PCRs {
		t.Error("PCR bank differs between fleets")
	}
	if f1.PCR14() != f2.PCR14() {
		t.Error("PCR14 derivation differs between fleets")
	}
	for i := range f1.Agents {
		if f1.Agents[i].HardwareID == f2.Agents[i].HardwareID {
			t.Errorf("agent %d hardware ID collides across rigs", i)
		}
		if f1.Agents[i].Pseudonym == f2.Agents[i].Pseudonym {
			t.Errorf("agent %d pseudonym collides across rigs", i)
		}
	}

	// same CA + key pool = same rig directory reloaded:
	// identities must reproduce exactly
	keys := make([]*rsa.PrivateKey, 0, len(f1.Agents))
	for _, a := range f1.Agents {
		keys = append(keys, a.Key)
	}
	f3, err := NewFleetWithKeys(f1.CA, len(f1.Agents), keys)
	if err != nil {
		t.Fatalf("NewFleetWithKeys: %v", err)
	}
	for i := range f1.Agents {
		if f1.Agents[i].HardwareID != f3.Agents[i].HardwareID {
			t.Errorf("agent %d hardware ID unstable across rig reload", i)
		}
		if f1.Agents[i].Pseudonym != f3.Agents[i].Pseudonym {
			t.Errorf("agent %d pseudonym unstable across rig reload", i)
		}
	}
}

// CA round-trips through its PEM form
// so rig directory can be reused without re-issuing certificates
func TestCAPEMRoundTrip(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	loaded, err := LoadCA(ca.CertPEM(), ca.KeyPEM())
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if !loaded.Cert.Equal(ca.Cert) {
		t.Error("CA certificate changed across PEM round-trip")
	}
	if !loaded.Key.Equal(ca.Key) {
		t.Error("CA key changed across PEM round-trip")
	}
}

// AIK key pool round-trips through its PEM form:
// the rig directory persists it once, so a reload must hand back the same keys
// in the same order or every agent's certificate subject moves
func TestKeyPoolPEMRoundTrip(t *testing.T) {
	keys, err := GenerateKeyPool(2)
	if err != nil {
		t.Fatalf("GenerateKeyPool: %v", err)
	}
	blob, err := KeyPoolPEM(keys)
	if err != nil {
		t.Fatalf("KeyPoolPEM: %v", err)
	}
	loaded, err := LoadKeyPool(blob)
	if err != nil {
		t.Fatalf("LoadKeyPool: %v", err)
	}
	if len(loaded) != len(keys) {
		t.Fatalf("pool has %d keys after reload, want %d", len(loaded), len(keys))
	}
	for i := range keys {
		if !loaded[i].Equal(keys[i]) {
			t.Errorf("key %d changed across PEM round-trip", i)
		}
	}
}

func TestKeyPoolRejectsBadInput(t *testing.T) {
	if _, err := GenerateKeyPool(0); err == nil {
		t.Error("non-positive pool size accepted")
	}
	if _, err := LoadKeyPool([]byte("not a PEM block")); err == nil {
		t.Error("PEM-less blob accepted")
	}
	// well-formed PEM carrying something that is not an RSA key
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	if _, err := LoadKeyPool(ca.CertPEM()); err == nil {
		t.Error("certificate PEM accepted as a key pool")
	}
}
