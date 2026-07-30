// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"testing"
)

// profileVerifier builds a verifier whose active policy declares the given fleet
// profile, with the command-line override in whatever state the caller wants.
func profileVerifier(t *testing.T, profile string, override *bool) *Verifier {
	t.Helper()

	cfg := DefaultConfig()
	cfg.EnableSelfServiceReanchor = override

	v := NewVerifier(cfg, newCertStore(t))
	policy := DefaultPolicy()
	policy.Profile = profile
	if err := v.AddPolicy(policy); err != nil {
		t.Fatalf("AddPolicy(profile=%q): %v", profile, err)
	}
	if err := v.SetActivePolicy("default"); err != nil {
		t.Fatalf("SetActivePolicy: %v", err)
	}
	return v
}

// Consumer profile is what fleet of machines the relying party does not own
// declares, and it is the whole reason the knob moved into the policy.
func TestSelfServiceReanchor_ConsumerProfileEnablesIt(t *testing.T) {
	v := profileVerifier(t, ProfileConsumer, nil)
	if !v.selfServiceReanchorForTenant("") {
		t.Fatal("consumer profile must enable self-service re-anchor")
	}
}

// Enterprise treats firmware drift as finding, so it stays off.
// So does unset profile: policy written before profiles existed must not acquire
// the permissive handling by silence.
func TestSelfServiceReanchor_EnterpriseAndUnsetLeaveItOff(t *testing.T) {
	for _, profile := range []string{ProfileEnterprise, ""} {
		v := profileVerifier(t, profile, nil)
		if v.selfServiceReanchorForTenant("") {
			t.Fatalf("profile %q must leave self-service re-anchor off", profile)
		}
	}
}

// Flag overrides the policy in both directions, which is the point of it being
// override rather than second way to switch it on.
func TestSelfServiceReanchor_FlagOverridesPolicyBothWays(t *testing.T) {
	on, off := true, false

	if v := profileVerifier(t, ProfileEnterprise, &on); !v.selfServiceReanchorForTenant("") {
		t.Fatal("--enable-self-service-reanchor must override an enterprise policy")
	}
	if v := profileVerifier(t, ProfileConsumer, &off); v.selfServiceReanchorForTenant("") {
		t.Fatal("--enable-self-service-reanchor=false must override a consumer policy")
	}
}

// Tenant with no policy of its own falls back to the active policy, which is how
// every other gate resolves; the profile must not invent second rule.
func TestSelfServiceReanchor_TenantWithoutPolicyFollowsTheActiveOne(t *testing.T) {
	v := profileVerifier(t, ProfileConsumer, nil)
	if !v.selfServiceReanchorForTenant("tenant-with-no-policy-of-its-own") {
		t.Fatal("a tenant without its own policy must follow the active policy")
	}

	v = profileVerifier(t, ProfileEnterprise, nil)
	if v.selfServiceReanchorForTenant("tenant-with-no-policy-of-its-own") {
		t.Fatal("the fallback must carry the active policy's profile, not a default of its own")
	}
}

// With no policy at all there is nothing to consent on the fleet's behalf.
func TestSelfServiceReanchor_NoPolicyMeansOff(t *testing.T) {
	v := NewVerifier(DefaultConfig(), newCertStore(t))
	if v.selfServiceReanchorForTenant("") {
		t.Fatal("a verifier with no policy must not re-anchor")
	}
}

// Typo must not be read as "not consumer" and quietly leave diverse fleet on
// the enterprise handling: the operator would find out from players whose games
// stopped after a BIOS update.
func TestAddPolicy_RejectsUnknownProfile(t *testing.T) {
	v := NewVerifier(DefaultConfig(), newCertStore(t))
	policy := DefaultPolicy()
	policy.Profile = "consumr"

	if err := v.AddPolicy(policy); err == nil {
		t.Fatal("expected AddPolicy to refuse an unknown profile")
	}
}

func TestAddPolicy_AcceptsKnownProfiles(t *testing.T) {
	for _, profile := range []string{"", ProfileEnterprise, ProfileConsumer} {
		v := NewVerifier(DefaultConfig(), newCertStore(t))
		policy := DefaultPolicy()
		policy.Profile = profile
		if err := v.AddPolicy(policy); err != nil {
			t.Fatalf("AddPolicy(profile=%q): %v", profile, err)
		}
	}
}
