// SPDX-License-Identifier: MIT
// LOTA Verifier - PCR Policy Tests

package verify

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

func TestDefaultPolicy(t *testing.T) {
	t.Log("TEST: DefaultPolicy() creates valid baseline policy")

	policy := DefaultPolicy()

	if policy.Name != "default" {
		t.Errorf("Expected name 'default', got '%s'", policy.Name)
	}

	if len(policy.PCRs) != 0 {
		t.Errorf("Expected empty PCRs map for default policy, got %d entries", len(policy.PCRs))
	}

	if !policy.RequireEnforce {
		t.Error("Default policy should require LSM enforce mode")
	}

	t.Log("DefaultPolicy creates valid baseline policy")
}

func TestStrictPolicy(t *testing.T) {
	t.Log("TEST: StrictPolicy() creates high-security policy")

	policy := StrictPolicy()

	if policy.Name != "strict" {
		t.Errorf("Expected name 'strict', got '%s'", policy.Name)
	}

	// all security requirements should be enabled
	checks := []struct {
		name  string
		value bool
	}{
		{"RequireIOMMU", policy.RequireIOMMU},
		{"RequireEnforce", policy.RequireEnforce},
		{"RequireModuleSig", policy.RequireModuleSig},
		{"RequireSecureBoot", policy.RequireSecureBoot},
		{"RequireLockdown", policy.RequireLockdown},
	}

	for _, check := range checks {
		if !check.value {
			t.Errorf("Strict policy should have %s enabled", check.name)
		}
	}

	t.Log("StrictPolicy enables all security requirements")
}

func TestPCRVerifier_LoadPolicy(t *testing.T) {
	t.Log("SECURITY TEST: Policy loading from YAML files")

	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "test-policy.yaml")

	policyContent := `
name: test-security
description: "Test policy for unit tests"
pcrs:
  0: "b6d107af0ef8a52065f6d3c344cfc811920fa81b28dd4c746ea1ad55464c5b61"
  7: "3ea36e1ae53f0d0298e9b976b69718c043c421623a18fba2f1e40541ed3d507e"
kernel_hashes:
  - "6da97dc5886e0da1d3ce0ac1a01c82c642564460d907cfc10db9af1ca8ad97d9"
agent_hashes:
  - "db457c14130c56c599bc56c2bb888b644e3b504aaeefe6dc6aaf6c665087cf46"
require_iommu: true
require_enforce: true
require_module_sig: false
require_secureboot: false
require_lockdown: false
`
	if err := os.WriteFile(policyPath, []byte(policyContent), 0644); err != nil {
		t.Fatalf("Failed to create test policy file: %v", err)
	}

	verifier := NewPCRVerifier()
	if err := verifier.LoadPolicy(policyPath); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// should be active now
	if verifier.GetActivePolicy() != "test-security" {
		t.Errorf("Expected active policy 'test-security', got '%s'", verifier.GetActivePolicy())
	}

	// verify policy content
	policies := verifier.ListPolicies()
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}

	t.Log("Policy loaded and activated correctly from YAML")
}

func TestPCRVerifier_MultiplePolicies(t *testing.T) {
	t.Log("TEST: Multiple policy management")

	verifier := NewPCRVerifier()

	verifier.AddPolicy(DefaultPolicy())
	verifier.AddPolicy(StrictPolicy())

	policies := verifier.ListPolicies()
	if len(policies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(policies))
	}

	// first added becomes active
	if verifier.GetActivePolicy() != "default" {
		t.Errorf("Expected 'default' as active, got '%s'", verifier.GetActivePolicy())
	}

	// switch to strict
	if err := verifier.SetActivePolicy("strict"); err != nil {
		t.Errorf("Failed to set active policy: %v", err)
	}

	if verifier.GetActivePolicy() != "strict" {
		t.Errorf("Expected 'strict' as active after switch, got '%s'", verifier.GetActivePolicy())
	}

	t.Log("Multiple policies managed correctly")
}

func TestPCRVerifier_SetActivePolicy_NotFound(t *testing.T) {
	t.Log("TEST: Setting non-existent policy fails")

	verifier := NewPCRVerifier()
	verifier.AddPolicy(DefaultPolicy())

	err := verifier.SetActivePolicy("nonexistent")
	if err == nil {
		t.Error("Expected error when setting non-existent policy")
	}

	t.Log("Non-existent policy correctly rejected")
}

func TestPCRVerifier_VerifyReport_NoPolicy(t *testing.T) {
	t.Log("TEST: Verification fails without policy")

	verifier := NewPCRVerifier()
	report := &types.AttestationReport{}

	err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("Expected error when no policy configured")
	}

	t.Log("Verification correctly fails without policy")
}

func TestPCRVerifier_VerifyReport_PCRMismatch(t *testing.T) {
	t.Log("SECURITY TEST: PCR value mismatch detection")

	verifier := NewPCRVerifier()

	// policy expecting specific PCR 0 value
	policy := &PCRPolicy{
		Name: "test-pcr-check",
		PCRs: map[int]string{
			0: "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	verifier.AddPolicy(policy)

	// different PCR 0 value
	report := &types.AttestationReport{}
	report.TPM.PCRMask = 1 // PCR 0 included
	// PCR 0 as a non-zero value
	for i := 0; i < types.HashSize; i++ {
		report.TPM.PCRValues[0][i] = 0xFF
	}

	err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("Expected error for PCR mismatch")
	}

	t.Logf("PCR mismatch correctly detected: %v", err)
}

func TestPCRVerifier_VerifyReport_PCRNotInQuote(t *testing.T) {
	t.Log("SECURITY TEST: Missing PCR in quote detection")

	verifier := NewPCRVerifier()

	policy := &PCRPolicy{
		Name: "require-pcr0",
		PCRs: map[int]string{
			0: "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	verifier.AddPolicy(policy)

	// report WITHOUT PCR 0 in mask
	report := &types.AttestationReport{}
	report.TPM.PCRMask = 0x4000 // only PCR 14

	err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("Expected error when required PCR not in quote")
	}

	t.Logf("Missing PCR in quote correctly detected: %v", err)
}

func TestPCRVerifier_VerifyReport_RequireIOMMU(t *testing.T) {
	t.Log("SECURITY TEST: IOMMU requirement enforcement")

	verifier := NewPCRVerifier()

	policy := &PCRPolicy{
		Name:         "require-iommu",
		RequireIOMMU: true,
	}
	verifier.AddPolicy(policy)

	report := &types.AttestationReport{}
	// IOMMU flag not set (0x04)
	report.System.IOMMU.Flags = 0x00

	err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("Expected error when IOMMU not enabled")
	}

	t.Logf("Missing IOMMU correctly detected: %v", err)
}

func TestPCRVerifier_VerifyReport_RequireSecureBoot(t *testing.T) {
	t.Log("SECURITY TEST: Secure Boot requirement enforcement")

	verifier := NewPCRVerifier()

	policy := &PCRPolicy{
		Name:              "require-secureboot",
		RequireSecureBoot: true,
	}
	verifier.AddPolicy(policy)

	report := &types.AttestationReport{}
	report.Header.Flags = 0 // no SecureBoot flag

	err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("Expected error when SecureBoot not enabled")
	}

	t.Logf("Missing SecureBoot correctly detected: %v", err)
}

func TestPCRVerifier_VerifyReport_KernelHashAllowed(t *testing.T) {
	t.Log("SECURITY TEST: Kernel hash allowlist")

	verifier := NewPCRVerifier()

	policy := &PCRPolicy{
		Name: "kernel-allowlist",
		KernelHashes: []string{
			"6da97dc5886e0da1d3ce0ac1a01c82c642564460d907cfc10db9af1ca8ad97d9",
		},
	}
	verifier.AddPolicy(policy)

	report := &types.AttestationReport{}
	// wrong kernel hash
	for i := 0; i < types.HashSize; i++ {
		report.System.KernelHash[i] = byte(i)
	}

	err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("Expected error for non-allowlisted kernel")
	}

	t.Logf("Non-allowlisted kernel correctly rejected: %v", err)
}

func TestPCRVerifier_VerifyReport_AgentHashAllowed(t *testing.T) {
	t.Log("SECURITY TEST: Agent hash allowlist")

	verifier := NewPCRVerifier()

	policy := &PCRPolicy{
		Name: "agent-allowlist",
		AgentHashes: []string{
			"db457c14130c56c599bc56c2bb888b644e3b504aaeefe6dc6aaf6c665087cf46",
		},
	}
	verifier.AddPolicy(policy)

	report := &types.AttestationReport{}
	// wrong agent hash
	for i := 0; i < types.HashSize; i++ {
		report.System.AgentHash[i] = byte(i)
	}

	err := verifier.VerifyReport(report)
	if err == nil {
		t.Error("Expected error for non-allowlisted agent")
	}

	t.Logf("Non-allowlisted agent correctly rejected: %v", err)
}

func TestPCRVerifier_VerifyReport_PassingPolicy(t *testing.T) {
	t.Log("TEST: Report passing all policy checks")

	verifier := NewPCRVerifier()

	// permissive policy
	verifier.AddPolicy(DefaultPolicy())

	report := &types.AttestationReport{}
	report.Header.Flags = types.FlagModuleSig // will not be checked since RequireModuleSig=false

	err := verifier.VerifyReport(report)
	if err != nil {
		t.Errorf("Report should pass default policy: %v", err)
	}

	t.Log("Report correctly passes permissive policy")
}

func TestLoadPolicy_FileNotFound(t *testing.T) {
	t.Log("TEST: Loading non-existent policy file")

	verifier := NewPCRVerifier()
	err := verifier.LoadPolicy("/nonexistent/path/policy.yaml")

	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	t.Logf("Non-existent file correctly rejected: %v", err)
}

func TestLoadPolicy_InvalidYAML(t *testing.T) {
	t.Log("TEST: Loading invalid YAML policy file")

	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "invalid.yaml")

	invalidContent := `
name: broken
pcrs:
  - this is not a map
  [invalid yaml
`
	if err := os.WriteFile(policyPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	verifier := NewPCRVerifier()
	err := verifier.LoadPolicy(policyPath)

	if err == nil {
		t.Error("Expected error for invalid YAML")
	}

	t.Logf("Invalid YAML correctly rejected: %v", err)
}

func TestExamplePolicy(t *testing.T) {
	t.Log("TEST: ExamplePolicy() provides valid template")

	policy := ExamplePolicy()

	if policy.Name == "" {
		t.Error("Example policy should have a name")
	}

	if len(policy.PCRs) == 0 {
		t.Error("Example policy should demonstrate PCR entries")
	}

	// should have PCR 0 and 7 as examples
	if _, ok := policy.PCRs[0]; !ok {
		t.Error("Example policy should include PCR 0")
	}
	if _, ok := policy.PCRs[7]; !ok {
		t.Error("Example policy should include PCR 7")
	}

	t.Log("ExamplePolicy provides valid template structure")
}
