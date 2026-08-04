// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - PCR baseline verification module
//
// Verifies that PCR values match expected "golden" measurements.
// This is the core of attestation - proving system is in known-good state.

package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/szymonwilczek/lota/verifier/types"
)

// defines expected PCR values for verification
type PCRPolicy struct {
	// human-readable policy name
	Name string `yaml:"name"`

	// explains what this policy represents
	Description string `yaml:"description"`

	// binds this policy to one tenant:
	// clients whose AIK certificate carries this tenant verify against it
	// instead of the active policy.
	// Empty means no binding.
	// Binding travels inside the policy file, so signed policy authenticates its own scope.
	Tenant string `yaml:"tenant"`

	// maps PCR index to expected hash value (hex-encoded)
	// IMPORTANT: only PCRs listed here are checked; others are ignored
	PCRs map[int]string `yaml:"pcrs"`

	// lists allowed kernel image hashes
	KernelHashes []string `yaml:"kernel_hashes"`

	// lists allowed LOTA agent hashes
	AgentHashes []string `yaml:"agent_hashes"`

	// if true, fails verification if IOMMU not enabled
	RequireIOMMU bool `yaml:"require_iommu"`

	// if true, fails if LSM not in enforce mode
	RequireEnforce bool `yaml:"require_enforce"`

	// if true, fails if kernel module signature enforcement disabled
	RequireModuleSig bool `yaml:"require_module_sig"`

	// if true, fails if Secure Boot not enabled
	RequireSecureBoot bool `yaml:"require_secureboot"`

	// if true, fails if kernel lockdown not enabled
	RequireLockdown bool `yaml:"require_lockdown"`

	// if true, fails when the event-log-measured kernel command line
	// carries a denylisted parameter (builtin denylist + cmdline_deny).
	// GRUB-only in v1: hosts with no PCR 8 cmdline measurement and a
	// zero quoted PCR 8 skip the check (systemd-boot/UKI measure the
	// cmdline into PCR 12 instead)
	RequireCmdlinePolicy bool `yaml:"require_cmdline_policy"`

	// operator extensions to the builtin cmdline parameter denylist;
	// entry forms: "param" (bare or any value), "param=" (any value),
	// "param=value" (exact pair)
	CmdlineDeny []string `yaml:"cmdline_deny"`
}

// returns the effective cmdline denylist: builtin rules plus operator
// extensions from the policy file
func (p *PCRPolicy) EffectiveCmdlineDeny() []string {
	out := make([]string, 0, len(builtinCmdlineDeny)+len(p.CmdlineDeny))
	out = append(out, builtinCmdlineDeny...)
	out = append(out, p.CmdlineDeny...)
	return out
}

// manages PCR policies and verification
type PCRVerifier struct {
	mu           sync.RWMutex
	policies     map[string]*PCRPolicy
	active       string            // name of active policy
	tenantPolicy map[string]string // tenant -> bound policy name
	policyPubKey ed25519.PublicKey // if set, policy files require valid Ed25519 signature

	// if false, LoadPolicy rejects policies that define no measurement allowlists
	// (no PCR values and no kernel/agent hash allowlists)
	allowPermissivePolicy bool

	// if false, LoadPolicy rejects a diverse-fleet policy (require_secureboot
	// with no raw PCR pins) that does not pin agent_hashes.
	// See RequiresAgentHashPin.
	allowUnpinnedAgent bool
}

// creates a new PCR verifier
func NewPCRVerifier() *PCRVerifier {
	return &PCRVerifier{
		policies:              make(map[string]*PCRPolicy),
		tenantPolicy:          make(map[string]string),
		allowPermissivePolicy: false,
		allowUnpinnedAgent:    false,
	}
}

// controls whether LoadPolicy accepts measurement-empty policies
// This is intentionally false by default to avoid silent misconfiguration.
func (v *PCRVerifier) SetAllowPermissivePolicy(allow bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.allowPermissivePolicy = allow
}

// controls whether LoadPolicy accepts a diverse-fleet policy with no pinned
// agent_hashes.
// Intentionally false by default:
// on the diverse-fleet path (require_secureboot, no raw PCR pins) the per-device
// PCR 0/1/7 and the agent self-hash both go through TOFU, so without a pinned
// agent_hash a modified, non-enforcing agent would pin its own hash on first use
// and then attest "OK" while doing no enforcement.
//
// kernel_hashes do not count -- they are advisory and self-reported.
// agent_hash allowlist is the only cryptographic gate on which agent binary ran.
func (v *PCRVerifier) SetAllowUnpinnedAgent(allow bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.allowUnpinnedAgent = allow
}

// RequiresAgentHashPin reports whether a policy is a diverse-fleet policy
// (require_secureboot with no raw PCR pins) that fails to pin agent_hashes.
// Such a policy leaves the agent self-hash on TOFU, which a modified agent
// can exploit, so LoadPolicy refuses it unless the operator opts out.
func RequiresAgentHashPin(policy *PCRPolicy) bool {
	if policy == nil {
		return false
	}
	return policy.RequireSecureBoot &&
		len(policy.PCRs) == 0 &&
		len(policy.AgentHashes) == 0
}

// sets the Ed25519 public key used to verify policy file signatures
// when set, LoadPolicy rejects any policy without a valid detached .sig file
// pass nil to disable signature verification
func (v *PCRVerifier) SetPolicyPublicKey(pubKey ed25519.PublicKey) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.policyPubKey = pubKey
}

// checks policy for common misconfigurations and logs warnings
// returns list of warnings found (empty if policy is well-configured)
func ValidatePolicy(policy *PCRPolicy) []string {
	var warnings []string

	if len(policy.PCRs) == 0 {
		warnings = append(warnings, fmt.Sprintf(
			"policy '%s': no PCR values defined -> any PCR set will pass",
			policy.Name))
	}

	if len(policy.KernelHashes) == 0 && len(policy.AgentHashes) == 0 {
		warnings = append(warnings, fmt.Sprintf(
			"policy '%s': no kernel/agent hash allowlists -> any binary accepted",
			policy.Name))
	}

	hasAnyRequirement := policy.RequireIOMMU || policy.RequireEnforce ||
		policy.RequireModuleSig || policy.RequireSecureBoot ||
		policy.RequireLockdown || policy.RequireCmdlinePolicy
	if !hasAnyRequirement && len(policy.PCRs) == 0 {
		warnings = append(warnings, fmt.Sprintf(
			"policy '%s': no security requirements enabled -> effectively permissive",
			policy.Name))
	}

	return warnings
}

// returns true if the policy does not define any measurement allowlists:
// neither explicit PCR values nor kernel/agent hash allowlists.
//
// NOTE: This is intentionally different from ValidatePolicy() definition of
// "effectively permissive".
func IsMeasurementEmptyPolicy(policy *PCRPolicy) bool {
	if policy == nil {
		return true
	}
	return len(policy.PCRs) == 0 && len(policy.KernelHashes) == 0 && len(policy.AgentHashes) == 0
}

func validatePolicyPCRIndices(policy *PCRPolicy) error {
	if policy == nil {
		return errors.New("nil policy")
	}
	for pcrIdx := range policy.PCRs {
		if pcrIdx < 0 || pcrIdx >= types.PCRCount {
			return fmt.Errorf("invalid PCR index in policy '%s': %d (valid range: 0..%d)",
				policy.Name, pcrIdx, types.PCRCount-1)
		}
	}
	return nil
}

// loads a policy from YAML file
// if a policy public key has been set via SetPolicyPublicKey,
// the file must have a valid detached Ed25519 signature at path+".sig"!
func (v *PCRVerifier) LoadPolicy(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	v.mu.RLock()
	pubKey := v.policyPubKey
	v.mu.RUnlock()

	if pubKey != nil {
		if err := VerifyPolicyFile(path, pubKey); err != nil {
			return fmt.Errorf("policy signature verification failed: %w", err)
		}
	}

	var policy PCRPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("failed to parse policy: %w", err)
	}
	if err := validatePolicyPCRIndices(&policy); err != nil {
		return err
	}

	v.mu.RLock()
	allowPermissive := v.allowPermissivePolicy
	allowUnpinnedAgent := v.allowUnpinnedAgent
	v.mu.RUnlock()
	if IsMeasurementEmptyPolicy(&policy) && !allowPermissive {
		return fmt.Errorf("refusing to load measurement-empty PCR policy '%s' (no pcrs and no kernel_hashes/agent_hashes)", policy.Name)
	}
	if RequiresAgentHashPin(&policy) && !allowUnpinnedAgent {
		return fmt.Errorf("refusing to load diverse-fleet policy '%s' (require_secureboot, no raw PCR pins) with empty agent_hashes: the agent self-hash would be TOFU and a modified non-enforcing agent could pin its own hash. Pin the official agent hash in agent_hashes (from the signed release), or pass --allow-unpinned-agent to accept the risk", policy.Name)
	}

	for _, w := range ValidatePolicy(&policy) {
		slog.Warn(w)
	}

	return v.registerPolicy(&policy)
}

// adds a policy programmatically
func (v *PCRVerifier) AddPolicy(policy *PCRPolicy) error {
	if err := validatePolicyPCRIndices(policy); err != nil {
		return err
	}
	for _, w := range ValidatePolicy(policy) {
		slog.Warn(w)
	}

	return v.registerPolicy(policy)
}

// registerPolicy stores validated policy and maintains the tenant binding index.
// Tenant binds to at most one policy.
// Re-registering the same policy name refreshes its binding.
func (v *PCRVerifier) registerPolicy(policy *PCRPolicy) error {
	if policy.Tenant != "" && !ValidTenantName(policy.Tenant) {
		return fmt.Errorf("policy '%s' declares an invalid tenant %q", policy.Name, policy.Tenant)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if policy.Tenant != "" {
		if bound, ok := v.tenantPolicy[policy.Tenant]; ok && bound != policy.Name {
			return fmt.Errorf("tenant %q is already bound to policy '%s'", policy.Tenant, bound)
		}
	}

	// drop stale binding when policy is re-registered under
	// new or removed tenant
	if old, ok := v.policies[policy.Name]; ok && old.Tenant != "" && old.Tenant != policy.Tenant {
		delete(v.tenantPolicy, old.Tenant)
	}

	v.policies[policy.Name] = policy
	if policy.Tenant != "" {
		v.tenantPolicy[policy.Tenant] = policy.Name
	}

	// set as active if first policy
	if v.active == "" {
		v.active = policy.Name
	}

	return nil
}

// sets which policy to use for verification
func (v *PCRVerifier) SetActivePolicy(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if _, exists := v.policies[name]; !exists {
		return fmt.Errorf("policy not found: %s", name)
	}

	v.active = name
	return nil
}

// checks report against active policy without event-log boot facts;
// policies that gate on Secure Boot or the cmdline fail closed here
func (v *PCRVerifier) VerifyReport(report *types.AttestationReport) error {
	return v.VerifyReportWithFacts(report, nil)
}

// checks report against active policy using the quote-authenticated
// boot facts extracted from the event log
func (v *PCRVerifier) VerifyReportWithFacts(report *types.AttestationReport, facts *BootFacts) error {
	return v.VerifyReportForTenant(report, "", facts)
}

// checks report against the policy bound to the client's tenant,
// falling back to the active policy when the tenant has no binding
func (v *PCRVerifier) VerifyReportForTenant(report *types.AttestationReport, tenant string, facts *BootFacts) error {
	policy, exists := v.policyForTenant(tenant)
	if !exists {
		return errors.New("no active policy configured")
	}

	return v.verifyAgainstPolicy(report, policy, facts)
}

// policyForTenant resolves the policy a tenant verifies against:
// its bound policy when one is registered, the active policy otherwise
func (v *PCRVerifier) policyForTenant(tenant string) (*PCRPolicy, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if tenant != "" {
		if name, ok := v.tenantPolicy[tenant]; ok {
			if policy, ok := v.policies[name]; ok {
				return policy, true
			}
		}
	}
	policy, ok := v.policies[v.active]
	return policy, ok
}

// PolicyNameForTenant reports which policy tenant verifies against (for logging).
// Falls back to the active policy name
func (v *PCRVerifier) PolicyNameForTenant(tenant string) string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if tenant != "" {
		if name, ok := v.tenantPolicy[tenant]; ok {
			return name
		}
	}
	return v.active
}

// tenant-aware counterpart of ActivePolicyDeclaresBootPCRs
func (v *PCRVerifier) PolicyDeclaresBootPCRsForTenant(tenant string) bool {
	policy, ok := v.policyForTenant(tenant)
	if !ok || policy == nil {
		return false
	}
	if _, ok := policy.PCRs[0]; !ok {
		return false
	}
	if _, ok := policy.PCRs[1]; !ok {
		return false
	}
	if _, ok := policy.PCRs[7]; !ok {
		return false
	}
	return true
}

// tenant-aware counterpart of ActivePolicyRequiresSecureBoot
func (v *PCRVerifier) PolicyRequiresSecureBootForTenant(tenant string) bool {
	policy, ok := v.policyForTenant(tenant)
	return ok && policy != nil && policy.RequireSecureBoot
}

// tenant-aware counterpart of ActivePolicyRequiresCmdline
func (v *PCRVerifier) PolicyRequiresCmdlineForTenant(tenant string) bool {
	policy, ok := v.policyForTenant(tenant)
	return ok && policy != nil && policy.RequireCmdlinePolicy
}

// agentHashAllowed reports whether the reported agent hash is one the active
// policy lists, ie build the publisher has blessed.
// It is named predicate rather than inline loop because more than one gate has
// to ask the same question, and two independent comparisons of one list are two
// places for it to be read differently.
//
// The comparison is over lower-case hex, which is what the agent reports
// and what a policy file carries; upper-case entry does not match and is policy
// authoring error rather than hash to accept leniently.
func agentHashAllowed(reported [types.HashSize]byte, allowedHashes []string) bool {
	return slices.Contains(allowedHashes, hex.EncodeToString(reported[:]))
}

func (v *PCRVerifier) verifyAgainstPolicy(report *types.AttestationReport, policy *PCRPolicy, facts *BootFacts) error {
	// check pcr values
	for pcrIdx, expectedHex := range policy.PCRs {
		if pcrIdx < 0 || pcrIdx >= types.PCRCount {
			return fmt.Errorf("invalid PCR index in policy '%s': %d", policy.Name, pcrIdx)
		}

		// check if this pcr was included in quote
		if report.TPM.PCRMask&(1<<uint(pcrIdx)) == 0 {
			return fmt.Errorf("PCR %d not included in quote", pcrIdx)
		}

		expected, err := hex.DecodeString(expectedHex)
		if err != nil {
			return fmt.Errorf("invalid expected hash for PCR %d: %w", pcrIdx, err)
		}

		actual := report.TPM.PCRValues[pcrIdx][:]
		if !bytes.Equal(actual, expected) {
			return fmt.Errorf("PCR %d mismatch: got %s, expected %s",
				pcrIdx, hex.EncodeToString(actual), expectedHex)
		}
	}

	// check kernel hash
	if len(policy.KernelHashes) > 0 {
		kernelHashHex := hex.EncodeToString(report.System.KernelHash[:])
		found := false
		for _, allowed := range policy.KernelHashes {
			if kernelHashHex == allowed {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("kernel hash not in allowed list: %s", kernelHashHex)
		}
	}

	// verify agent binary hash if policy specifies allowed hashes
	if len(policy.AgentHashes) > 0 {
		if !agentHashAllowed(report.System.AgentHash, policy.AgentHashes) {
			return fmt.Errorf("agent hash not in allowed list: %s",
				hex.EncodeToString(report.System.AgentHash[:]))
		}
	}

	// check iommu requirement
	if policy.RequireIOMMU {
		if report.System.IOMMU.Flags&0x04 == 0 {
			return errors.New("IOMMU DMA remapping not enabled")
		}
	}

	// check LSM enforce mode
	if policy.RequireEnforce {
		if report.Header.Flags&types.FlagEnforce == 0 {
			return errors.New("LSM enforce mode not active")
		}
	}

	// check module signing enforcement
	if policy.RequireModuleSig {
		if report.Header.Flags&types.FlagModuleSig == 0 {
			return errors.New("kernel module signature enforcement not enabled")
		}
	}

	// check secure boot from the firmware-measured event log value;
	// the agent-reported FlagSecureBoot is telemetry only (a
	// compromised kernel sets it freely)
	if policy.RequireSecureBoot {
		if facts == nil || !facts.SecureBootTrusted {
			return errors.New("Secure Boot state not authenticated by event log")
		}
		if !facts.SecureBoot.Found {
			return errors.New("event log carries no SecureBoot measurement")
		}
		if !facts.SecureBoot.Enabled {
			return errors.New("Secure Boot disabled per firmware measurement")
		}
	}

	// check the measured kernel cmdline against the parameter denylist
	if policy.RequireCmdlinePolicy {
		if err := verifyCmdlinePolicy(policy, facts); err != nil {
			return err
		}
	}

	// check kernel lockdown
	if policy.RequireLockdown {
		if report.Header.Flags&types.FlagLockdown == 0 {
			return errors.New("kernel lockdown not active")
		}
	}

	return nil
}

// returns the current active policy name
func (v *PCRVerifier) GetActivePolicy() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.active
}

// returns the currently active policy configuration
// returned pointer must be treated as read-only by callers
func (v *PCRVerifier) GetActivePolicyConfig() (*PCRPolicy, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	policy, ok := v.policies[v.active]
	return policy, ok
}

// ActivePolicyDeclaresBootPCRs reports whether the active policy pins
// expected hex values for PCR0, PCR1, and PCR7. A policy that pins
// all three authenticates the firmware/Secure Boot baseline through
// the signed-policy channel, so first-use of the per-client boot
// baseline is no longer a pure TOFU decision. Used by the
// enrollment gate in Verify().
func (v *PCRVerifier) ActivePolicyDeclaresBootPCRs() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	policy, ok := v.policies[v.active]
	if !ok || policy == nil {
		return false
	}
	if _, ok := policy.PCRs[0]; !ok {
		return false
	}
	if _, ok := policy.PCRs[1]; !ok {
		return false
	}
	if _, ok := policy.PCRs[7]; !ok {
		return false
	}
	return true
}

// reports whether the active policy enforces event-log Secure Boot;
// drives the event-log-anchored TOFU branch of the boot enrollment
// gate in Verify()
func (v *PCRVerifier) ActivePolicyRequiresSecureBoot() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	policy, ok := v.policies[v.active]
	return ok && policy != nil && policy.RequireSecureBoot
}

// reports whether the active policy gates on the measured kernel
// cmdline; drives PCR 8 consistency enforcement in the event-log check
func (v *PCRVerifier) ActivePolicyRequiresCmdline() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	policy, ok := v.policies[v.active]
	return ok && policy != nil && policy.RequireCmdlinePolicy
}

// returns names of all loaded policies
func (v *PCRVerifier) ListPolicies() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	names := make([]string, 0, len(v.policies))
	for name := range v.policies {
		names = append(names, name)
	}
	return names
}

// creates the built-in permissive policy used only for explicit insecure fallback.
// IMPORTANT: this policy has no measurement allowlists and MUST NOT be used by default
// in production deployments. Provide a custom YAML policy with explicit PCR values
// and/or kernel/agent hash allowlists.
func DefaultPolicy() *PCRPolicy {
	return &PCRPolicy{
		Name:        "default",
		Description: "Built-in baseline policy - enforces security requirements without specific PCR values",
		// PCR values intentionally empty - use TOFU for PCR14!
		// Site-specific PCR0/PCR7 values should be defined in custom YAML policies
		PCRs:              map[int]string{},
		KernelHashes:      []string{}, // defined in site-specific policy
		AgentHashes:       []string{}, // defined in site-specific policy
		RequireIOMMU:      true,       // baseline: DMA remapping should be enabled
		RequireEnforce:    true,       // LSM must be in enforce mode
		RequireModuleSig:  true,       // baseline: module signature enforcement should be enabled
		RequireSecureBoot: false,      // optional hardware feature
		RequireLockdown:   false,      // optional kernel feature
	}
}

// creates a strict policy for high-security environments.
// Requires all available security features to be enabled.
func StrictPolicy() *PCRPolicy {
	return &PCRPolicy{
		Name:                 "strict",
		Description:          "High-security policy - requires all security features enabled",
		PCRs:                 map[int]string{}, // defined via TOFU or custom policy
		KernelHashes:         []string{},
		AgentHashes:          []string{},
		RequireIOMMU:         true,
		RequireEnforce:       true,
		RequireModuleSig:     true,
		RequireSecureBoot:    true,
		RequireLockdown:      true,
		RequireCmdlinePolicy: true,
	}
}

// calculates the PCR mask required by this policy
// always includes PCR 14 (LOTA self-measurement) as it is required for baseline verification
// and the firmware / SecureBoot PCRs (0, 1, 7) so the verifier can TOFU-pin them
func (p *PCRPolicy) GetRequiredMask() uint32 {
	mask := uint32(0)

	// PCRs defined in the policy
	for pcrIdx := range p.PCRs {
		if pcrIdx >= 0 && pcrIdx < types.PCRCount {
			mask |= (1 << uint(pcrIdx))
		}
	}

	// PCR 14: LOTA self-measurement; required for runtime baseline.
	// PCR 0:  SRTM / firmware code.
	// PCR 1:  host platform configuration (BIOS settings, boot order).
	// PCR 7:  Secure Boot policy + authority chain.
	mask |= (1 << 14) | (1 << 0) | (1 << 1) | (1 << 7)

	// PCR 8: GRUB kernel cmdline; the cmdline gate can only trust the
	// measured command line when the quote covers the PCR it extends
	if p.RequireCmdlinePolicy {
		mask |= 1 << 8
	}

	return mask
}

// returns the PCR mask required by the currently active policy
func (v *PCRVerifier) GetActivePolicyMask() uint32 {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if policy, exists := v.policies[v.active]; exists {
		return policy.GetRequiredMask()
	}

	// fallback if no active policy
	return DefaultPolicy().GetRequiredMask()
}

// GetChallengePolicyMask returns the union of the PCR masks of the active policy
// and every tenant-bound policy.
// Challenge is issued before the client authenticates its tenant, so it must
// request every PCR any selectable policy may check.
// Quoting a superset is harmless.
func (v *PCRVerifier) GetChallengePolicyMask() uint32 {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var mask uint32
	if policy, exists := v.policies[v.active]; exists {
		mask = policy.GetRequiredMask()
	} else {
		mask = DefaultPolicy().GetRequiredMask()
	}
	for _, name := range v.tenantPolicy {
		if policy, ok := v.policies[name]; ok {
			mask |= policy.GetRequiredMask()
		}
	}
	return mask
}
