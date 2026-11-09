// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - PCR baseline verification module

package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/szymonwilczek/lota/verifier/types"
)

// PCRPolicy is a verification policy, read from YAML.
type PCRPolicy struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	// Tenant binds the policy to clients whose AIK certificate carries
	// this tenant; empty binds none.
	Tenant string `yaml:"tenant"`

	// Profile is ProfileEnterprise or ProfileConsumer; empty reads as
	// ProfileEnterprise.
	Profile string `yaml:"profile"`

	// PCRs maps a PCR index to its expected hex digest.
	PCRs map[int]string `yaml:"pcrs"`

	KernelHashes []string `yaml:"kernel_hashes"`
	AgentHashes  []string `yaml:"agent_hashes"`

	RequireIOMMU         bool `yaml:"require_iommu"`
	RequireEnforce       bool `yaml:"require_enforce"`
	RequireModuleSig     bool `yaml:"require_module_sig"`
	RequireSecureBoot    bool `yaml:"require_secureboot"`
	RequireLockdown      bool `yaml:"require_lockdown"`
	RequireIMAAppraisal  bool `yaml:"require_ima_appraisal"`
	RequireCmdlinePolicy bool `yaml:"require_cmdline_policy"`

	// CmdlineDeny extends builtinCmdlineDeny, in its rule forms.
	CmdlineDeny []string `yaml:"cmdline_deny"`
}

// EffectiveCmdlineDeny returns builtinCmdlineDeny followed by CmdlineDeny.
func (p *PCRPolicy) EffectiveCmdlineDeny() []string {
	out := make([]string, 0, len(builtinCmdlineDeny)+len(p.CmdlineDeny))
	out = append(out, builtinCmdlineDeny...)
	out = append(out, p.CmdlineDeny...)
	return out
}

// PCRVerifier holds the loaded policies and their tenant bindings.
type PCRVerifier struct {
	mu           sync.RWMutex
	policies     map[string]*PCRPolicy
	active       string
	tenantPolicy map[string]string // tenant -> policy name
	policyPubKey ed25519.PublicKey

	allowPermissivePolicy bool
	allowUnpinnedAgent    bool
}

// NewPCRVerifier returns a verifier with no policy.
func NewPCRVerifier() *PCRVerifier {
	return &PCRVerifier{
		policies:              make(map[string]*PCRPolicy),
		tenantPolicy:          make(map[string]string),
		allowPermissivePolicy: false,
		allowUnpinnedAgent:    false,
	}
}

// SetAllowPermissivePolicy makes LoadPolicy accept a policy for which
// IsMeasurementEmptyPolicy holds.
func (v *PCRVerifier) SetAllowPermissivePolicy(allow bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.allowPermissivePolicy = allow
}

// SetAllowUnpinnedAgent makes LoadPolicy accept a policy for which
// RequiresAgentHashPin holds.
func (v *PCRVerifier) SetAllowUnpinnedAgent(allow bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.allowUnpinnedAgent = allow
}

// RequiresAgentHashPin reports whether a policy requires Secure Boot and
// pins neither a PCR nor an agent hash. The first agent hash a client
// reports is then pinned unchecked, so LoadPolicy refuses such a policy
// unless SetAllowUnpinnedAgent allows it.
func RequiresAgentHashPin(policy *PCRPolicy) bool {
	if policy == nil {
		return false
	}
	return policy.RequireSecureBoot &&
		len(policy.PCRs) == 0 &&
		len(policy.AgentHashes) == 0
}

// SetPolicyPublicKey makes LoadPolicy require a valid signature at
// path + ".sig"; nil drops the requirement.
func (v *PCRVerifier) SetPolicyPublicKey(pubKey ed25519.PublicKey) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.policyPubKey = pubKey
}

// ValidatePolicy returns a warning for each check the policy leaves open.
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
		policy.RequireLockdown || policy.RequireCmdlinePolicy ||
		policy.RequireIMAAppraisal
	if !hasAnyRequirement && len(policy.PCRs) == 0 {
		warnings = append(warnings, fmt.Sprintf(
			"policy '%s': no security requirements enabled -> effectively permissive",
			policy.Name))
	}

	return warnings
}

// IsMeasurementEmptyPolicy reports whether a policy pins no PCR, kernel hash
// or agent hash. A nil policy is empty.
func IsMeasurementEmptyPolicy(policy *PCRPolicy) bool {
	if policy == nil {
		return true
	}
	return len(policy.PCRs) == 0 && len(policy.KernelHashes) == 0 && len(policy.AgentHashes) == 0
}

func isAllZeroHex(hexDigest string) bool {
	if hexDigest == "" {
		return false
	}
	for i := 0; i < len(hexDigest); i++ {
		if hexDigest[i] != '0' {
			return false
		}
	}
	return true
}

func validateKernelPins(policy *PCRPolicy) error {
	if policy == nil {
		return nil
	}
	for _, allowed := range policy.KernelHashes {
		if isAllZeroHex(strings.TrimSpace(allowed)) {
			return fmt.Errorf("refusing to load policy '%s': kernel_hashes pins an all-zero kernel hash, which every host with no kernel measurement reports -- the list would admit any kernel on any such machine. Pin the digest the device actually reports, or drop kernel_hashes and rely on the PCR pins", policy.Name)
		}
	}
	return nil
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

// LoadPolicy reads a YAML policy file and registers it.
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
	if err := validatePolicyDocument(&policy); err != nil {
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

	return v.registerPolicy(&policy)
}

// AddPolicy registers a policy without the signature, IsMeasurementEmptyPolicy
// and RequiresAgentHashPin checks of LoadPolicy.
func (v *PCRVerifier) AddPolicy(policy *PCRPolicy) error {
	return v.registerPolicy(policy)
}

func validatePolicyDocument(policy *PCRPolicy) error {
	if err := validatePolicyPCRIndices(policy); err != nil {
		return err
	}
	if err := validateProfile(policy); err != nil {
		return err
	}
	return validateKernelPins(policy)
}

// registerPolicy stores a policy under its name; the first one stored becomes
// active. A tenant binds to at most one policy.
func (v *PCRVerifier) registerPolicy(policy *PCRPolicy) error {
	if err := validatePolicyDocument(policy); err != nil {
		return err
	}
	if policy.Tenant != "" && !ValidTenantName(policy.Tenant) {
		return fmt.Errorf("policy '%s' declares an invalid tenant %q", policy.Name, policy.Tenant)
	}

	for _, w := range ValidatePolicy(policy) {
		slog.Warn(w)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if policy.Tenant != "" {
		if bound, ok := v.tenantPolicy[policy.Tenant]; ok && bound != policy.Name {
			return fmt.Errorf("tenant %q is already bound to policy '%s'", policy.Tenant, bound)
		}
	}

	if old, ok := v.policies[policy.Name]; ok && old.Tenant != "" && old.Tenant != policy.Tenant {
		delete(v.tenantPolicy, old.Tenant)
	}

	v.policies[policy.Name] = policy
	if policy.Tenant != "" {
		v.tenantPolicy[policy.Tenant] = policy.Name
	}

	if v.active == "" {
		v.active = policy.Name
	}

	return nil
}

// VerifyReportForTenant checks a report against the policy bound to the
// tenant, or the active policy when the tenant has none.
func (v *PCRVerifier) VerifyReportForTenant(report *types.AttestationReport, tenant string, facts *BootFacts) error {
	policy, exists := v.policyForTenant(tenant)
	if !exists {
		return errors.New("no active policy configured")
	}

	return v.verifyAgainstPolicy(report, policy, facts)
}

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

// PolicyNameForTenant returns the name of the policy the tenant verifies
// against.
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

// PolicyDeclaresBootPCRsForTenant reports whether the tenant's policy pins
// PCR 0, 1 and 7.
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

// PolicyRequiresSecureBootForTenant reports whether the tenant's policy sets
// RequireSecureBoot.
func (v *PCRVerifier) PolicyRequiresSecureBootForTenant(tenant string) bool {
	policy, ok := v.policyForTenant(tenant)
	return ok && policy != nil && policy.RequireSecureBoot
}

// PolicyRequiresCmdlineForTenant reports whether the tenant's policy sets
// RequireCmdlinePolicy.
func (v *PCRVerifier) PolicyRequiresCmdlineForTenant(tenant string) bool {
	policy, ok := v.policyForTenant(tenant)
	return ok && policy != nil && policy.RequireCmdlinePolicy
}

// Fleet profiles; ProfileConsumer enables self-service re-anchor.
const (
	ProfileEnterprise = "enterprise"
	ProfileConsumer   = "consumer"
)

func validateProfile(policy *PCRPolicy) error {
	switch policy.Profile {
	case "", ProfileEnterprise, ProfileConsumer:
		return nil
	default:
		return fmt.Errorf("policy %q: unknown profile %q (want %q or %q)",
			policy.Name, policy.Profile, ProfileEnterprise, ProfileConsumer)
	}
}

// PolicyEnablesSelfServiceReanchorForTenant reports whether the tenant's
// policy has ProfileConsumer.
func (v *PCRVerifier) PolicyEnablesSelfServiceReanchorForTenant(tenant string) bool {
	policy, ok := v.policyForTenant(tenant)
	return ok && policy != nil && policy.Profile == ProfileConsumer
}

// agentHashAllowed reports whether allowedHashes lists the reported hash in
// lower-case hex.
func agentHashAllowed(reported [types.HashSize]byte, allowedHashes []string) bool {
	return slices.Contains(allowedHashes, hex.EncodeToString(reported[:]))
}

// kernelPinValue returns the quote-bound kernel image digest kernel_hashes is
// compared with, or why there is none. The reported register is a whole-boot
// aggregate, which no image digest pin matches.
func kernelPinValue(facts *BootFacts) ([types.HashSize]byte, error) {
	var out [types.HashSize]byte

	if facts == nil || !facts.KernelImage.Found {
		return out, errors.New(
			"kernel_hashes is pinned and this host's event log records no kernel image, " +
				"so the pin cannot be evaluated: attest with PCR 9 in the quote from a host " +
				"whose bootloader measures the kernel, or drop kernel_hashes and pin PCR 7")
	}
	if !facts.KernelImageTrusted {
		return out, errors.New(
			"kernel_hashes is pinned and this host's kernel image is not quote-bound " +
				"(PCR 9 outside the quote, or the event log does not replay to it), " +
				"so the pin cannot be evaluated: include PCR 9 in the quote, " +
				"or drop kernel_hashes and pin PCR 7")
	}

	copy(out[:], facts.KernelImage.Digest)
	return out, nil
}

// policyError pairs a verifyAgainstPolicy refusal with its verdict.
type policyError struct {
	verdict uint32
	err     error
}

func (e *policyError) Error() string { return e.err.Error() }

func (e *policyError) Unwrap() error { return e.err }

func refuse(verdict uint32, err error) error {
	return &policyError{verdict: verdict, err: err}
}

// policyVerdict returns the verdict refuse attached to err, or VerifyPCRFail.
func policyVerdict(err error) uint32 {
	var pe *policyError

	if errors.As(err, &pe) {
		return pe.verdict
	}
	return types.VerifyPCRFail
}

func (v *PCRVerifier) verifyAgainstPolicy(report *types.AttestationReport, policy *PCRPolicy, facts *BootFacts) error {
	// name every mismatch, in the same order on every round
	var stale []string
	for _, pcrIdx := range slices.Sorted(maps.Keys(policy.PCRs)) {
		expectedHex := policy.PCRs[pcrIdx]

		if pcrIdx < 0 || pcrIdx >= types.PCRCount {
			return fmt.Errorf("invalid PCR index in policy '%s': %d", policy.Name, pcrIdx)
		}

		if report.TPM.PCRMask&(1<<uint(pcrIdx)) == 0 {
			return fmt.Errorf("PCR %d not included in quote", pcrIdx)
		}

		expected, err := hex.DecodeString(expectedHex)
		if err != nil {
			return fmt.Errorf("invalid expected hash for PCR %d: %w", pcrIdx, err)
		}

		actual := report.TPM.PCRValues[pcrIdx][:]
		if !bytes.Equal(actual, expected) {
			stale = append(stale, fmt.Sprintf("PCR %d mismatch: got %s, expected %s",
				pcrIdx, hex.EncodeToString(actual), expectedHex))
		}
	}
	if len(stale) > 0 {
		return errors.New(strings.Join(stale, "; "))
	}

	if len(policy.KernelHashes) > 0 {
		pinned, err := kernelPinValue(facts)
		if err != nil {
			return refuse(types.VerifyKernelImageRequired, err)
		}
		kernelHashHex := hex.EncodeToString(pinned[:])
		found := false
		for _, allowed := range policy.KernelHashes {
			if kernelHashHex == allowed {
				found = true
				break
			}
		}
		if !found {
			return refuse(types.VerifyKernelImageRequired,
				fmt.Errorf("kernel hash not in allowed list: %s", kernelHashHex))
		}
	}

	if len(policy.AgentHashes) > 0 {
		if !agentHashAllowed(report.System.AgentHash, policy.AgentHashes) {
			return refuse(types.VerifyIntegrityMismatch,
				fmt.Errorf("agent hash not in allowed list: %s",
					hex.EncodeToString(report.System.AgentHash[:])))
		}
	}

	if policy.RequireIOMMU {
		if report.System.IOMMU.Flags&0x04 == 0 {
			return refuse(types.VerifyIOMMUFail,
				errors.New("IOMMU DMA remapping not enabled"))
		}
	}

	if policy.RequireEnforce {
		if report.Header.Flags&types.FlagEnforce == 0 {
			return refuse(types.VerifyEnforceRequired,
				errors.New("LSM enforce mode not active"))
		}
	}

	if policy.RequireModuleSig {
		if report.Header.Flags&types.FlagModuleSig == 0 {
			return refuse(types.VerifyModuleSigRequired,
				errors.New("kernel module signature enforcement not enabled"))
		}
	}

	// FlagSecureBoot is agent-reported; the event log is quote-bound
	if policy.RequireSecureBoot {
		if facts == nil || !facts.SecureBootTrusted {
			return refuse(types.VerifySecureBootRequired,
				errors.New("Secure Boot state not authenticated by event log"))
		}
		if !facts.SecureBoot.Found {
			return refuse(types.VerifySecureBootRequired,
				errors.New("event log carries no SecureBoot measurement"))
		}
		if !facts.SecureBoot.Enabled {
			return refuse(types.VerifySecureBootRequired,
				errors.New("Secure Boot disabled per firmware measurement"))
		}
	}

	if policy.RequireCmdlinePolicy {
		if err := verifyCmdlinePolicy(policy, facts); err != nil {
			return refuse(types.VerifyCmdlineRequired, err)
		}
	}

	if policy.RequireLockdown {
		if report.Header.Flags&types.FlagLockdown == 0 {
			return refuse(types.VerifyLockdownRequired,
				errors.New("kernel lockdown not active"))
		}
	}

	if policy.RequireIMAAppraisal {
		if report.Header.Flags&types.FlagIMAAppraisal == 0 {
			return refuse(types.VerifyIMAAppraisalRequired,
				errors.New("exec appraisal not established "+
					"on this host (KERNEL_APPRAISAL "+
					"clear: ima_appraise= not enforce, "+
					"no appraise rule on BPRM_CHECK or "+
					"without func=, or the policy "+
					"unread)"))
		}
	}

	return nil
}

// GetActivePolicy returns the name of the active policy.
func (v *PCRVerifier) GetActivePolicy() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.active
}

// GetActivePolicyConfig returns the active policy, which the caller must not
// modify.
func (v *PCRVerifier) GetActivePolicyConfig() (*PCRPolicy, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	policy, ok := v.policies[v.active]
	return policy, ok
}

// ListPolicies returns the names of the loaded policies.
func (v *PCRVerifier) ListPolicies() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	names := make([]string, 0, len(v.policies))
	for name := range v.policies {
		names = append(names, name)
	}
	return names
}

// TenantBindings reports which policy each tenant is verified against.
// A tenant absent from the map falls back to the active policy.
func (v *PCRVerifier) TenantBindings() map[string]string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	bindings := make(map[string]string, len(v.tenantPolicy))
	for tenant, name := range v.tenantPolicy {
		bindings[tenant] = name
	}
	return bindings
}

// DefaultPolicy returns a built-in policy that pins no measurement.
func DefaultPolicy() *PCRPolicy {
	return &PCRPolicy{
		Name:        "default",
		Description: "Built-in baseline policy - enforces security requirements without specific PCR values",

		PCRs:                map[int]string{},
		KernelHashes:        []string{},
		AgentHashes:         []string{},
		RequireIOMMU:        true,
		RequireEnforce:      true,
		RequireModuleSig:    true,
		RequireSecureBoot:   false,
		RequireLockdown:     false,
		RequireIMAAppraisal: false,
	}
}

// GetRequiredMask returns the mask of the PCRs the policy pins, PCR 0, 1, 7
// and 14 for the baselines, PCR 9 for the kernel image digest, and PCR 8
// when RequireCmdlinePolicy is set.
func (p *PCRPolicy) GetRequiredMask() uint32 {
	mask := uint32(0)

	for pcrIdx := range p.PCRs {
		if pcrIdx >= 0 && pcrIdx < types.PCRCount {
			mask |= (1 << uint(pcrIdx))
		}
	}

	mask |= (1 << 14) | (1 << 0) | (1 << 1) | (1 << 7)

	if p.RequireCmdlinePolicy {
		mask |= 1 << 8
	}

	mask |= 1 << 9

	return mask
}

// GetChallengePolicyMask returns the union of the required masks of the
// active policy, or DefaultPolicy without one, and every tenant-bound policy.
// The challenge is issued before the client's tenant is known.
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
