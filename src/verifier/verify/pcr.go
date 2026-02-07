// SPDX-License-Identifier: MIT
// LOTA Verifier - PCR baseline verification module
//
// Verifies that PCR values match expected "golden" measurements.
// This is the core of attestation - proving system is in known-good state.

package verify

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/szymonwilczek/lota/verifier/types"
	"gopkg.in/yaml.v3"
)

// defines expected PCR values for verification
type PCRPolicy struct {
	// human-readable policy name
	Name string `yaml:"name"`

	// explains what this policy represents
	Description string `yaml:"description"`

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
}

// manages PCR policies and verification
type PCRVerifier struct {
	mu       sync.RWMutex
	policies map[string]*PCRPolicy
	active   string // name of active policy
}

// creates a new PCR verifier
func NewPCRVerifier() *PCRVerifier {
	return &PCRVerifier{
		policies: make(map[string]*PCRPolicy),
	}
}

// loads a policy from YAML file
func (v *PCRVerifier) LoadPolicy(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy PCRPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("failed to parse policy: %w", err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	v.policies[policy.Name] = &policy

	// set as active if first policy
	if v.active == "" {
		v.active = policy.Name
	}

	return nil
}

// adds a policy programmatically
func (v *PCRVerifier) AddPolicy(policy *PCRPolicy) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.policies[policy.Name] = policy

	if v.active == "" {
		v.active = policy.Name
	}
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

// checks report against active policy
func (v *PCRVerifier) VerifyReport(report *types.AttestationReport) error {
	v.mu.RLock()
	policy, exists := v.policies[v.active]
	v.mu.RUnlock()

	if !exists {
		return errors.New("no active policy configured")
	}

	return v.verifyAgainstPolicy(report, policy)
}

// checks report against specific policy
func (v *PCRVerifier) VerifyReportWithPolicy(report *types.AttestationReport, policyName string) error {
	v.mu.RLock()
	policy, exists := v.policies[policyName]
	v.mu.RUnlock()

	if !exists {
		return fmt.Errorf("policy not found: %s", policyName)
	}

	return v.verifyAgainstPolicy(report, policy)
}

func (v *PCRVerifier) verifyAgainstPolicy(report *types.AttestationReport, policy *PCRPolicy) error {
	// check pcr values
	for pcrIdx, expectedHex := range policy.PCRs {
		if pcrIdx < 0 || pcrIdx >= types.PCRCount {
			continue
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
		agentHashHex := hex.EncodeToString(report.System.AgentHash[:])
		found := false
		for _, allowed := range policy.AgentHashes {
			if agentHashHex == allowed {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("agent hash not in allowed list: %s", agentHashHex)
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

	// check secure boot
	if policy.RequireSecureBoot {
		if report.Header.Flags&types.FlagSecureBoot == 0 {
			return errors.New("Secure Boot not enabled")
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

// creates the built-in default policy with baseline security requirements.
// IMPORTANT NOTE: For production deployments, use a custom YAML policy with explicit PCR values.
// This policy enforces fundamental security requirements without PCR value checks,
// suitable for initial deployment before collecting site-specific baselines.
func DefaultPolicy() *PCRPolicy {
	return &PCRPolicy{
		Name:        "default",
		Description: "Built-in baseline policy - enforces security requirements without specific PCR values",
		// PCR values intentionally empty - use TOFU for PCR14!
		// Site-specific PCR0/PCR7 values should be defined in custom YAML policies
		PCRs:              map[int]string{},
		KernelHashes:      []string{}, // defined in site-specific policy
		AgentHashes:       []string{}, // defined in site-specific policy
		RequireIOMMU:      false,      // not all systems have IOMMU
		RequireEnforce:    true,       // LSM must be in enforce mode
		RequireModuleSig:  false,      // distribution-dependent
		RequireSecureBoot: false,      // optional hardware feature
		RequireLockdown:   false,      // optional kernel feature
	}
}

// creates a strict policy for high-security environments.
// Requires all available security features to be enabled.
func StrictPolicy() *PCRPolicy {
	return &PCRPolicy{
		Name:              "strict",
		Description:       "High-security policy - requires all security features enabled",
		PCRs:              map[int]string{}, // defined via TOFU or custom policy
		KernelHashes:      []string{},
		AgentHashes:       []string{},
		RequireIOMMU:      true,
		RequireEnforce:    true,
		RequireModuleSig:  true,
		RequireSecureBoot: true,
		RequireLockdown:   true,
	}
}

// creates an example policy demonstrating the structure.
// Use this as a template when creating site-specific policies.
//
// Typical PCR meanings (SHA-256):
//
//	PCR 0:  SRTM, BIOS/UEFI firmware measurement
//	PCR 1:  Host platform configuration
//	PCR 2:  UEFI driver code
//	PCR 3:  UEFI driver configuration
//	PCR 4:  Boot loader code (GRUB/systemd-boot)
//	PCR 5:  GPT partition table
//	PCR 7:  Secure Boot state (policies/certificates)
//	PCR 8:  Kernel command line (grub2-measured)
//	PCR 9:  Linux IMA measurements (if enabled)
//	PCR 14: LOTA agent self-measurement
func ExamplePolicy() *PCRPolicy {
	return &PCRPolicy{
		Name:        "example-production",
		Description: "Example production policy - customize PCR values for your environment",
		PCRs: map[int]string{
			// PCR 0: Firmware measurement - unique per hardware/firmware version
			// Collect with: tpm2_pcrread sha256:0 -o pcr0.bin && xxd -p pcr0.bin
			0: "<COLLECT_FROM_YOUR_SYSTEM>",
			// PCR 7: Secure Boot state - changes when certificates updated
			7: "<COLLECT_FROM_YOUR_SYSTEM>",
			// PCR 14: LOTA agent - self controlled entirely (TOFU handles this)
			// 14: handled by TOFU baseline store
		},
		KernelHashes: []string{
			// SHA-256 of /boot/vmlinuz-*
			// Collect with: sha256sum /boot/vmlinuz-$(uname -r)
			"<KERNEL_SHA256_HASH>",
		},
		AgentHashes: []string{
			// SHA-256 of lota-agent binary
			// Collect with: sha256sum /usr/sbin/lota-agent
			"<AGENT_SHA256_HASH>",
		},
		RequireIOMMU:      true, // DMA protection required
		RequireEnforce:    true, // LSM enforce mode required
		RequireModuleSig:  true, // signed kernel modules only
		RequireSecureBoot: true, // UEFI Secure Boot required
		RequireLockdown:   true, // kernel lockdown mode required
	}
}
