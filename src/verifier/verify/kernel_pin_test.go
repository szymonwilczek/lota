// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package verify

import (
	"strings"
	"testing"
)

// An all-zero kernel hash is what a host reports when nothing measured a kernel
// into the register the agent read -- a GRUB host has nothing in PCR 11,
// and every one of them reports the same thirty-two zero bytes.
// Pinning that value looks like a kernel allow-list and admits every such
// machine running any kernel, so the policy has to be refused.
func TestAddPolicy_RefusesAnAllZeroKernelPin(t *testing.T) {
	v := NewPCRVerifier()

	err := v.AddPolicy(&PCRPolicy{
		Name:    "zero-kernel-pin",
		Profile: ProfileEnterprise,
		KernelHashes: []string{
			strings.Repeat("0", 64),
		},
		AgentHashes: []string{strings.Repeat("ab", 32)},
	})
	if err == nil {
		t.Fatal("a policy pinning an all-zero kernel hash was accepted")
	}
	if !strings.Contains(err.Error(), "kernel") {
		t.Errorf("the refusal does not name the kernel pin: %v", err)
	}
}

// The guard is about a value that pins nothing, not about kernel pinning:
// a real digest still loads, alongside a zero one being refused.
func TestAddPolicy_AcceptsARealKernelPin(t *testing.T) {
	v := NewPCRVerifier()

	if err := v.AddPolicy(&PCRPolicy{
		Name:         "real-kernel-pin",
		Profile:      ProfileEnterprise,
		KernelHashes: []string{strings.Repeat("3c", 32)},
		AgentHashes:  []string{strings.Repeat("ab", 32)},
	}); err != nil {
		t.Fatalf("a policy pinning a real kernel hash was refused: %v", err)
	}
}
