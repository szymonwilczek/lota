// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package verify

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
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

// The gate compares one value from one producer: the bootloader's measurement
// of the kernel image, which is what --export-policy writes into kernel_hashes.
// A host that establishes it is judged against the pin.
func TestKernelPin_ComparesTheMeasuredImage(t *testing.T) {
	digest := bytes.Repeat([]byte{0x5b}, types.HashSize)
	facts := &BootFacts{
		KernelImage: KernelImage{
			Found:  true,
			Path:   "(hd0,gpt4)/vmlinuz-7.1.8-200.fc44.x86_64",
			Digest: digest,
		},
		KernelImageTrusted: true,
	}

	got, err := kernelPinValue(facts)
	if err != nil {
		t.Fatalf("a quote-bound kernel image was refused: %v", err)
	}
	if !bytes.Equal(got[:], digest) {
		t.Errorf("compared %x rather than the measured image", got)
	}
}

// RecordedKernelHash falls back to the register the agent reports, because an
// attestation record with an empty kernel column says less than one with the
// aggregate in it. The gate must not fall back the same way: the pin was written
// from an image digest, so comparing a whole-boot aggregate against it refuses
// a host for the wrong reason and names the kernel while doing so.
func TestKernelPin_DoesNotFallBackToTheReportedRegister(t *testing.T) {
	register := bytes.Repeat([]byte{0x4b}, types.HashSize)
	facts := &BootFacts{
		KernelImage:        KernelImage{Found: false},
		KernelImageTrusted: false,
	}

	_, err := kernelPinValue(facts)
	if err == nil {
		t.Fatal("a host establishing no kernel image was judged against a kernel pin")
	}
	if strings.Contains(err.Error(), hex.EncodeToString(register)) {
		t.Errorf("the refusal offers a register as the compared value: %v", err)
	}
	if !strings.Contains(err.Error(), "PCR 9") {
		t.Errorf("the refusal does not say what would make the pin evaluable: %v", err)
	}
}

// A kernel image the quote does not cover is a claim. It is not compared and it
// is not silently replaced by something else -- the round is refused with the
// reason, which is a different sentence from "not in allowed list".
func TestKernelPin_RefusesAnImageTheQuoteDoesNotCover(t *testing.T) {
	facts := &BootFacts{
		KernelImage: KernelImage{
			Found:  true,
			Digest: bytes.Repeat([]byte{0x5b}, types.HashSize),
		},
		KernelImageTrusted: false, // PCR 9 outside the quote, or replay disagreed
	}

	_, err := kernelPinValue(facts)
	if err == nil {
		t.Fatal("an unauthenticated kernel image satisfied a kernel pin")
	}
	if !strings.Contains(err.Error(), "quote-bound") {
		t.Errorf("the refusal does not say the image is unauthenticated: %v", err)
	}
}

// No facts at all is the same answer: a pin nothing can be compared against
// is refused.
func TestKernelPin_NoFactsIsRefused(t *testing.T) {
	if _, err := kernelPinValue(nil); err == nil {
		t.Fatal("a kernel pin was evaluated with no boot facts")
	}
}
