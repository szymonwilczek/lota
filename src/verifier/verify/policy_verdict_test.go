// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

// The verdict is all the host learns of a refusal; the verifier's log is out
// of its reach. A refusal unrelated to a register (an unlisted agent build,
// no IOMMU) must carry its own class, not "PCR values don't match policy",
// which points at the boot chain.
// Single requirements are in requirement_verdict_test.go.
func TestPolicyRefusalCarriesItsOwnVerdict(t *testing.T) {
	unlisted := [types.HashSize]byte{0xAB}
	listed := [types.HashSize]byte{0xCD}

	cases := []struct {
		name    string
		policy  *PCRPolicy
		report  func() *types.AttestationReport
		facts   *BootFacts
		verdict uint32
		names   string
	}{
		{
			name: "an agent build nobody listed",
			policy: &PCRPolicy{Name: "p", AgentHashes: []string{
				hex.EncodeToString(listed[:]),
			}},
			report: func() *types.AttestationReport {
				r := &types.AttestationReport{}
				r.System.AgentHash = unlisted
				return r
			},
			verdict: types.VerifyIntegrityMismatch,
			names:   "agent hash not in allowed list",
		},
		{
			name:   "a host with DMA remapping off",
			policy: &PCRPolicy{Name: "p", RequireIOMMU: true},
			report: func() *types.AttestationReport {
				return &types.AttestationReport{}
			},
			verdict: types.VerifyIOMMUFail,
			names:   "IOMMU DMA remapping not enabled",
		},
		{
			name: "a register that moved, which is what the PCR verdict is for",
			policy: &PCRPolicy{Name: "p", PCRs: map[int]string{
				7: hex.EncodeToString(listed[:]),
			}},
			report: func() *types.AttestationReport {
				r := &types.AttestationReport{}
				r.TPM.PCRMask = 1 << 7
				r.TPM.PCRValues[7] = unlisted
				return r
			},
			verdict: types.VerifyPCRFail,
			names:   "PCR 7 mismatch",
		},
		{
			name: "a register the quote does not cover",
			policy: &PCRPolicy{Name: "p", PCRs: map[int]string{
				7: hex.EncodeToString(listed[:]),
			}},
			report: func() *types.AttestationReport {
				return &types.AttestationReport{}
			},
			verdict: types.VerifyPCRFail,
			names:   "PCR 7 not included in quote",
		},
	}

	v := &PCRVerifier{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.verifyAgainstPolicy(tc.report(), tc.policy, tc.facts)
			if err == nil {
				t.Fatal("the policy accepted a host it states a requirement about")
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Fatalf("the refusal does not name what failed: %v", err)
			}
			if got := policyVerdict(err); got != tc.verdict {
				t.Fatalf("verdict %s (%d), want %s (%d)",
					types.VerifyResultString(got), got,
					types.VerifyResultString(tc.verdict), tc.verdict)
			}
		})
	}
}

// A refusal that never gets classified is still a refusal, and the register
// verdict is the one that claims least about a cause -- so that is where an
// unwrapped error lands.
func TestUnclassifiedPolicyErrorStaysAPCRVerdict(t *testing.T) {
	policy := &PCRPolicy{Name: "p", PCRs: map[int]string{99: "00"}}
	v := &PCRVerifier{}

	err := v.verifyAgainstPolicy(&types.AttestationReport{}, policy, nil)
	if err == nil {
		t.Fatal("an out-of-range PCR index was accepted")
	}
	if got := policyVerdict(err); got != types.VerifyPCRFail {
		t.Fatalf("verdict %d, want VerifyPCRFail", got)
	}
}
