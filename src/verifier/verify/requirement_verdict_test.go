// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

// Each policy requirement has its own remedy, so its refusal must name it;
// so must a report with no AIK certificate, not a TPM signature failure.
// Literals, not constants: an unsent code fails the test, not the build.
const (
	codeCertificateMissing   = 13
	codeSecureBootRequired   = 14
	codeLockdownRequired     = 15
	codeModuleSigRequired    = 16
	codeEnforceRequired      = 17
	codeIMAAppraisalRequired = 18
	codeKernelImageRequired  = 19
	codeCmdlineRequired      = 20
)

func TestRequirementRefusalNamesTheRequirement(t *testing.T) {
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
			name: "a kernel image outside the allow-list",
			policy: &PCRPolicy{Name: "p", KernelHashes: []string{
				hex.EncodeToString(listed[:]),
			}},
			report: func() *types.AttestationReport {
				return &types.AttestationReport{}
			},
			facts: &BootFacts{
				KernelImage:        KernelImage{Found: true, Digest: unlisted[:]},
				KernelImageTrusted: true,
			},
			verdict: codeKernelImageRequired,
			names:   "kernel hash not in allowed list",
		},
		{
			name: "a kernel pin this host cannot be judged against",
			policy: &PCRPolicy{Name: "p", KernelHashes: []string{
				hex.EncodeToString(listed[:]),
			}},
			report: func() *types.AttestationReport {
				return &types.AttestationReport{}
			},
			verdict: codeKernelImageRequired,
			names:   "records no kernel image",
		},
		{
			name:   "an LSM that is not enforcing",
			policy: &PCRPolicy{Name: "p", RequireEnforce: true},
			report: func() *types.AttestationReport {
				return &types.AttestationReport{}
			},
			verdict: codeEnforceRequired,
			names:   "LSM enforce mode not active",
		},
		{
			name:   "a kernel that loads unsigned modules",
			policy: &PCRPolicy{Name: "p", RequireModuleSig: true},
			report: func() *types.AttestationReport {
				return &types.AttestationReport{}
			},
			verdict: codeModuleSigRequired,
			names:   "module signature enforcement not enabled",
		},
		{
			name:   "a boot the event log does not authenticate",
			policy: &PCRPolicy{Name: "p", RequireSecureBoot: true},
			report: func() *types.AttestationReport {
				return &types.AttestationReport{}
			},
			verdict: codeSecureBootRequired,
			names:   "Secure Boot state not authenticated",
		},
		{
			name:   "a boot whose log carries no Secure Boot measurement",
			policy: &PCRPolicy{Name: "p", RequireSecureBoot: true},
			report: func() *types.AttestationReport {
				return &types.AttestationReport{}
			},
			facts:   &BootFacts{SecureBootTrusted: true},
			verdict: codeSecureBootRequired,
			names:   "no SecureBoot measurement",
		},
		{
			name:   "firmware that measured Secure Boot off",
			policy: &PCRPolicy{Name: "p", RequireSecureBoot: true},
			report: func() *types.AttestationReport {
				return &types.AttestationReport{}
			},
			facts: &BootFacts{
				SecureBootTrusted: true,
				SecureBoot:        SecureBootState{Found: true, Enabled: false},
			},
			verdict: codeSecureBootRequired,
			names:   "Secure Boot disabled",
		},
		{
			name:   "a kernel with lockdown off",
			policy: &PCRPolicy{Name: "p", RequireLockdown: true},
			report: func() *types.AttestationReport {
				return &types.AttestationReport{}
			},
			verdict: codeLockdownRequired,
			names:   "kernel lockdown not active",
		},
		{
			name:   "a kernel that appraises nothing",
			policy: &PCRPolicy{Name: "p", RequireIMAAppraisal: true},
			report: func() *types.AttestationReport {
				return &types.AttestationReport{}
			},
			verdict: codeIMAAppraisalRequired,
			names:   "appraises no executable",
		},
		{
			name: "a kernel command line carrying a denied parameter",
			policy: &PCRPolicy{
				Name: "p", RequireCmdlinePolicy: true,
				CmdlineDeny: []string{"kgdboc="},
			},
			report: func() *types.AttestationReport {
				return &types.AttestationReport{}
			},
			facts: &BootFacts{
				PCR8Quoted:     true,
				CmdlineTrusted: true,
				Cmdlines:       []string{"root=/dev/sda1 kgdboc=ttyS0"},
			},
			verdict: codeCmdlineRequired,
			names:   "denied parameters",
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
				t.Fatalf("verdict %s (%d), want %d -- the host is told a class and not the requirement",
					types.VerifyResultString(got), got, tc.verdict)
			}
		})
	}
}

// Class-level verdicts stay in policy_verdict_test.go.

// A profile with no certificate on disk reports without one.
func TestReportWithoutAIKCertificateNamesTheAbsentCertificate(t *testing.T) {
	aikStore := newCertStore(t)
	verifier := createTestVerifier(t, aikStore)

	clientID := "cert-absent-client"
	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	reportData := createValidReport(t, clientID, challenge.Nonce, [32]byte{})
	aikCertSizeOff := 16 + types.PCRCount*types.HashSize + 4 +
		types.MaxSigSize + 2 + types.MaxAttestSize + 2 +
		types.MaxAIKPubSize + 2 + types.MaxAIKCertSize
	binary.LittleEndian.PutUint16(reportData[aikCertSizeOff:aikCertSizeOff+2], 0)

	result, verr := verifier.VerifyReport(clientID, reportData)
	if verr == nil {
		t.Fatal("expected verification to fail without an AIK certificate")
	}
	if result == nil {
		t.Fatal("no result to read a verdict off")
	}
	if result.Result != codeCertificateMissing {
		t.Fatalf("verdict %s (%d), want %d -- the host is sent to its TPM for a certificate that is not on disk",
			types.VerifyResultString(result.Result), result.Result,
			codeCertificateMissing)
	}
}
