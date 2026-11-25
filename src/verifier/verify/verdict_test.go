// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// baseOnlyStore implements the base baseline contract and nothing else,
// which is the shape of a store the verifier cannot pin firmware PCRs with.
// The interface is embedded so the optional contracts are genuinely absent.
type baseOnlyStore struct{ BaselineStorer }

// A store the verifier cannot use is a verifier fault; the verdict must not
// tell a healthy host its integrity failed.
func TestBaselineStoreFailureIsNotAnIntegrityVerdict(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NonceLifetime = 1 * time.Second
	cfg.RequireBootEnrollment = false
	cfg.BaselineStore = baseOnlyStore{NewBaselineStore()}

	v := NewVerifier(cfg, newCertVerifier(t))
	if err := v.AddPolicy(DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	const clientID = "store-without-boot-pinning"
	challenge, err := v.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	report := createValidReport(t, clientID, challenge.Nonce, fixturePCR14())

	result, err := v.VerifyReportFrom(clientID, "", report)
	if err == nil {
		t.Fatal("a store that cannot pin boot PCRs was accepted")
	}
	if !strings.Contains(err.Error(), "store missing boot PCR support") {
		t.Fatalf("refused for another reason: %v", err)
	}
	if result.Result != types.VerifyInternalError {
		t.Fatalf("verdict %s (%d), want internal_error",
			types.VerifyResultString(result.Result), result.Result)
	}
}

// The verdict is all the host learns of a refusal; the verifier's log is out
// of its reach. A refusal unrelated to a register (an unlisted agent build,
// no IOMMU) must carry its own class, not "PCR values don't match policy",
// which points at the boot chain.
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

// A truncated report is a bad link or a forged frame, not an agent to
// upgrade, so it must not share old_version with an older wire.
// Literals, not constants: an unsent code fails the test, not the build.
const (
	codeOldVersion      = 5
	codeReportMalformed = 21
)

// one report cut at two depths, and one with an unknown wire version
func TestTruncatedReportIsNotAnOldAgent(t *testing.T) {
	cases := []struct {
		name    string
		cut     func(report []byte) []byte
		verdict uint32
		reason  string
	}{
		{
			name: "a report that stops before the mandatory ESRT section",
			cut: func(report []byte) []byte {
				return report[:len(report)-types.MokListSizeLen-types.ESRTWireSize]
			},
			verdict: codeReportMalformed,
			reason:  "report_malformed",
		},
		{
			name: "a report one byte short of the ESRT section",
			cut: func(report []byte) []byte {
				return report[:len(report)-types.MokListSizeLen-1]
			},
			verdict: codeReportMalformed,
			reason:  "report_malformed",
		},
		{
			name: "a report that stops before the mandatory MOK list section",
			cut: func(report []byte) []byte {
				return report[:len(report)-types.MokListSizeLen]
			},
			verdict: codeReportMalformed,
			reason:  "report_malformed",
		},
		{
			name: "a report that stops inside the event log",
			cut: func(report []byte) []byte {
				// shortest legal frame, still inside the log
				return report[:types.MinReportSize]
			},
			verdict: codeReportMalformed,
			reason:  "report_malformed",
		},
		{
			name: "an agent on another wire",
			cut: func(report []byte) []byte {
				binary.LittleEndian.PutUint32(report[4:8], types.ReportVersion+0x00010000)
				return report
			},
			verdict: codeOldVersion,
			reason:  "old_version",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := createTestVerifier(t, newCertVerifier(t))

			clientID := "malformed-report-client"
			challenge, err := verifier.GenerateChallenge(clientID)
			if err != nil {
				t.Fatalf("GenerateChallenge: %v", err)
			}

			report := tc.cut(createValidReport(t, clientID, challenge.Nonce, fixturePCR14()))

			before := verifier.metrics.Rejections.Values()[tc.reason]
			result, verr := verifier.VerifyReportFrom(clientID, "", report)
			if verr == nil {
				t.Fatal("the verifier accepted a report it cannot parse")
			}
			if result == nil {
				t.Fatal("no result to read a verdict off")
			}
			if result.Result != tc.verdict {
				t.Fatalf("verdict %s (%d), want %d -- the two peers are told the same thing and the answers differ",
					types.VerifyResultString(result.Result),
					result.Result, tc.verdict)
			}
			if after := verifier.metrics.Rejections.Values()[tc.reason]; after != before+1 {
				t.Fatalf("the %s series read %d and now reads %d: the arm that produces the verdict does not count it",
					tc.reason, before, after)
			}
		})
	}
}

// Every refusal arm counts a reason. Arms are read from the source
// so that an arm added later without a count fails here.
func TestEveryRefusalArmCountsItsReason(t *testing.T) {
	const verifyPath = "verify.go"

	data, err := os.ReadFile(verifyPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", verifyPath, err)
	}
	lines := strings.Split(string(data), "\n")

	// the count must sit between the previous arm's end and the verdict
	refusal := regexp.MustCompile(`^\s*result\.Result = (.+)$`)
	armEnd := regexp.MustCompile(`^\s*return result`)

	armStart := 0
	arms := 0
	for i, line := range lines {
		if armEnd.MatchString(line) {
			armStart = i
			continue
		}
		m := refusal.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if strings.TrimSpace(m[1]) == "types.VerifyOK" {
			armStart = i
			continue
		}

		arms++
		counted := false
		for _, before := range lines[armStart : i+1] {
			if strings.Contains(before, "Rejections.Inc(") {
				counted = true
				break
			}
		}
		if !counted {
			t.Errorf("%s:%d: the arm refusing with %s returns without touching Rejections, so its reason series can never leave zero",
				verifyPath, i+1, strings.TrimSpace(m[1]))
		}
		armStart = i
	}

	if arms == 0 {
		t.Fatalf("%s: no refusal arms found; the pattern has gone stale", verifyPath)
	}
}

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
			names:   "exec appraisal not established",
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

// With no attestation-CA root nothing can vouch for an AIK, and the fault is
// the verifier's: the host must not be told its evidence was bad.
func TestVerifierWithoutCARootRefusesAsItsOwnFault(t *testing.T) {
	verifier := createTestVerifier(t, nil)

	clientID := "no-ca-root-client"
	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	result, verr := verifier.VerifyReportFrom(clientID, "",
		createValidReport(t, clientID, challenge.Nonce, [32]byte{}))
	if verr == nil {
		t.Fatal("a verifier with no CA root attested a report")
	}
	if result == nil || result.Result != types.VerifyInternalError {
		t.Fatalf("result %+v, want the internal-error verdict", result)
	}
}

// A profile with no certificate on disk reports without one.
func TestReportWithoutAIKCertificateNamesTheAbsentCertificate(t *testing.T) {
	aikVerifier := newCertVerifier(t)
	verifier := createTestVerifier(t, aikVerifier)

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

	result, verr := verifier.VerifyReportFrom(clientID, "", reportData)
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
