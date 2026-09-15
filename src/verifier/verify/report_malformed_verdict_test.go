// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"encoding/binary"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

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
				return report[:len(report)-types.ESRTWireSize]
			},
			verdict: codeReportMalformed,
			reason:  "report_malformed",
		},
		{
			name: "a report one byte short of the ESRT section",
			cut: func(report []byte) []byte {
				return report[:len(report)-1]
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
			name: "an agent on wire 1.0.0",
			cut: func(report []byte) []byte {
				binary.LittleEndian.PutUint32(report[4:8], 0x00010000)
				return report
			},
			verdict: codeOldVersion,
			reason:  "old_version",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := createTestVerifier(t, newCertStore(t))

			clientID := "malformed-report-client"
			challenge, err := verifier.GenerateChallenge(clientID)
			if err != nil {
				t.Fatalf("GenerateChallenge: %v", err)
			}

			report := tc.cut(createValidReport(t, clientID, challenge.Nonce, fixturePCR14()))

			before := verifier.metrics.Rejections.Values()[tc.reason]
			result, verr := verifier.VerifyReport(clientID, report)
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
