// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package types

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The verdict codes are a wire contract between two enumerations that live in
// different languages and were written at different times: the verifier's
// const block here, and the agent's VERIFY_* macros in src/agent/net.h.
// A code the verifier sends and the agent has never heard of arrives on
// the machine as "Unknown error", which is the only account that machine has
// of why it stopped attesting.
//
// So the test reads both lists off disk rather than restating either.
// A code added on one side and forgotten on the other fails here, in the build,
// by number.
const (
	agentHeaderPath   = "../../agent/net.h"
	verifierCodesPath = "report.go"
)

var (
	agentCodeRe    = regexp.MustCompile(`(?m)^#define\s+(VERIFY_[A-Z0-9_]+)\s+([0-9]+)\s*$`)
	verifierCodeRe = regexp.MustCompile(`(?m)^\s*(Verify[A-Za-z0-9]+)\s+uint32\s*=\s*([0-9]+)`)
)

// codes maps a declared value to the name it was declared under
func codes(t *testing.T, path string, re *regexp.Regexp) map[uint32]string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}

	out := make(map[uint32]string)
	for _, m := range re.FindAllStringSubmatch(string(data), -1) {
		v, err := strconv.ParseUint(m[2], 10, 32)
		if err != nil {
			t.Fatalf("%s: %s = %q is not a number", path, m[1], m[2])
		}
		if prev, dup := out[uint32(v)]; dup {
			t.Errorf("%s: %s and %s are both %d", path, prev, m[1], v)
		}
		out[uint32(v)] = m[1]
	}
	if len(out) == 0 {
		t.Fatalf("%s: no verdict codes found; the pattern has gone stale", path)
	}
	return out
}

func TestVerdictCodesAgreeWithTheAgent(t *testing.T) {
	verifier := codes(t, verifierCodesPath, verifierCodeRe)
	agent := codes(t, agentHeaderPath, agentCodeRe)

	for value, name := range verifier {
		if _, ok := agent[value]; !ok {
			t.Errorf("verifier sends %s = %d and the agent has no name for it, so a host receiving it reports an unknown error", name, value)
		}
	}
	for value, name := range agent {
		if _, ok := verifier[value]; !ok {
			t.Errorf("the agent names %s = %d, which no verifier sends", name, value)
		}
	}
}

// Every code this side can send needs a string on this side too:
// the verifier's own logs and its operator API are where a support call starts
func TestVerdictCodesAreNamedHere(t *testing.T) {
	unknown := regexp.MustCompile(`^unknown_[0-9]+$`)

	for value, name := range codes(t, verifierCodesPath, verifierCodeRe) {
		if s := VerifyResultString(value); unknown.MatchString(s) {
			t.Errorf("%s = %d renders as %q", name, value, s)
		}
	}
}
