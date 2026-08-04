// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

func testAgentHash(seed byte) [types.HashSize]byte {
	var h [types.HashSize]byte
	for i := range h {
		h[i] = seed ^ byte(i)
	}
	return h
}

func testAgentHashHex(seed byte) string {
	h := testAgentHash(seed)
	return hex.EncodeToString(h[:])
}

// update case this whole path exists for:
// package upgrade moves the client to build the publisher already lists.
func TestAgentHashDecision_AllowsBlessedBuild(t *testing.T) {
	now := time.Now()
	allowed := []string{testAgentHashHex(0xAA), testAgentHashHex(0xBB)}

	got := agentHashDecision(testAgentHash(0xBB), allowed, time.Time{}, now)
	if got != AgentHashRepin {
		t.Fatalf("expected %v, got %v", AgentHashRepin, got)
	}
}

// empty allow-list is the enterprise profile:
// nobody has said which agent builds are trusted,
// so the TOFU pin is the only such statement and it stands.
func TestAgentHashDecision_EscalatesWithoutAllowList(t *testing.T) {
	got := agentHashDecision(testAgentHash(0xBB), nil, time.Time{}, time.Now())
	if got != AgentHashEscalate {
		t.Fatalf("expected %v, got %v", AgentHashEscalate, got)
	}

	got = agentHashDecision(testAgentHash(0xBB), []string{}, time.Time{}, time.Now())
	if got != AgentHashEscalate {
		t.Fatalf("empty slice: expected %v, got %v", AgentHashEscalate, got)
	}
}

// hash nobody blessed is the drift the pin was built to catch
func TestAgentHashDecision_EscalatesUnlistedHash(t *testing.T) {
	allowed := []string{testAgentHashHex(0xAA)}

	got := agentHashDecision(testAgentHash(0xCC), allowed, time.Time{}, time.Now())
	if got != AgentHashEscalate {
		t.Fatalf("expected %v, got %v", AgentHashEscalate, got)
	}
}

func TestAgentHashDecision_RateLimitsRepeatedRepins(t *testing.T) {
	now := time.Now()
	allowed := []string{testAgentHashHex(0xBB)}
	reported := testAgentHash(0xBB)

	recent := now.Add(-AgentHashRepinMinInterval + time.Minute)
	if got := agentHashDecision(reported, allowed, recent, now); got != AgentHashEscalate {
		t.Fatalf("inside the window: expected %v, got %v", AgentHashEscalate, got)
	}

	elapsed := now.Add(-AgentHashRepinMinInterval - time.Minute)
	if got := agentHashDecision(reported, allowed, elapsed, now); got != AgentHashRepin {
		t.Fatalf("past the window: expected %v, got %v", AgentHashRepin, got)
	}
}

// zero verdict must be the refusing one, so path that forgets to assign fails closed
func TestAgentHashDecision_ZeroVerdictIsEscalate(t *testing.T) {
	// a lookup that misses carries the same zero value a path that never
	// assigned one holds
	decided := map[string]AgentHashVerdict{}

	v := decided["client that never reported"]
	if v != AgentHashEscalate {
		t.Fatalf("zero value must be escalate, got %v", v)
	}
	if v.String() != "escalate" {
		t.Fatalf("zero value String(): got %q", v.String())
	}
}

// Policy gate and the re-pin discriminator must read the allow-list the same way.
// They share agentHashAllowed for that reason, so this pins the predicate's own
// contract: lower-case hex matches, anything else does not
func TestAgentHashAllowed_ComparesLowerCaseHex(t *testing.T) {
	reported := testAgentHash(0xBB)
	lower := hex.EncodeToString(reported[:])

	if !agentHashAllowed(reported, []string{"deadbeef", lower}) {
		t.Fatal("lower-case hex entry must match")
	}
	if agentHashAllowed(reported, []string{strings.ToUpper(lower)}) {
		t.Fatal("upper-case hex entry must not match")
	}
	if agentHashAllowed(reported, nil) {
		t.Fatal("empty list must not match")
	}

	// and the discriminator must inherit exactly that
	if agentHashDecision(reported, []string{strings.ToUpper(lower)},
		time.Time{}, time.Now()) != AgentHashEscalate {
		t.Fatal("discriminator accepted what the predicate rejects")
	}
}
