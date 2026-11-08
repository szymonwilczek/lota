// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Agent-hash re-pin decision

package verify

import (
	"errors"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// ErrAgentHashRepinRateLimited is returned by a store's
// ArchiveAndRepinAgentHash when the client's interval has not elapsed.
var ErrAgentHashRepinRateLimited = errors.New("agent-hash re-pin: rate limit not elapsed")

// ErrAgentHashNotPinned is returned by a store's ArchiveAndRepinAgentHash
// when the row carries no agent hash (out-of-band PCR 14 pin).
var ErrAgentHashNotPinned = errors.New("agent-hash re-pin: row has no pinned agent_hash to replace")

// AgentHashRepinMinInterval is the minimum spacing between agent-hash
// re-pins of one client. The policy allow-list is the barrier here,
// so the interval only makes a client that flips between builds visible.
const AgentHashRepinMinInterval = 24 * time.Hour

// AgentHashVerdict is the outcome of agentHashDecision.
// The zero value is AgentHashEscalate.
type AgentHashVerdict int

const (
	// AgentHashEscalate keeps the pinned baseline and refuses the
	// attestation.
	AgentHashEscalate AgentHashVerdict = iota
	// AgentHashRepin lets the client move its pin to the reported hash.
	AgentHashRepin
)

// AgentHashRefusal is why a re-pin was refused.
type AgentHashRefusal int

const (
	// AgentHashNoRefusal means the re-pin was allowed.
	AgentHashNoRefusal AgentHashRefusal = iota
	// AgentHashNoAllowList means the policy lists no build.
	AgentHashNoAllowList
	// AgentHashNotAllowed means the reported build is not listed.
	AgentHashNotAllowed
	// AgentHashTooSoon means the reported build is listed and the client
	// re-pinned less than AgentHashRepinMinInterval ago.
	AgentHashTooSoon
)

// agentHashDecision answers whether a client whose reported agent hash differs
// from its pinned one may re-pin to the reported hash: only when the policy
// allow-list names it and the interval has passed. The reported hash is the
// binary that extended PCR 14 this boot, since MatchLockedBootCommitmentPCR14
// derived the quoted register from it. With an empty allow-list the pin
// stands.
//
// The allow-list test is agentHashAllowed, the predicate of the policy gate
// in verifyAgainstPolicy.
func agentHashDecision(
	reported [types.HashSize]byte,
	allowedHashes []string,
	lastRepin time.Time,
	now time.Time,
) (AgentHashVerdict, AgentHashRefusal) {
	if len(allowedHashes) == 0 {
		return AgentHashEscalate, AgentHashNoAllowList
	}

	if !agentHashAllowed(reported, allowedHashes) {
		return AgentHashEscalate, AgentHashNotAllowed
	}

	if !lastRepin.IsZero() && now.Sub(lastRepin) < AgentHashRepinMinInterval {
		return AgentHashEscalate, AgentHashTooSoon
	}

	return AgentHashRepin, AgentHashNoRefusal
}
