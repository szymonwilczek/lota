// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Agent-hash re-pin decision

package verify

import (
	"errors"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// ErrAgentHashRepinRateLimited is returned by store's ArchiveAndRepinAgentHash
// when the per-client interval has not elapsed.
// The interval is re-checked inside the write transaction (under the row lock),
// so concurrent attestations for one client cannot race the cheap-path gate in
// agentHashDecision.
var ErrAgentHashRepinRateLimited = errors.New("agent-hash re-pin: rate limit not elapsed")

// Minimum spacing between agent-hash re-pins for one client.
//
// Deliberately far shorter than the boot re-anchor intervals, because the two
// are guarded by different things.
// Boot re-anchor has no allow-list to appeal to, so its rate limit is the main barrier.
// Here the policy allow-list is the barrier: every hash this path accepts is
// a build the publisher already trusts, so the interval only has to make
// oscillation visible rather than carry the security argument on its own.
// Package update arrives at most daily even on fast-moving distribution;
// client flipping builds faster than that is reporting something other than update.
const AgentHashRepinMinInterval = 24 * time.Hour

// AgentHashVerdict is the outcome of the agent-hash re-pin discriminator.
// The zero value is Escalate so any unhandled path fails closed.
type AgentHashVerdict int

const (
	// AgentHashEscalate:
	// the pinned baseline stands and the attestation is refused.
	// Recovering is operator action.
	AgentHashEscalate AgentHashVerdict = iota
	// AgentHashRepin:
	// the client may move its baseline to the reported hash.
	AgentHashRepin
)

func (v AgentHashVerdict) String() string {
	if v == AgentHashRepin {
		return "repin"
	}
	return "escalate"
}

// agentHashDecision answers whether a client whose reported agent hash differs
// from its pinned baseline may re-pin to the reported one.
//
// Call it only on mismatch; match never reaches this path.
//
// What the caller has already proven by the time this runs is what makes
// the decision safe.
// MatchLockedBootCommitmentPCR14 derives the expected PCR 14 from the *reported*
// hash and compares it against the quoted register, so the reported hash is not
// a claim: it is the binary that actually extended PCR 14 during this boot,
// attested by the TPM.
// Per-client baseline therefore adds nothing beyond the allow-list when allow-list
// exists -- its value is precisely the case where there is none.
//
// So:
//   - The policy allow-list is the authority. Hash on it is a build the publisher
//     has blessed, and refusing a transition into a blessed build protects nothing
//     while breaking every player on update day.
//   - Empty allow-list means there is no trust root to appeal to. TOFU pin is
//     then the only statement anyone has made about which agent this client runs,
//     so it stands and the operator decides. This is the enterprise profile,
//     and its behaviour does not change.
//   - The interval bounds how often one client may move.
//
// The allow-list test is agentHashAllowed, the same predicate the policy gate
// in verifyAgainstPolicy uses.
// Sharing it is deliberate: two independent comparisons of the same list could
// drift, and a hash one gate reads as allowed while the other does not would be
// a hole in whichever is weaker.
func agentHashDecision(
	reported [types.HashSize]byte,
	allowedHashes []string,
	lastRepin time.Time,
	now time.Time,
) AgentHashVerdict {
	if len(allowedHashes) == 0 {
		return AgentHashEscalate
	}

	if !agentHashAllowed(reported, allowedHashes) {
		return AgentHashEscalate
	}

	// client that has never re-pinned carries the zero time, which is older
	// than any interval, so first update is never rate limited
	if !lastRepin.IsZero() && now.Sub(lastRepin) < AgentHashRepinMinInterval {
		return AgentHashEscalate
	}

	return AgentHashRepin
}
