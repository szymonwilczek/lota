// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - PCR 14 re-pin after a MOK change

package verify

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/types"
)

// ErrPCR14RepinRaced is returned by RepinPCR14 when the pinned register is no
// longer the one the decision was made against.
var ErrPCR14RepinRaced = errors.New("PCR 14 re-pin: pinned register moved")

// PCR14RepinStorer is optionally implemented by baseline stores that can move
// a client's pinned PCR 14 after its MOK state changed.
//
// RepinPCR14 replaces the pinned register from -> to and stores eventLog as the
// client's boot evidence in one write, so the next diff runs against the boot
// that produced the new pin. It returns ErrPCR14RepinRaced when the row no
// longer holds from.
type PCR14RepinStorer interface {
	RepinPCR14(clientID string, from, to [types.HashSize]byte,
		eventLog []byte, now time.Time) error
}

// mokPCR14Events names the PCR 14 events that carry the MOK state.
var mokPCR14Events = []string{"MokList", "MokListX", "MokListTrusted"}

func pcr14Events(parsed *ParsedEventLog) []*EventLogEntry {
	var out []*EventLogEntry
	for i := range parsed.Entries {
		e := &parsed.Entries[i]
		if e.PCRIndex == pcr14Index && e.EventType != EvNoAction {
			out = append(out, e)
		}
	}
	return out
}

func eventName(e *EventLogEntry) string {
	return string(bytes.TrimRight(e.EventData, "\x00"))
}

// mokPCR14Change returns the MOK events whose digest moved between the pinned
// boot's log and this one, or an error when anything else in PCR 14 moved.
//
// Event data is outside the digest, so a name is trusted only at the position
// the pinned log gave it: both logs must carry the same events in the same
// order, and only the digests may differ.
func mokPCR14Change(pinned, current *ParsedEventLog) ([]string, error) {
	pe := pcr14Events(pinned)
	ce := pcr14Events(current)
	if len(pe) == 0 {
		return nil, errors.New("the pinned boot measured nothing into PCR 14")
	}
	if len(pe) != len(ce) {
		return nil, fmt.Errorf("PCR 14 carries %d events, the pinned boot %d",
			len(ce), len(pe))
	}

	var changed []string
	for i := range pe {
		name := eventName(pe[i])
		if pe[i].EventType != ce[i].EventType || name != eventName(ce[i]) {
			return nil, fmt.Errorf("PCR 14 event %d is not the one the pinned boot logged", i)
		}
		if bytes.Equal(pe[i].Digests[AlgSHA256], ce[i].Digests[AlgSHA256]) {
			continue
		}
		if !slices.Contains(mokPCR14Events, name) {
			return nil, fmt.Errorf("PCR 14 event %q moved, and only the MOK state re-pins", name)
		}
		changed = append(changed, name)
	}
	if len(changed) == 0 {
		return nil, errors.New("no PCR 14 event moved")
	}
	return changed, nil
}

// tryMOKRepin decides whether a client whose PCR 14 moved from its pin may move
// the pin with it. Returns true only on an actual re-pin.
//
// By the time this runs the register is derived from this boot's log and the
// agent hash, so what moved is the pre-lock baseline. The pin follows it only
// when the change sits in the MOK events alone, and the re-pin logs which
// lists moved.
//
// Gated like the boot re-anchor: the tenant's profile enables self-service and
// its policy requires Secure Boot, which this boot's log proves.
func (v *Verifier) tryMOKRepin(clog *slog.Logger, clientID, tenant string,
	pinned, pcr14 [types.HashSize]byte, report *types.AttestationReport,
	bootFacts *BootFacts,
) bool {
	if !v.selfServiceReanchorForTenant(tenant) {
		return false
	}
	if !v.pcrVerifier.PolicyRequiresSecureBootForTenant(tenant) || !SecureBootAnchored(bootFacts) {
		return false
	}
	rs, ok := v.baselineStore.(ReanchorStorer)
	if !ok {
		return false
	}
	ps, ok := v.baselineStore.(PCR14RepinStorer)
	if !ok {
		return false
	}

	escalate := func(reason string) bool {
		logging.Security(clog, "PCR14 re-pin escalated to operator", "reason", reason)
		v.metrics.Reanchors.Inc("escalate")
		return false
	}

	st := rs.GetReanchorState(clientID)
	if len(st.EventLogBaseline) == 0 {
		return escalate("no baseline event log on record")
	}
	pinnedLog, err := ParseEventLog(st.EventLogBaseline)
	if err != nil {
		return escalate("baseline event log unparseable")
	}
	// the log on record must be the boot the pin came from
	if DeriveLockedBootCommitmentPCR14(PCR14BaselineFromEventLog(pinnedLog),
		report.System.AgentHash) != pinned {
		return escalate("baseline event log does not derive the pinned PCR 14")
	}
	changed, err := mokPCR14Change(pinnedLog, bootFacts.Parsed)
	if err != nil {
		return escalate(err.Error())
	}
	if slices.Contains(changed, "MokList") &&
		mokListState(bootFacts.Parsed, report.MokList) != MOKListed {
		return escalate("MokList moved and the report carries no list that hashes to it")
	}

	err = ps.RepinPCR14(clientID, pinned, pcr14, report.EventLog, time.Now())
	if err != nil {
		if errors.Is(err, ErrPCR14RepinRaced) {
			return escalate("pinned PCR 14 moved during the re-pin")
		}
		clog.Warn("PCR14 re-pin failed", "error", err)
		return false
	}

	logging.Security(clog, "PCR14 re-pinned after a MOK change",
		"changed", changed,
		"pinned_pcr14", FormatPCR14(pinned),
		"pcr14", FormatPCR14(pcr14))
	v.metrics.Reanchors.Inc("mok")
	return true
}
