// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - What the decision log records
//
// A row records a change; a round identical to the standing row folds into it.
// Backend-free, so both SQL stores agree.

package store

import "time"

// DefaultCollapseWindow applies when a deployment sets none.
// An hour keeps per-day evidence and folds twelve five-minute rounds into one
// row.
const DefaultCollapseWindow = time.Hour

// verdict of a trusted round; every other verdict is an event
const attestationResultOK = "ok"

func attestationIsEvent(r AttestationRecord) bool {
	return r.Result != attestationResultOK
}

// whether @next folds into @standing (zero when no row is open).
// A zero @window records every round.
func attestationCollapses(standing, next AttestationRecord, window time.Duration) bool {
	if window <= 0 {
		return false
	}

	// first sighting
	if standing.Rounds <= 0 || standing.Timestamp.IsZero() {
		return false
	}

	// failure and recovery are both events
	if attestationIsEvent(standing) || attestationIsEvent(next) {
		return false
	}

	// client IDs are unique only per tenant
	if standing.Tenant != next.Tenant || standing.ClientID != next.ClientID {
		return false
	}

	// same verdict over different evidence is a new row
	if standing.HardwareID != next.HardwareID ||
		standing.PCR14 != next.PCR14 ||
		standing.KernelHash != next.KernelHash ||
		standing.Details != next.Details {
		return false
	}

	// a reordered flush must not move last_seen backwards
	last := standing.LastSeen
	if last.IsZero() {
		last = standing.Timestamp
	}
	if next.Timestamp.Before(last) {
		return false
	}

	// from the row's opening, else a busy host holds one row forever
	return !next.Timestamp.After(standing.Timestamp.Add(window))
}
