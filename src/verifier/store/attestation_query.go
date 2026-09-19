// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - reading the decision log by what is being asked
//
// Narrowed reads: what went wrong, on which host, during which window.

package store

import "time"

// AttestationQuery narrows a read of the decision log.
// A zero query reads the whole log, newest first.
type AttestationQuery struct {
	// zero or less: no limit
	Limit int

	// rows overlapping the window, including ones opened before it;
	// a zero bound is open on that side
	Since time.Time
	Until time.Time

	// one verdict, empty for any
	Result string

	// non-trusted rows only; ignored when Result is set
	EventsOnly bool

	// one subject, empty for any
	Tenant   string
	ClientID string
}

// AttestationQuerier is an optional AttestationLog capability:
// narrowing in the backend.
// Without it a caller filters the whole log itself.
type AttestationQuerier interface {
	QueryAttestationsFiltered(q AttestationQuery) []AttestationRecord
}
