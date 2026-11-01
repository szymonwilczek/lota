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

// WHERE clause and arguments for @q; shared so both SQL stores agree.
// @timeArg renders a bound as the store writes its times.
func attestationQueryClauses(q AttestationQuery, placeholder func(n int) string,
	timeArg func(time.Time) any,
) (where string, args []any) {
	add := func(clause string, arg any) {
		args = append(args, arg)
		cond := clause + " " + placeholder(len(args))
		if where == "" {
			where = " WHERE " + cond
			return
		}
		where += " AND " + cond
	}

	// overlap, not containment: a row may open before the window
	if !q.Since.IsZero() {
		add("last_seen >=", timeArg(q.Since))
	}
	if !q.Until.IsZero() {
		add("timestamp <=", timeArg(q.Until))
	}

	if q.Result != "" {
		add("result =", q.Result)
	} else if q.EventsOnly {
		add("result <>", attestationResultOK)
	}

	if q.Tenant != "" {
		add("tenant =", q.Tenant)
	}
	if q.ClientID != "" {
		add("client_id =", q.ClientID)
	}
	return where, args
}
