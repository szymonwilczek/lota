// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - the decision log's times are instants
//
// Rows are compared by time to extend and to answer window reads, from
// verifiers in any zone. Postgres stores timestamptz; SQLite stores what it
// is given, so it gets UTC text of fixed width, where text order is time order.

package store

import (
	"fmt"
	"time"
)

// UTC, fixed width: text order is time order
const attestationTimeLayout = "2006-01-02 15:04:05.000000000"

// SQLite argument for a decision-log time, written or queried
func attestationTimeArg(t time.Time) any {
	return t.UTC().Format(attestationTimeLayout)
}

// time column as the driver returned it, as UTC; unreadable is an error,
// never the zero time, which would read as an ancient row
func attestationTimeValue(v any) (time.Time, error) {
	switch t := v.(type) {
	case nil:
		return time.Time{}, nil
	case time.Time:
		return t.UTC(), nil
	case string:
		return parseAttestationTime(t)
	case []byte:
		return parseAttestationTime(string(t))
	default:
		return time.Time{}, fmt.Errorf("a decision-log time came back as %T", v)
	}
}

// ours, then the ones drivers render timestamps in
var attestationTimeLayouts = []string{
	attestationTimeLayout,
	"2006-01-02 15:04:05",
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999-07:00",
}

func parseAttestationTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range attestationTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("a decision-log time reads as no time: %q", s)
}
