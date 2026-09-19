// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - What the decision log records
//
// A row records a change; a round identical to the standing row folds into it.
// Backend-free, so both SQL stores agree.

package store

import "time"

// whether @next folds into @standing (zero when no row is open).
// A zero @window records every round.
func attestationCollapses(standing, next AttestationRecord, window time.Duration) bool {
	// nothing collapses yet
	return false
}
