// SPDX-License-Identifier: MIT
package server

import (
	"encoding/hex"
	"testing"
)

func TestNewChallengeID_UniqueAndHex(t *testing.T) {
	id1, err := newChallengeID()
	if err != nil {
		t.Fatalf("newChallengeID 1: %v", err)
	}
	id2, err := newChallengeID()
	if err != nil {
		t.Fatalf("newChallengeID 2: %v", err)
	}
	if id1 == id2 {
		t.Fatalf("expected different challenge IDs, got same: %q", id1)
	}
	if len(id1) != 32 {
		t.Fatalf("expected 32 hex chars, got %d (%q)", len(id1), id1)
	}
	if _, err := hex.DecodeString(id1); err != nil {
		t.Fatalf("id1 is not hex: %q: %v", id1, err)
	}
}
