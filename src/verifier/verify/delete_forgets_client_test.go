// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

// ListClients merges the baseline store, the AIK registry and the nonce
// store's per-identity state; delete must clear all three. The used-nonce
// history (replay defence) is keyed separately and stays.
func TestDeleteTakesTheClientOutOfTheListing(t *testing.T) {
	aikStore := store.NewMemoryStore()

	cfg := DefaultConfig()
	cfg.RequireBootEnrollment = false
	v := NewVerifier(cfg, aikStore)

	const clientID = "host-0001"

	var pcr14 [types.HashSize]byte
	pcr14[0] = 0x11
	if res, _ := v.baselineStore.CheckAndUpdate(clientID, pcr14); res != TOFUFirstUse {
		t.Fatalf("seeding baseline: %v, want first use", res)
	}

	// live host: counter and last attestation time
	v.nonceStore.mu.Lock()
	v.nonceStore.identityChallenges[clientID] = clientState{
		attestCounter:   7,
		lastAttestation: time.Now(),
	}
	v.nonceStore.mu.Unlock()

	if err := v.DeleteClient(clientID); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}

	for _, id := range v.ListClients() {
		if id == clientID {
			t.Fatal("a deleted client is still listed, so the operator cannot tell the removal worked")
		}
	}
	if got := v.nonceStore.ClientCounter(clientID); got != 0 {
		t.Fatalf("the deleted client kept its attestation counter (%d)", got)
	}
	if got := v.nonceStore.ClientLastAttestation(clientID); !got.IsZero() {
		t.Fatalf("the deleted client kept its last-attestation time (%v)", got)
	}
}
