// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"slices"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// ListClients merges the baseline store and the nonce store's per-identity
// state; delete must clear both. The used-nonce
// history (replay defence) is keyed separately and stays.
func TestDeleteTakesTheClientOutOfTheListing(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireBootEnrollment = false
	v := NewVerifier(cfg, nil)

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

// A global page takes the clients only this instance knows in the same ID
// order as the durable ones; a tenant page takes the durable ones only.
func TestClientsPageMergesInstanceOnlyClients(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireBootEnrollment = false
	v := NewVerifier(cfg, nil)

	for i, id := range []string{"host-b", "host-d"} {
		var pcr14 [types.HashSize]byte
		pcr14[0] = byte(i + 1)
		v.baselineStore.CheckAndUpdate(id, pcr14)
	}
	v.nonceStore.mu.Lock()
	for _, id := range []string{"host-a", "host-c", "host-d"} {
		v.nonceStore.identityChallenges[id] = clientState{
			attestCounter: 1,
		}
	}
	v.nonceStore.mu.Unlock()

	for _, tc := range []struct {
		tenants []string
		after   string
		want    []string
	}{
		{nil, "", []string{"host-a", "host-b"}},
		{nil, "host-b", []string{"host-c", "host-d"}},
		{nil, "host-d", []string{}},
		{[]string{DefaultTenant}, "", []string{"host-b", "host-d"}},
	} {
		got, err := v.ClientsPage(tc.tenants, tc.after, 2)
		if err != nil {
			t.Fatalf("ClientsPage(%v, %q): %v", tc.tenants,
				tc.after, err)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("ClientsPage(%v, %q) = %v, want %v",
				tc.tenants, tc.after, got, tc.want)
		}
	}
}
