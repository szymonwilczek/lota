// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"fmt"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

func newShardedMemoryBaselines(n int) (*ShardedBaselineStore, []*BaselineStore) {
	raw := make([]*BaselineStore, n)
	shards := make([]BaselineStorer, n)
	for i := range n {
		raw[i] = NewBaselineStore()
		shards[i] = raw[i]
	}
	return NewShardedBaselineStore(shards), raw
}

func pcrOf(i int) [types.HashSize]byte {
	var p [types.HashSize]byte
	p[0] = byte(i)
	p[1] = byte(i >> 8)
	return p
}

// In-memory reference store must satisfy the full shard capability set,
// otherwise sharding would silently disable a feature.
func TestBaselineStoreSatisfiesShardCapabilities(t *testing.T) {
	if _, ok := any(NewBaselineStore()).(baselineShard); !ok {
		t.Fatal("in-memory BaselineStore does not provide the full baselineShard set")
	}
}

// Every client lands on exactly one shard, fleet is the union of the shards,
// and client's baseline is retrievable through the router.
func TestShardedBaselineDistributionAndRouting(t *testing.T) {
	const (
		n       = 4
		clients = 4000
	)
	s, raw := newShardedMemoryBaselines(n)

	for i := range clients {
		id := fmt.Sprintf("client-%06d", i)
		if res, _ := s.CheckAndUpdate(id, pcrOf(i)); res != TOFUFirstUse {
			t.Fatalf("first CheckAndUpdate(%s) = %v, want TOFUFirstUse", id, res)
		}
	}

	// union across shards equals the fleet, with no duplication
	if got := len(s.ListClients()); got != clients {
		t.Fatalf("ListClients = %d, want %d", got, clients)
	}
	if s.Stats().TotalClients != clients {
		t.Fatalf("Stats.TotalClients = %d, want %d", s.Stats().TotalClients, clients)
	}

	// each shard owns a disjoint, non-empty subset,
	// and client is only on the shard the hash selects
	total := 0
	for i, r := range raw {
		owned := r.ListClients()
		if len(owned) == 0 {
			t.Errorf("shard %d owns no clients; distribution collapsed", i)
		}
		total += len(owned)
		for _, id := range owned {
			if want := shardIndex(id, n); want != i {
				t.Fatalf("client %s stored on shard %d, hash says %d", id, i, want)
			}
		}
	}
	if total != clients {
		t.Fatalf("shards own %d clients in total, want %d", total, clients)
	}

	// specific client's baseline is retrievable and matches its PCR
	id := "client-000042"
	b := s.GetBaseline(id)
	if b == nil {
		t.Fatalf("GetBaseline(%s) = nil", id)
	}
	if b.PCR14 != pcrOf(42) {
		t.Fatalf("GetBaseline(%s) PCR14 mismatch", id)
	}
}

// Tenant stamping and clearing must route to the owning shard.
func TestShardedBaselineTenantAndClear(t *testing.T) {
	s, _ := newShardedMemoryBaselines(3)
	id := "tenant-client"
	s.CheckAndUpdate(id, pcrOf(7))
	if s.GetBaseline(id) == nil {
		t.Fatal("baseline not established")
	}

	if err := s.SetClientTenant(id, "acme"); err != nil {
		t.Fatalf("SetClientTenant: %v", err)
	}
	got, err := s.ClientTenant(id)
	if err != nil {
		t.Fatalf("ClientTenant: %v", err)
	}
	if got != "acme" {
		t.Fatalf("ClientTenant = %q, want acme", got)
	}

	if err := s.ClearBaseline(id); err != nil {
		t.Fatalf("ClearBaseline: %v", err)
	}
	if s.GetBaseline(id) != nil {
		t.Fatal("baseline survived ClearBaseline")
	}
}

// same client always routes to the same shard, so its atomic baseline decision
// stays on one database: re-attestation is not TOFUNew
func TestShardedBaselineStableRouting(t *testing.T) {
	s, _ := newShardedMemoryBaselines(8)
	id := "stable-client"
	if res, _ := s.CheckAndUpdate(id, pcrOf(1)); res != TOFUFirstUse {
		t.Fatalf("first = %v, want TOFUFirstUse", res)
	}
	if res, _ := s.CheckAndUpdate(id, pcrOf(1)); res != TOFUMatch {
		t.Fatalf("second = %v, want TOFUMatch (routing not stable)", res)
	}
}
