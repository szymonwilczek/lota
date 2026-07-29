// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"fmt"
	"testing"
	"time"
)

// shardIndex must be deterministic and process-independent:
// the same key and shard count always yield the same shard.
func TestShardIndexDeterministic(t *testing.T) {
	for _, n := range []int{1, 2, 4, 16} {
		for i := range 1000 {
			key := fmt.Sprintf("client-%d", i)
			a := shardIndex(key, n)
			b := shardIndex(key, n)
			if a != b {
				t.Fatalf("shardIndex(%q,%d) not stable: %d != %d", key, n, a, b)
			}
			if a < 0 || a >= n {
				t.Fatalf("shardIndex(%q,%d) = %d out of range", key, n, a)
			}
		}
	}
	// n<=1 always routes to shard 0
	if shardIndex("anything", 1) != 0 || shardIndex("anything", 0) != 0 {
		t.Fatal("single/zero shard must route to 0")
	}
}

// reduction must stay in unsigned space.
// Half the FNV-1a range has the high bit set, so reducing after a signed
// conversion yields a negative index wherever int is 32 bits, and the router
// indexes a slice with it
func TestShardIndexNeverNegative(t *testing.T) {
	for _, n := range []int{2, 3, 4, 8, 16} {
		for i := range 5000 {
			key := fmt.Sprintf("loadgen-%06d", i)
			if idx := shardIndex(key, n); idx < 0 || idx >= n {
				t.Fatalf("shardIndex(%q,%d) = %d out of [0,%d)", key, n, idx, n)
			}
			var tok [32]byte
			tok[0], tok[1], tok[2] = byte(i), byte(i>>8), byte(i>>16)
			if idx := shardIndexBytes(tok[:], n); idx < 0 || idx >= n {
				t.Fatalf("shardIndexBytes(%d,%d) = %d out of [0,%d)", i, n, idx, n)
			}
		}
	}
}

// Over many keys the router must spread load roughly evenly,
// or shard becomes hot spot and the fan-out does not scale.
func TestShardIndexEvenDistribution(t *testing.T) {
	const (
		n    = 8
		keys = 200000
	)
	counts := make([]int, n)
	for i := range keys {
		counts[shardIndex(fmt.Sprintf("client-%08d", i), n)]++
	}
	mean := float64(keys) / float64(n)
	for i, c := range counts {
		dev := (float64(c) - mean) / mean
		if dev < -0.05 || dev > 0.05 {
			t.Errorf("shard %d holds %d keys, %.2f%% off the %.0f mean (>5%%)",
				i, c, dev*100, mean)
		}
	}
}

// countingNonce records which shard each call reached
// so the test can assert routing isolation.
type countingNonce struct {
	inner    UsedNonceBackend
	recorded int
}

func (c *countingNonce) Record(k string, t time.Time) error {
	c.recorded++
	return c.inner.Record(k, t)
}
func (c *countingNonce) Contains(k string) bool { return c.inner.Contains(k) }
func (c *countingNonce) Count() int             { return c.inner.Count() }
func (c *countingNonce) Cleanup(o time.Time)    { c.inner.Cleanup(o) }

// nonce recorded on its shard must be seen only there,
// and replay detection (Contains) must route to the same shard.
func TestShardedNonceRoutingAndReplay(t *testing.T) {
	const n = 4
	backends := make([]*countingNonce, n)
	shards := make([]UsedNonceBackend, n)
	for i := range n {
		backends[i] = &countingNonce{inner: newMemoryUsedNonceBackend(8000)}
		shards[i] = backends[i]
	}
	s := NewShardedUsedNonceBackend(shards)

	const keys = 4000
	for i := range keys {
		key := fmt.Sprintf("nonce-%d", i)
		if s.Contains(key) {
			t.Fatalf("fresh nonce %q reported as used", key)
		}
		if err := s.Record(key, time.Now()); err != nil {
			t.Fatalf("Record: %v", err)
		}
		// replay: the same key must now be seen used,
		// proving Contains routed to the shard that Record wrote
		if !s.Contains(key) {
			t.Fatalf("recorded nonce %q not seen as used (routing mismatch)", key)
		}
	}

	if s.Count() != keys {
		t.Fatalf("aggregate Count = %d, want %d", s.Count(), keys)
	}
	// exactly one shard recorded each key;
	// the total matches and no shard took everything
	total := 0
	for i, b := range backends {
		if b.recorded == 0 {
			t.Errorf("shard %d recorded nothing; distribution collapsed", i)
		}
		total += b.recorded
	}
	if total != keys {
		t.Fatalf("shards recorded %d keys in total, want %d", total, keys)
	}
}

// Token remembered through the sharded store must validate through the same
// sharded store (and, because routing is process-independent, through second
// independent sharded store over equivalent shard set) -- the cross-instance
// failover property under sharding.
func TestShardedSessionCrossInstance(t *testing.T) {
	const n = 4
	// model SHARED database tier:
	// two verifier instances point at the same shard backends,
	// as they would at the same N Postgres databases
	shared := make([]SessionTokenStore, n)
	for i := range n {
		shared[i] = newMemorySessionTokenStore()
	}
	instanceA := NewShardedSessionTokenStore(shared)
	instanceB := NewShardedSessionTokenStore(shared)

	now := unixTimestamp(time.Now())
	for i := range 1000 {
		var tok [32]byte
		tok[0] = byte(i)
		tok[1] = byte(i >> 8)
		tok[31] = 0xFF
		rec := sessionTokenRecord{
			ClientID:   fmt.Sprintf("client-%d", i),
			ValidUntil: unixTimestamp(time.Now().Add(time.Hour)),
		}
		instanceA.Remember(tok, rec)
		st := instanceB.Validate(tok, false, now)
		if !st.Exists || st.ClientID != rec.ClientID {
			t.Fatalf("token %d issued on A did not validate on B: %+v", i, st)
		}
	}
}
