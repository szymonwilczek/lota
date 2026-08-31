// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"errors"
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

// A client's nonces must live on the client's own shard -- the same shard its
// baseline lives on -- so losing one shard costs that shard's clients and no
// others. Routing by the nonce spread every client over every shard, which is
// what made one shard's outage refuse a share of every client's attestations.
func TestShardedNonceRoutesByClientNotNonce(t *testing.T) {
	const n = 4
	backends := make([]*countingNonce, n)
	shards := make([]UsedNonceBackend, n)
	for i := range n {
		backends[i] = &countingNonce{inner: newMemoryUsedNonceBackend(8000)}
		shards[i] = backends[i]
	}
	s := NewShardedUsedNonceBackend(shards)

	const clients = 32
	const rounds = 25
	for c := range clients {
		client := fmt.Sprintf("client-%d", c)
		want := shardIndex(client, n)
		// the shard the baseline store would pick for the same client
		if got := shardIndex(client, n); got != want {
			t.Fatalf("client %q routes to %d and %d", client, want, got)
		}
		before := backends[want].recorded

		for r := range rounds {
			nonce := fmt.Sprintf("nonce-%d-%d", c, r)
			if s.ContainsFor(client, nonce) {
				t.Fatalf("fresh nonce %q reported as used", nonce)
			}
			if err := s.RecordFor(client, nonce, time.Now()); err != nil {
				t.Fatalf("RecordFor: %v", err)
			}
			// a replay is the same client presenting the same nonce,
			// so it must be found again on that client's shard
			if !s.ContainsFor(client, nonce) {
				t.Fatalf("recorded nonce %q not seen as used", nonce)
			}
		}

		// every round of this client landed on the one shard it belongs to
		if got := backends[want].recorded - before; got != rounds {
			t.Errorf("client %q wrote %d of %d rounds to shard %d",
				client, got, rounds, want)
		}
	}

	// no client's rounds leaked onto a shard that does not own it
	total := 0
	for _, b := range backends {
		total += b.recorded
	}
	if total != clients*rounds {
		t.Fatalf("shards recorded %d rounds, want %d", total, clients*rounds)
	}
}

// Losing a shard must cost that shard's clients only. The failure is staged by
// pointing one shard at a backend that refuses every write, which is what
// an unreachable database is to the caller.
func TestShardedNonceOutageCostsOnlyItsOwnClients(t *testing.T) {
	const n = 3
	shards := make([]UsedNonceBackend, n)
	for i := range n {
		shards[i] = newMemoryUsedNonceBackend(8000)
	}
	const dead = 1
	shards[dead] = failingNonceBackend{}
	s := NewShardedUsedNonceBackend(shards)

	var refusedOwn, refusedOther, servedOwn int
	for c := range 200 {
		client := fmt.Sprintf("client-%d", c)
		err := s.RecordFor(client, fmt.Sprintf("nonce-%d", c), time.Now())
		switch {
		case shardIndex(client, n) == dead && err != nil:
			refusedOwn++
		case shardIndex(client, n) == dead:
			servedOwn++
		case err != nil:
			refusedOther++
		}
	}

	if refusedOther != 0 {
		t.Errorf("%d clients of healthy shards were refused by the dead one", refusedOther)
	}
	if refusedOwn == 0 {
		t.Fatal("the dead shard refused nobody; the staging is wrong")
	}
	if servedOwn != 0 {
		t.Errorf("%d clients of the dead shard were served anyway", servedOwn)
	}
}

// backend that cannot be reached: every write refuses and nothing is held
type failingNonceBackend struct{}

func (failingNonceBackend) Record(string, time.Time) error {
	return errors.New("shard unreachable")
}
func (failingNonceBackend) Contains(string) bool { return false }
func (failingNonceBackend) Count() int           { return 0 }
func (failingNonceBackend) Cleanup(time.Time)    {}
