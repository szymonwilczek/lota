// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Store sharding
//
// Postgres backend is bounded by per-database WAL fsync throughput, shared by every
// verifier instance on that database. To scale the database tier past one host the fleet
// is partitioned across N independent databases: each store operation is routed to shard
// by stable hash of its own key, so given client's baseline, given nonce, and given
// session token always land on the same shard on every instance.
// Independent databases commit in parallel, so aggregate durable write throughput scales
// with the number of shards (on independent storage).
//
// Hash is FNV-1a, which is deterministic and process-independent:
// Two verifier instances pointed at the same shard set route identically,
// so session token issued by one instance validates on another.
// Routing adds only a hash to each call - it introduces no cross-shard transaction
// and no new failure mode beyond single backend's.

package verify

import (
	"hash/fnv"
	"time"
)

// maxPositiveInt32 clears the hash's sign bit before it becomes an int.
// Half the FNV-1a range has the high bit set, so a bare int(h.Sum32()) is
// negative wherever int is 32 bits, and the router would index a slice with it.
const maxPositiveInt32 = 0x7fffffff

// shardIndex maps key to one of n shards with FNV-1a.
// It is stable across processes and architectures, which is what lets separate
// verifier instances agree on key's shard.
func shardIndex(key string, n int) int {
	if n <= 1 {
		return 0
	}
	h := fnv.New32a()
	// write on hash.Hash never returns error
	_, _ = h.Write([]byte(key))
	return int(h.Sum32()&maxPositiveInt32) % n
}

// shardIndexBytes is shardIndex for fixed-size binary key (session token),
// avoiding string allocation on the hot path
func shardIndexBytes(key []byte, n int) int {
	if n <= 1 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write(key)
	return int(h.Sum32()&maxPositiveInt32) % n
}

// ShardedUsedNonceBackend routes each nonce to shard by the nonce key.
// Replay protection is preserved because given nonce always maps to the same
// shard, so its Record and Contains hit the same backend.
type ShardedUsedNonceBackend struct {
	shards []UsedNonceBackend
}

// NewShardedUsedNonceBackend partitions used-nonce state across shards.
// It panics on empty shard set: verifier with no nonce backend cannot enforce
// replay protection and must fail at construction, not silently.
func NewShardedUsedNonceBackend(shards []UsedNonceBackend) *ShardedUsedNonceBackend {
	if len(shards) == 0 {
		panic("verify: ShardedUsedNonceBackend requires at least one shard")
	}
	return &ShardedUsedNonceBackend{shards: shards}
}

func (s *ShardedUsedNonceBackend) Record(nonceKey string, usedAt time.Time) error {
	return s.shards[shardIndex(nonceKey, len(s.shards))].Record(nonceKey, usedAt)
}

func (s *ShardedUsedNonceBackend) Contains(nonceKey string) bool {
	return s.shards[shardIndex(nonceKey, len(s.shards))].Contains(nonceKey)
}

func (s *ShardedUsedNonceBackend) Count() int {
	total := 0
	for _, sh := range s.shards {
		total += sh.Count()
	}
	return total
}

func (s *ShardedUsedNonceBackend) Cleanup(olderThan time.Time) {
	for _, sh := range s.shards {
		sh.Cleanup(olderThan)
	}
}

// ShardedSessionTokenStore routes each token to a shard by the token bytes.
// Because the routing is deterministic and process-independent, token remembered
// on one verifier instance validates on any instance pointed at the same shard set.
type ShardedSessionTokenStore struct {
	shards []SessionTokenStore
}

// NewShardedSessionTokenStore partitions session-token state across shards.
func NewShardedSessionTokenStore(shards []SessionTokenStore) *ShardedSessionTokenStore {
	if len(shards) == 0 {
		panic("verify: ShardedSessionTokenStore requires at least one shard")
	}
	return &ShardedSessionTokenStore{shards: shards}
}

func (s *ShardedSessionTokenStore) Remember(token [32]byte, rec sessionTokenRecord) {
	s.shards[shardIndexBytes(token[:], len(s.shards))].Remember(token, rec)
}

func (s *ShardedSessionTokenStore) Validate(token [32]byte, consume bool, now uint64) SessionTokenStatus {
	return s.shards[shardIndexBytes(token[:], len(s.shards))].Validate(token, consume, now)
}
