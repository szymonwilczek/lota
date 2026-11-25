// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Store sharding
//
// A client-scoped call goes to the shard FNV-1a of its client picks,
// so a client's baseline and used nonces share a shard, and instances
// given the same shard set route alike. No transaction spans shards.

package verify

import (
	"hash/fnv"
	"time"
)

// maxPositiveInt32 clears the hash's sign bit before it becomes an int.
// Half the FNV-1a range has the high bit set, so a bare int(h.Sum32()) is
// negative wherever int is 32 bits, and the router would index a slice with it.
const maxPositiveInt32 = 0x7fffffff

// shardIndex maps key to one of n shards with FNV-1a, alike in every process
// and on every architecture.
func shardIndex(key string, n int) int {
	if n <= 1 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32()&maxPositiveInt32) % n
}

// ShardedUsedNonceBackend routes RecordFor and ContainsFor by the client the
// nonce was issued to, see RoutedUsedNonceBackend.
//
// Record and Contains route by the nonce, for callers with no client in hand.
// The nonce store picks one pair at construction and never mixes them.
type ShardedUsedNonceBackend struct {
	shards []UsedNonceBackend
}

var _ RoutedUsedNonceBackend = (*ShardedUsedNonceBackend)(nil)

// NewShardedUsedNonceBackend partitions used-nonce state across shards.
// It panics on an empty shard set.
func NewShardedUsedNonceBackend(shards []UsedNonceBackend) *ShardedUsedNonceBackend {
	if len(shards) == 0 {
		panic("verify: ShardedUsedNonceBackend requires at least one shard")
	}
	return &ShardedUsedNonceBackend{shards: shards}
}

func (s *ShardedUsedNonceBackend) Record(nonceKey string, usedAt time.Time) error {
	return s.shards[shardIndex(nonceKey, len(s.shards))].Record(nonceKey, usedAt)
}

func (s *ShardedUsedNonceBackend) Contains(nonceKey string) (bool, error) {
	return s.shards[shardIndex(nonceKey, len(s.shards))].Contains(nonceKey)
}

// RecordFor stores the nonce in the client's shard.
func (s *ShardedUsedNonceBackend) RecordFor(routeKey, nonceKey string, usedAt time.Time) error {
	return s.shards[shardIndex(routeKey, len(s.shards))].Record(nonceKey, usedAt)
}

// ContainsFor looks the nonce up in the client's shard.
func (s *ShardedUsedNonceBackend) ContainsFor(routeKey, nonceKey string) (bool, error) {
	return s.shards[shardIndex(routeKey, len(s.shards))].Contains(nonceKey)
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
