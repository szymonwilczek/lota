// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Sharded baseline store
//
// ShardedBaselineStore partitions per-client baseline state across N independent
// baseline stores, routing every single-client operation to the shard that owns
// the client (by a stable hash of the client ID) and fanning out the fleet-wide
// reads (client listing, statistics, the LFA review queue).
// It reproduces the full BaselineStorer capability set -- including the atomic
// attestation transaction, boot-PCR pinning, tenant stamping and self-service re-anchor
// -- so sharded deployment loses no verifier feature.
//
// Client's baseline always lives on exactly one shard, so the atomic read-modify-write
// guarantees of the underlying store are preserved unchanged:
// sharding never splits one client's decision across databases.

package verify

import (
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// baselineShard is the full capability set shardable baseline store must provide.
// Production Postgres baseline store satisfies it; requiring it at construction
// means every optional interface the verifier probes
// (atomic attestation, boot PCRs, tenant, re-anchor)
// can be routed to the owning shard, so no feature silently degrades under sharding.
type baselineShard interface {
	BaselineStorer
	BootBaselineStorer
	BootBaselineReader
	AtomicBaselineStorer
	AgentHashStorer
	TenantStorer
	ReanchorStorer
}

// ShardedBaselineStore routes per-client baseline operations across set of baseline shards.
type ShardedBaselineStore struct {
	shards []baselineShard
}

// compile-time proof the sharded store keeps the whole capability set,
// so verifier's interface probes succeed exactly as on single store.
var _ baselineShard = (*ShardedBaselineStore)(nil)

// NewShardedBaselineStore partitions baseline state across shards.
// Every shard must provide the full baseline capability set;
// it panics otherwise, because shard missing capability would silently disable
// that feature for the clients it owns.
func NewShardedBaselineStore(shards []BaselineStorer) *ShardedBaselineStore {
	if len(shards) == 0 {
		panic("verify: ShardedBaselineStore requires at least one shard")
	}
	full := make([]baselineShard, len(shards))
	for i, sh := range shards {
		bs, ok := sh.(baselineShard)
		if !ok {
			panic("verify: baseline shard does not provide the full capability set")
		}
		full[i] = bs
	}
	return &ShardedBaselineStore{shards: full}
}

// shardFor returns the shard owning clientID.
func (s *ShardedBaselineStore) shardFor(clientID string) baselineShard {
	return s.shards[shardIndex(clientID, len(s.shards))]
}

func (s *ShardedBaselineStore) CheckAndUpdate(clientID string, pcr14 [types.HashSize]byte) (TOFUResult, *ClientBaseline) {
	return s.shardFor(clientID).CheckAndUpdate(clientID, pcr14)
}

func (s *ShardedBaselineStore) GetBaseline(clientID string) *ClientBaseline {
	return s.shardFor(clientID).GetBaseline(clientID)
}

func (s *ShardedBaselineStore) ClearBaseline(clientID string) error {
	return s.shardFor(clientID).ClearBaseline(clientID)
}

func (s *ShardedBaselineStore) ListClients() []string {
	var all []string
	for _, sh := range s.shards {
		all = append(all, sh.ListClients()...)
	}
	return all
}

func (s *ShardedBaselineStore) Stats() BaselineStats {
	var agg BaselineStats
	for _, sh := range s.shards {
		st := sh.Stats()
		agg.TotalClients += st.TotalClients
		if !st.OldestBaseline.IsZero() &&
			(agg.OldestBaseline.IsZero() || st.OldestBaseline.Before(agg.OldestBaseline)) {
			agg.OldestBaseline = st.OldestBaseline
		}
		if st.NewestBaseline.After(agg.NewestBaseline) {
			agg.NewestBaseline = st.NewestBaseline
		}
	}
	return agg
}

func (s *ShardedBaselineStore) CheckAndUpdateBootPCRs(clientID string, boot BootBaseline) (TOFUResult, *BootBaseline) {
	return s.shardFor(clientID).CheckAndUpdateBootPCRs(clientID, boot)
}

func (s *ShardedBaselineStore) GetBootBaseline(clientID string) *BootBaseline {
	return s.shardFor(clientID).GetBootBaseline(clientID)
}

func (s *ShardedBaselineStore) CheckAndUpdateAttestation(clientID string,
	pcr14, agentHash [types.HashSize]byte, boot *BootBaseline,
) AttestationOutcome {
	return s.shardFor(clientID).CheckAndUpdateAttestation(clientID, pcr14, agentHash, boot)
}

func (s *ShardedBaselineStore) CheckAndUpdateAgentHash(clientID string,
	currentPCR14, agentHash [types.HashSize]byte,
) (TOFUResult, *ClientBaseline) {
	return s.shardFor(clientID).CheckAndUpdateAgentHash(clientID, currentPCR14, agentHash)
}

func (s *ShardedBaselineStore) SetClientTenant(clientID, tenant string) error {
	return s.shardFor(clientID).SetClientTenant(clientID, tenant)
}

func (s *ShardedBaselineStore) ClientTenant(clientID string) (string, error) {
	return s.shardFor(clientID).ClientTenant(clientID)
}

func (s *ShardedBaselineStore) GetReanchorState(clientID string) ReanchorState {
	return s.shardFor(clientID).GetReanchorState(clientID)
}

func (s *ShardedBaselineStore) ArchiveAndReanchor(clientID string, boot BootBaseline,
	eventLog []byte, esrtVersion uint32, esrtCapable, lfa bool, reason string, now time.Time,
) error {
	return s.shardFor(clientID).ArchiveAndReanchor(clientID, boot, eventLog,
		esrtVersion, esrtCapable, lfa, reason, now)
}

func (s *ShardedBaselineStore) RecordBootEvidence(clientID string, eventLog []byte,
	esrtVersion uint32, esrtPresent bool,
) error {
	return s.shardFor(clientID).RecordBootEvidence(clientID, eventLog, esrtVersion, esrtPresent)
}

func (s *ShardedBaselineStore) ListLFAReviewPending() []string {
	var all []string
	for _, sh := range s.shards {
		all = append(all, sh.ListLFAReviewPending()...)
	}
	return all
}

func (s *ShardedBaselineStore) AcknowledgeLFAReview(clientID string) error {
	return s.shardFor(clientID).AcknowledgeLFAReview(clientID)
}
