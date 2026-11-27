// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Sharded baseline store
//
// A client-scoped call goes to the one shard that owns the client, so its
// transaction stays inside one database. Client listing, statistics and the
// LFA review queue fan out to every shard.

package verify

import (
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// baselineShard is every capability a baseline shard must have.
type baselineShard interface {
	BaselineStorer
	BootBaselineStorer
	BootBaselineReader
	AtomicBaselineStorer
	AgentHashStorer
	TenantStorer
	ReanchorStorer
	AgentHashRepinStorer
	PCR14RepinStorer
	BootEntryRepinStorer
	KernelHashRecorder
	MachineKeysRecorder
	ForcedReanchorStorer
}

// ShardedBaselineStore partitions baseline state across shards.
type ShardedBaselineStore struct {
	shards []baselineShard
}

var (
	_ baselineShard = (*BaselineStore)(nil)
	_ baselineShard = (*ShardedBaselineStore)(nil)
)

// NewShardedBaselineStore returns a store over shards.
// It panics on an empty set or a shard that is not a baselineShard.
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

func (s *ShardedBaselineStore) GetBaseline(clientID string,
) (*ClientBaseline, error) {
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

// ListClientsAfter asks every shard for a page and merges them; a client
// lives on one shard, so the merge has no duplicates.
func (s *ShardedBaselineStore) ListClientsAfter(tenants []string,
	after string, limit int,
) ([]string, error) {
	pages := make([][]string, len(s.shards))
	for i, sh := range s.shards {
		page, err := sh.ListClientsAfter(tenants, after, limit)
		if err != nil {
			return nil, err
		}
		pages[i] = page
	}

	merged := []string{}
	for len(merged) < limit {
		best := -1
		for i, p := range pages {
			if len(p) > 0 && (best < 0 || p[0] < pages[best][0]) {
				best = i
			}
		}
		if best < 0 {
			break
		}
		merged = append(merged, pages[best][0])
		pages[best] = pages[best][1:]
	}
	return merged, nil
}

// CountClients sums the shards; a client lives on one shard.
func (s *ShardedBaselineStore) CountClients(tenants []string) (int, error) {
	total := 0
	for _, sh := range s.shards {
		n, err := sh.CountClients(tenants)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
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

func (s *ShardedBaselineStore) GetBootBaseline(clientID string,
) (*BootBaseline, error) {
	return s.shardFor(clientID).GetBootBaseline(clientID)
}

func (s *ShardedBaselineStore) CheckAndUpdateAttestation(
	clientID, tenant string,
	pcr14, agentHash [types.HashSize]byte, boot *BootBaseline, consent bool,
) AttestationOutcome {
	return s.shardFor(clientID).CheckAndUpdateAttestation(clientID, tenant,
		pcr14, agentHash, boot, consent)
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

func (s *ShardedBaselineStore) GetAgentHashRepinState(clientID string) AgentHashRepinState {
	return s.shardFor(clientID).GetAgentHashRepinState(clientID)
}

func (s *ShardedBaselineStore) RepinPCR14(clientID string,
	from, to [types.HashSize]byte, eventLog []byte, now time.Time,
) error {
	return s.shardFor(clientID).RepinPCR14(clientID, from, to, eventLog, now)
}

func (s *ShardedBaselineStore) RepinBootEntries(clientID string,
	from BootBaseline, pcr1 [types.HashSize]byte, eventLog []byte,
	now time.Time,
) error {
	return s.shardFor(clientID).RepinBootEntries(clientID, from, pcr1,
		eventLog, now)
}

func (s *ShardedBaselineStore) ArchiveAndRepinAgentHash(clientID string,
	agentHash, pcr14 [types.HashSize]byte, now time.Time,
) error {
	return s.shardFor(clientID).ArchiveAndRepinAgentHash(clientID, agentHash, pcr14, now)
}

func (s *ShardedBaselineStore) RecordMachineKeys(clientID string, keys []byte) ([]byte, error) {
	return s.shardFor(clientID).RecordMachineKeys(clientID, keys)
}

func (s *ShardedBaselineStore) GetMachineKeys(clientID string) []byte {
	return s.shardFor(clientID).GetMachineKeys(clientID)
}

func (s *ShardedBaselineStore) RecordKernelHash(clientID string,
	kernelHash [types.HashSize]byte,
) (prev [types.HashSize]byte, had bool, err error) {
	return s.shardFor(clientID).RecordKernelHash(clientID, kernelHash)
}

func (s *ShardedBaselineStore) RecordBootEvidence(clientID string, eventLog []byte,
	esrtVersion uint32, esrtPresent bool,
) error {
	return s.shardFor(clientID).RecordBootEvidence(clientID, eventLog, esrtVersion, esrtPresent)
}

func (s *ShardedBaselineStore) ListLFAReviewPending() ([]string, error) {
	var all []string
	for _, sh := range s.shards {
		ids, err := sh.ListLFAReviewPending()
		if err != nil {
			return nil, err
		}
		all = append(all, ids...)
	}
	return all, nil
}

func (s *ShardedBaselineStore) AcknowledgeLFAReview(clientID string) error {
	return s.shardFor(clientID).AcknowledgeLFAReview(clientID)
}

func (s *ShardedBaselineStore) MarkForcedReanchor(clientID string) error {
	return s.shardFor(clientID).MarkForcedReanchor(clientID)
}

func (s *ShardedBaselineStore) HasForcedReanchor(clientID string,
) (bool, error) {
	return s.shardFor(clientID).HasForcedReanchor(clientID)
}

func (s *ShardedBaselineStore) TakeForcedReanchor(clientID string,
) (bool, error) {
	return s.shardFor(clientID).TakeForcedReanchor(clientID)
}
