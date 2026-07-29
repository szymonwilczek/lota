// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Shard set identity
//
// Shard routing is positional:
// key's shard is FNV-1a(key) mod N over the shard list as given.
// Two instances handed the same databases in different order, or different number
// of them, route the same client to different databases -- which silently breaks
// replay protection (nonce's Record and Contains land on different shards),
// cross-instance session validation, and makes every client look like first
// attestation on the shard that does not hold its baseline.
//
// Nothing about a DSN string can detect that:
// the same database is reachable under different credentials, hostnames or pooler.
// So each database carries its own random identity, and the control database pins
// the fingerprint of the ordered identity list.
// Verifier whose shard list does not reproduce the pinned fingerprint refuses to start
// rather than serve fleet on routing its peers disagree with.

package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

// ErrShardSetMismatch is returned when the shard list does not reproduce
// the fingerprint pinned in the control database.
var ErrShardSetMismatch = errors.New("shard set does not match the one pinned in the control database")

// ShardIdentity returns the database's stable identity,
// minting one on first use.
// The value is meaningless on its own; only equality matters.
func ShardIdentity(ctx context.Context, db *sql.DB) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate shard identity: %w", err)
	}

	// first writer wins; everyone else reads what it stored
	if _, err := db.ExecContext(ctx,
		`INSERT INTO shard_identity (singleton, id) VALUES (TRUE, $1)
		 ON CONFLICT (singleton) DO NOTHING`, hex.EncodeToString(raw[:])); err != nil {
		return "", fmt.Errorf("record shard identity: %w", err)
	}

	var id string
	if err := db.QueryRowContext(ctx,
		"SELECT id FROM shard_identity WHERE singleton").Scan(&id); err != nil {
		return "", fmt.Errorf("read shard identity: %w", err)
	}
	return id, nil
}

// ShardSetFingerprint hashes the ordered shard identities.
// Length prefixes keep the encoding unambiguous, so no reordering
// or regrouping of identities can collide with another list.
func ShardSetFingerprint(ids []string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d:", len(ids))
	for _, id := range ids {
		fmt.Fprintf(h, "%d:%s", len(id), id)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// AssertShardSet pins the shard list on first use and refuses later run whose list differs.
// control is the first shard, which holds the pinned record.
//
// Changing the shard set is a fleet-wide re-routing, not a rolling capacity
// step, so it is deliberately not silent: an operator who really means it
// clears the pin (DELETE FROM shard_set) after migrating or re-enrolling.
func AssertShardSet(ctx context.Context, control *sql.DB, ids []string) error {
	if len(ids) == 0 {
		return errors.New("shard set is empty")
	}
	if dup, ok := firstDuplicate(ids); ok {
		return fmt.Errorf("shard %s is listed more than once: the same database "+
			"cannot back two shards, routing would collapse onto it", dup)
	}

	want := ShardSetFingerprint(ids)
	if _, err := control.ExecContext(ctx,
		`INSERT INTO shard_set (singleton, fingerprint, shard_count) VALUES (TRUE, $1, $2)
		 ON CONFLICT (singleton) DO NOTHING`, want, len(ids)); err != nil {
		return fmt.Errorf("pin shard set: %w", err)
	}

	var (
		got   string
		count int
	)
	if err := control.QueryRowContext(ctx,
		"SELECT fingerprint, shard_count FROM shard_set WHERE singleton").Scan(&got, &count); err != nil {
		return fmt.Errorf("read pinned shard set: %w", err)
	}
	if got != want {
		return fmt.Errorf("%w: this instance was given %d shard(s), the control "+
			"database is pinned to %d; check every instance lists the same "+
			"databases in the same order",
			ErrShardSetMismatch, len(ids), count)
	}
	return nil
}

// firstDuplicate reports an identity that appears more than once.
func firstDuplicate(ids []string) (string, bool) {
	sorted := make([]string, len(ids))
	copy(sorted, ids)
	sort.Strings(sorted)
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return sorted[i], true
		}
	}
	return "", false
}
