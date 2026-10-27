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
// So each database carries its own random identity, and every shard pins
// the fingerprint of the ordered identity list.
// Verifier whose shard list does not reproduce the pinned fingerprint refuses
// to start.
//
// The pin lives in every shard: reordering the list moves the first database,
// so a pin held there is compared against a database that has none, the insert
// writes a fresh one, and the read-back matches what was just written.
// A reordering is exactly what this file exists to refuse, so it cannot be the
// thing that decides where the answer is read from.

package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
)

// ErrShardSetMismatch is returned when the shard list does not reproduce
// the fingerprint the shard databases are pinned to.
var ErrShardSetMismatch = errors.New("shard set does not match the one these databases are pinned to")

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

// ReadShardIdentity returns the identity a database carries, minting none.
func ReadShardIdentity(ctx context.Context, db *sql.DB) (string, error) {
	var id string
	err := db.QueryRowContext(ctx,
		"SELECT id FROM shard_identity WHERE singleton").Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("database carries no shard identity: " +
			"a verifier on the primary mints it, so start one there first")
	}
	if err != nil {
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

// AssertShardSet pins the shard list on first use and refuses later run whose
// list differs. The pin is read from and written to every shard, and all of them
// must agree: a shard that already carries a pin naming another set refuses the
// run, and a shard with no pin is given this one only once every shard that has
// an opinion has agreed with it. Positions are therefore never trusted to decide
// the answer.
//
// Changing the shard set is a fleet-wide re-routing, not a rolling capacity step,
// so it is deliberately not silent: an operator who really means it clears the
// pin (DELETE FROM shard_set) on every shard after migrating or re-enrolling.
func AssertShardSet(ctx context.Context, shards []*sql.DB, ids []string) error {
	return assertShardSet(ctx, shards, ids, false)
}

// CheckShardSet is AssertShardSet without writes: existing pins must agree,
// unpinned shards are left to the attesting side.
func CheckShardSet(ctx context.Context, shards []*sql.DB, ids []string) error {
	return assertShardSet(ctx, shards, ids, true)
}

func assertShardSet(ctx context.Context, shards []*sql.DB, ids []string, readOnly bool) error {
	if len(ids) == 0 {
		return errors.New("shard set is empty")
	}
	if len(shards) != len(ids) {
		return fmt.Errorf("shard set check needs one identity per database: "+
			"%d database(s), %d identity(ies)", len(shards), len(ids))
	}
	if dup, ok := firstDuplicate(ids); ok {
		return fmt.Errorf("shard %s is listed more than once: the same database "+
			"cannot back two shards, routing would collapse onto it", dup)
	}

	want := ShardSetFingerprint(ids)

	// Read every shard before writing any of them. A shard that disagrees must
	// stop the run
	unpinned := make([]int, 0, len(shards))
	for i, db := range shards {
		var (
			got   string
			count int
		)
		err := db.QueryRowContext(ctx,
			"SELECT fingerprint, shard_count FROM shard_set WHERE singleton").Scan(&got, &count)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			unpinned = append(unpinned, i)
			continue
		case err != nil:
			return fmt.Errorf("read pinned shard set from shard %d: %w", i, err)
		}
		if got != want {
			return fmt.Errorf("%w: %s; check every instance lists the same databases "+
				"in the same order, and that this database belongs to this fleet",
				ErrShardSetMismatch, describeMismatch(i, len(ids), count))
		}
	}

	// read-only: existing pins agree; unpinned ones are not ours to write
	if readOnly {
		if len(unpinned) > 0 {
			slog.Warn("shard set is not pinned on every database",
				"unpinned_shards", len(unpinned),
				"note", "a verifier on the primary pins it; this instance reads and pins nothing")
		}
		return nil
	}

	// Every shard that had an opinion shares it, so the ones that had none
	// can be given the set. ON CONFLICT DO NOTHING keeps a concurrent starter's
	// identical pin, and a racing writer that pinned something else is caught
	// by the read-back below.
	for _, i := range unpinned {
		if _, err := shards[i].ExecContext(ctx,
			`INSERT INTO shard_set (singleton, fingerprint, shard_count) VALUES (TRUE, $1, $2)
			 ON CONFLICT (singleton) DO NOTHING`, want, len(ids)); err != nil {
			return fmt.Errorf("pin shard set on shard %d: %w", i, err)
		}

		var (
			got   string
			count int
		)
		if err := shards[i].QueryRowContext(ctx,
			"SELECT fingerprint, shard_count FROM shard_set WHERE singleton").Scan(&got, &count); err != nil {
			return fmt.Errorf("read pinned shard set from shard %d: %w", i, err)
		}
		if got != want {
			return fmt.Errorf("%w: %s; another instance pinned a different set while "+
				"this one was starting",
				ErrShardSetMismatch, describeMismatch(i, len(ids), count))
		}
	}
	return nil
}

// describeMismatch says which of the two ways a list can diverge happened.
func describeMismatch(shard, given, pinned int) string {
	if given != pinned {
		return fmt.Sprintf("this instance was given %d shard(s), shard %d is pinned to %d",
			given, shard, pinned)
	}
	return fmt.Sprintf("this instance was given %d shard(s), the same number shard %d is "+
		"pinned to, so the databases themselves or their order differ",
		given, shard)
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
