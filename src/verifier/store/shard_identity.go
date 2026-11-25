// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Shard set identity
//
// A shard is picked by its position in the shard list. Each database
// carries a random identity, and every shard pins the fingerprint of the
// ordered identity list; AssertShardSet refuses a list that does not
// reproduce it.

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

// ShardIdentity returns the database's identity, minting a random one on
// first use.
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
// Length prefixes give every list a distinct encoding.
func ShardSetFingerprint(ids []string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d:", len(ids))
	for _, id := range ids {
		fmt.Fprintf(h, "%d:%s", len(id), id)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// AssertShardSet refuses ids when any shard is pinned to another set, and
// otherwise pins the set on every unpinned shard. It reads every shard
// before writing any. A changed set pins only after DELETE FROM shard_set
// on every shard pinned to another set.
func AssertShardSet(ctx context.Context, shards []*sql.DB, ids []string) error {
	return assertShardSet(ctx, shards, ids, false)
}

// CheckShardSet is AssertShardSet without writes: existing pins must agree
// and unpinned shards are only logged.
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

	if readOnly {
		if len(unpinned) > 0 {
			slog.Warn("shard set is not pinned on every database",
				"unpinned_shards", len(unpinned),
				"note", "a verifier on the primary pins it; this instance reads and pins nothing")
		}
		return nil
	}

	// ON CONFLICT keeps a concurrent starter's pin; the read-back
	// catches one naming another set
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
