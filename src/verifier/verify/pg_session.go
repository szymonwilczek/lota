// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - PostgreSQL Session Token Store
//
// Shared SessionTokenStore over the session_tokens table.
//
// With this backend a token issued by one verifier instance validates on
// every instance, so the validation API can sit behind a load balancer.
//
// Consume flips the token's consumed flag atomically
// 	(UPDATE ... WHERE consumed = FALSE),
// so a single-use token is consumed exactly once across the whole fleet.
//
// Status semantics match the in-memory store exactly so the validation API
// contract does not change: an expired token reports Exists=false,
// and Consumed reflects the post-call state.

package verify

import (
	"database/sql"
	"log/slog"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// PostgresSessionTokenStore implements SessionTokenStore against a shared
// Postgres database
type PostgresSessionTokenStore struct {
	db *sql.DB
}

// NewPostgresSessionTokenStore creates a session token store backed by
// the given Postgres database
func NewPostgresSessionTokenStore(db *sql.DB) *PostgresSessionTokenStore {
	return &PostgresSessionTokenStore{db: db}
}

func (s *PostgresSessionTokenStore) Remember(token [32]byte, rec sessionTokenRecord) {
	// Upsert the freshly issued token
	// Token hash collision would mean the same HMAC tag for different claims,
	// which deriveSessionToken makes infeasible;
	// ON CONFLICT keeps Remember idempotent regardless
	if _, err := s.db.Exec(`
		INSERT INTO session_tokens
			(token_hash, client_id, hardware_id, valid_until, result_code, flags, pcr_mask, consumed)
		VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE)
		ON CONFLICT (token_hash) DO UPDATE SET
			client_id   = EXCLUDED.client_id,
			hardware_id = EXCLUDED.hardware_id,
			valid_until = EXCLUDED.valid_until,
			result_code = EXCLUDED.result_code,
			flags       = EXCLUDED.flags,
			pcr_mask    = EXCLUDED.pcr_mask,
			consumed    = FALSE`,
		token[:], rec.ClientID, rec.HardwareID[:],
		int64(rec.ValidUntil), int64(rec.ResultCode), int64(rec.Flags), int64(rec.PCRMask),
	); err != nil {
		slog.Error("session token remember failed", "client_id", rec.ClientID, "error", err)
		return
	}

	// Opportunistically prune expired tokens.
	// Remember runs once per successful attestation (not on the hot validate path),
	// and the valid_until index keeps the delete bounded to already-dead rows
	if _, err := s.db.Exec(
		"DELETE FROM session_tokens WHERE valid_until > 0 AND valid_until <= $1",
		int64(unixTimestamp(time.Now())),
	); err != nil {
		slog.Warn("session token prune failed", "error", err)
	}
}

func (s *PostgresSessionTokenStore) Validate(token [32]byte, consume bool, now uint64) SessionTokenStatus {
	st := SessionTokenStatus{}

	var (
		clientID   string
		hwid       []byte
		validUntil int64
		resultCode int64
		flags      int64
		pcrMask    int64
		consumed   bool
	)
	err := s.db.QueryRow(`
		SELECT client_id, hardware_id, valid_until, result_code, flags, pcr_mask, consumed
		  FROM session_tokens WHERE token_hash = $1`, token[:]).
		Scan(&clientID, &hwid, &validUntil, &resultCode, &flags, &pcrMask, &consumed)
	if err == sql.ErrNoRows {
		return st
	}
	if err != nil {
		slog.Error("session token lookup failed", "error", err)
		return st
	}

	st.Exists = true
	st.ClientID = clientID
	if len(hwid) == types.HardwareIDSize {
		copy(st.HardwareID[:], hwid)
	}
	st.ValidUntil = uint64(validUntil)
	st.ResultCode = uint32(resultCode)
	st.Flags = uint32(flags)
	st.PCRMask = uint32(pcrMask)
	st.Consumed = consumed
	st.Expired = validUntil > 0 && uint64(validUntil) <= now

	if st.Expired {
		if _, err := s.db.Exec("DELETE FROM session_tokens WHERE token_hash = $1", token[:]); err != nil {
			slog.Warn("expired session token delete failed", "error", err)
		}
		st.Exists = false
		return st
	}

	if consume && !consumed {
		// Atomic single-use flip across all instances:
		// only the UPDATE that observes consumed = FALSE commits the transition.
		// Concurrent consumer on a peer instance affects zero rows; both report
		// the post-call state (consumed) to match the in-memory store
		if _, err := s.db.Exec(
			"UPDATE session_tokens SET consumed = TRUE WHERE token_hash = $1 AND consumed = FALSE",
			token[:],
		); err != nil {
			slog.Error("session token consume failed", "error", err)
			return st
		}
		st.Consumed = true
	}

	return st
}
