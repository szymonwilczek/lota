// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Hardware Ban List

package store

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// BanEntry is an active ban of a hardware identity within one tenant.
type BanEntry struct {
	Tenant     string
	HardwareID [32]byte
	Reason     RevocationReason
	BannedAt   time.Time
	BannedBy   string // administrator identifier
	Note       string // free-form justification
}

// AuditEntry is one operator action in the audit log.
type AuditEntry struct {
	ID        int64
	Timestamp time.Time
	Tenant    string // tenant the action acted within
	Action    string // e.g. "revoke", "ban", "reanchor", "delete_client"
	TargetID  string // clientID or hex-encoded hardwareID
	Reason    string
	Actor     string
	Note      string
}

// ban errors
var (
	ErrAlreadyBanned = errors.New("hardware ID is already banned")
	ErrNotBanned     = errors.New("hardware ID is not banned")
)

// BanStore holds hardware bans, each within one tenant. ListBans alone spans
// tenants.
type BanStore interface {
	// BanHardware returns ErrAlreadyBanned when the ban exists.
	BanHardware(tenant string, hardwareID [32]byte, reason RevocationReason, bannedBy, note string) error

	// IsBanned returns the ban and true, nil and false when there is none,
	// or an error when the store cannot tell.
	IsBanned(tenant string, hardwareID [32]byte) (*BanEntry, bool, error)

	// UnbanHardware records reason and actor in the audit log. It returns
	// ErrNotBanned when there is no ban.
	UnbanHardware(tenant string, hardwareID [32]byte, reason, actor, note string) error

	// ListBans returns the active bans of every tenant.
	ListBans() []BanEntry
}

// PaginatedBanLister is implemented by ban stores that page in SQL.
type PaginatedBanLister interface {
	ListBansPage(limit, offset int) []BanEntry
}

// PaginatedBanListerWithError is PaginatedBanLister with an error.
type PaginatedBanListerWithError interface {
	ListBansPageE(limit, offset int) ([]BanEntry, error)
}

// CursorBanLister pages bans after nextID, an encoded BanCursor.
type CursorBanLister interface {
	ListBansAfter(limit int, nextID string) ([]BanEntry, error)
}

// BanCounter is implemented by ban stores that count bans in SQL.
type BanCounter interface {
	CountBans() int
}

// BanCounterWithError is BanCounter with an error.
type BanCounterWithError interface {
	CountBansE() (int, error)
}

// AuditLog records operator actions.
type AuditLog interface {
	Log(tenant, action, targetID, reason, actor, note string) error

	// Query returns up to limit entries, newest first; zero returns all.
	Query(limit int) []AuditEntry
}

// txAuditLog writes an audit entry inside the caller's transaction.
type txAuditLog interface {
	logTx(tx *sql.Tx, tenant, action, targetID, reason, actor,
		note string) error
}

// commitAudited writes the audit entry into tx and commits it, so the change
// and its audit entry land together or not at all. A nil log commits alone.
func commitAudited(tx *sql.Tx, log AuditLog,
	tenant, action, targetID, reason, actor, note string,
) error {
	if log != nil {
		tl, ok := log.(txAuditLog)
		if !ok {
			return errors.New(
				"audit log cannot write in a transaction")
		}
		err := tl.logTx(tx, tenant, action, targetID, reason, actor,
			note)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// FormatHardwareID returns hwid as lower-case hex.
func FormatHardwareID(hwid [32]byte) string {
	return hex.EncodeToString(hwid[:])
}

// ParseHardwareID decodes 64 hex digits of either case.
func ParseHardwareID(hexStr string) ([32]byte, error) {
	var hwid [32]byte
	if len(hexStr) != 64 {
		return hwid, errors.New("hardware ID must be exactly 64 hex characters")
	}

	// accept either case (FormatHardwareID lower-cases); a bad digit gets
	// the same error as a bad length, not the decoder's
	for i := 0; i < len(hexStr); i++ {
		c := hexStr[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return hwid, errors.New("hardware ID must be exactly 64 hex characters")
		}
	}
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return hwid, errors.New("invalid hardware ID encoding")
	}
	if len(decoded) != 32 {
		return hwid, errors.New("hardware ID must be exactly 32 bytes")
	}
	copy(hwid[:], decoded)
	return hwid, nil
}

// AttestationLog records attestation decisions; a trusted round that
// repeats the standing row extends it, see attestationCollapses.
type AttestationLog interface {
	Record(entry AttestationRecord) error

	// QueryAttestations returns the records matching q, newest first.
	QueryAttestations(q AttestationQuery) []AttestationRecord
}

// BatchRecorder is implemented by attestation logs that write a batch in one
// transaction.
type BatchRecorder interface {
	// RecordBatch writes every entry or none, and stamps zero timestamps
	// with the current time.
	RecordBatch(entries []AttestationRecord) error
}

// AttestationRecord is one row of the decision log.
type AttestationRecord struct {
	ID         int64
	Timestamp  time.Time
	Tenant     string // CA-assigned tenant, empty when the report never authenticated
	ClientID   string
	HardwareID string  // hex-encoded, empty if unknown
	Result     string  // types.VerifyResultString of the verdict
	DurationMs float64 // verification wall-clock time in milliseconds
	PCR14      string  // hex-encoded PCR14 value, empty if not available
	Details    string  // human-readable detail or error message
	RemoteAddr string  // client IP address

	// RecordedKernelHash in hex, empty if unknown.
	KernelHash string

	// Last round this row stands for, and the round count.
	// An event row: Timestamp and 1.
	LastSeen time.Time
	Rounds   int64
}
