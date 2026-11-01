// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Hardware Ban List
//
// Manages hardware-level bans using the TPM-derived hardware identity.
// Banned hardware ID is rejected from ALL attestation attempts regardless
// of which client ID is used - this defeats re-registration under new IDs.
//
// Hardware ban check happens BEFORE nonce consumption, right after
// the revocation check. Hardware ID comes from the TPM's endorsement key
// and is unforgeable without physical TPM replacement.
//
// Ban propagation: game servers call POST /api/v1/bans with the hardware ID
// obtained from the attestation result. The verifier immediately rejects
// all future attestation attempts from that hardware.
//
// Audit log records all ban/unban and revoke/unrevoke actions for forensic
// review and compliance. The log is append-only - entries are never modified.

package store

import (
	"encoding/hex"
	"errors"
	"time"
)

// records an active hardware ban
// Ban is scoped to a single tenant:
// the same hardware identity may be banned in one tenant and clean in another.
type BanEntry struct {
	Tenant     string
	HardwareID [32]byte
	Reason     RevocationReason
	BannedAt   time.Time
	BannedBy   string // administrator identifier
	Note       string // free-form justification
}

// records an immutable action in the audit log
type AuditEntry struct {
	ID        int64
	Timestamp time.Time
	Tenant    string // tenant the action acted within
	Action    string // "revoke", "unrevoke", "ban", "unban"
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

// manages hardware-level bans
// Bans are strictly per-tenant:
// Every operation names the tenant it acts within and never observes another tenant's entries.
type BanStore interface {
	// bans a hardware identity within a tenant
	// returns ErrAlreadyBanned if the hardware ID is already banned there
	BanHardware(tenant string, hardwareID [32]byte, reason RevocationReason, bannedBy, note string) error

	// checks if a hardware identity is banned within a tenant
	// returns the ban entry and true if banned, nil and false otherwise
	IsBanned(tenant string, hardwareID [32]byte) (*BanEntry, bool)

	// removes the ban for a hardware identity within a tenant
	// returns ErrNotBanned if the hardware ID is not currently banned there
	//
	// reason and actor are recorded in the audit trail on the same terms as
	// BanHardware's: letting a banned machine back in is the act a fleet
	// most wants signed, so the row that lifts a ban names who and why.
	UnbanHardware(tenant string, hardwareID [32]byte, reason, actor, note string) error

	// returns all active hardware bans across tenants
	ListBans() []BanEntry
}

// optional interface for stores that support SQL-level pagination.
type PaginatedBanLister interface {
	ListBansPage(limit, offset int) []BanEntry
}

// optional interface for stores that can return pagination errors.
type PaginatedBanListerWithError interface {
	ListBansPageE(limit, offset int) ([]BanEntry, error)
}

// cursor-based ban pagination to avoid OFFSET scans on large datasets.
// nextID is an opaque token returned by the API.
type CursorBanLister interface {
	ListBansAfter(limit int, nextID string) ([]BanEntry, error)
}

// optional interface for retrieving total ban count efficiently.
type BanCounter interface {
	CountBans() int
}

// optional interface for retrieving total ban count with error propagation.
type BanCounterWithError interface {
	CountBansE() (int, error)
}

// records all enforcement actions for forensic review
// Log is append-only - entries are never modified or deleted.
type AuditLog interface {
	// appends an action to the audit trail
	Log(tenant, action, targetID, reason, actor, note string) error

	// returns the most recent audit entries (newest first)
	// Use limit=0 for all entries
	Query(limit int) []AuditEntry
}

// returns hex-encoded hardware identity for display and storage
func FormatHardwareID(hwid [32]byte) string {
	return hex.EncodeToString(hwid[:])
}

// decodes a hex-encoded hardware identity
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

// records every attestation decision for forensic review
// one entry per attestation attempt
// Log is append-only
type AttestationLog interface {
	// records a single attestation attempt with its outcome
	Record(entry AttestationRecord) error

	// returns the records matching @q, newest first
	QueryAttestations(q AttestationQuery) []AttestationRecord
}

// BatchRecorder is optional AttestationLog capability:
// Backend that persists many records in a single round trip.
// On a WAL-backed database that means one transaction and one commit fsync for
// the whole batch instead of one per record, which is what lets the audit log
// keep up with fleet-scale verify rate.
// BatchedAttestationLog uses this to coalesce the per-report audit writes off
// the verification hot path.
type BatchRecorder interface {
	// Persists every entry durably.
	// Timestamps left zero are stamped now.
	// Either all entries are persisted or error is returned.
	RecordBatch(entries []AttestationRecord) error
}

// single attestation attempt outcome
type AttestationRecord struct {
	ID         int64
	Timestamp  time.Time
	Tenant     string // CA-assigned tenant, empty when the report never authenticated
	ClientID   string
	HardwareID string  // hex-encoded, empty if unknown
	Result     string  // ok, nonce_fail, sig_fail, pcr_fail, integrity_mismatch, revoked, banned, parse_error
	DurationMs float64 // verification wall-clock time in milliseconds
	PCR14      string  // hex-encoded PCR14 value, empty if not available
	Details    string  // human-readable detail or error message
	RemoteAddr string  // client IP address

	// hex-encoded kernel image hash the agent reported, empty if unknown.
	// Advisory: it gates nothing, and it is what an operator reads to answer
	// whether a device's kernel changed.
	// It is covered by the quote, so a recorded value is attested.
	KernelHash string

	// Last round this row stands for, and the round count.
	// An event row: Timestamp and 1.
	LastSeen time.Time
	Rounds   int64
}
