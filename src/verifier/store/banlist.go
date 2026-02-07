// SPDX-License-Identifier: MIT
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
	"sync"
	"time"
)

// records an active hardware ban
type BanEntry struct {
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
type BanStore interface {
	// bans a hardware identity
	// returns ErrAlreadyBanned if the hardware ID is already banned
	BanHardware(hardwareID [32]byte, reason RevocationReason, bannedBy, note string) error

	// checks if a hardware identity is banned
	// returns the ban entry and true if banned, nil and false otherwise
	IsBanned(hardwareID [32]byte) (*BanEntry, bool)

	// removes the ban for a hardware identity
	// returns ErrNotBanned if the hardware ID is not currently banned
	UnbanHardware(hardwareID [32]byte) error

	// returns all active hardware bans
	ListBans() []BanEntry
}

// records all enforcement actions for forensic review
// Log is append-only - entries are never modified or deleted.
type AuditLog interface {
	// appends an action to the audit trail
	Log(action, targetID, reason, actor, note string) error

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
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return hwid, errors.New("invalid hex encoding")
	}
	if len(decoded) != 32 {
		return hwid, errors.New("hardware ID must be exactly 32 bytes")
	}
	copy(hwid[:], decoded)
	return hwid, nil
}

// implements BanStore using an in-memory map
// for testing!!!
type MemoryBanStore struct {
	mu       sync.RWMutex
	bans     map[[32]byte]*BanEntry
	auditLog AuditLog // optional audit trail
}

// creates an empty in-memory ban store
// if auditLog is non-nil, all mutations are recorded in the audit trail.
func NewMemoryBanStore(auditLog ...AuditLog) *MemoryBanStore {
	s := &MemoryBanStore{
		bans: make(map[[32]byte]*BanEntry),
	}
	if len(auditLog) > 0 {
		s.auditLog = auditLog[0]
	}
	return s
}

func (s *MemoryBanStore) BanHardware(hardwareID [32]byte, reason RevocationReason, bannedBy, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.bans[hardwareID]; exists {
		return ErrAlreadyBanned
	}

	s.bans[hardwareID] = &BanEntry{
		HardwareID: hardwareID,
		Reason:     reason,
		BannedAt:   time.Now().UTC(),
		BannedBy:   bannedBy,
		Note:       note,
	}

	if s.auditLog != nil {
		s.auditLog.Log("ban", FormatHardwareID(hardwareID), string(reason), bannedBy, note)
	}

	return nil
}

func (s *MemoryBanStore) IsBanned(hardwareID [32]byte) (*BanEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.bans[hardwareID]
	if !exists {
		return nil, false
	}
	return entry, true
}

func (s *MemoryBanStore) UnbanHardware(hardwareID [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.bans[hardwareID]; !exists {
		return ErrNotBanned
	}

	delete(s.bans, hardwareID)

	if s.auditLog != nil {
		s.auditLog.Log("unban", FormatHardwareID(hardwareID), "", "", "")
	}

	return nil
}

func (s *MemoryBanStore) ListBans() []BanEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := make([]BanEntry, 0, len(s.bans))
	for _, entry := range s.bans {
		entries = append(entries, *entry)
	}
	return entries
}

// implements AuditLog using an in-memory slice
// for testing!!!
type MemoryAuditLog struct {
	mu      sync.RWMutex
	entries []AuditEntry
	nextID  int64
}

// creates an empty in-memory audit log
func NewMemoryAuditLog() *MemoryAuditLog {
	return &MemoryAuditLog{
		entries: make([]AuditEntry, 0),
		nextID:  1,
	}
}

func (l *MemoryAuditLog) Log(action, targetID, reason, actor, note string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.entries = append(l.entries, AuditEntry{
		ID:        l.nextID,
		Timestamp: time.Now().UTC(),
		Action:    action,
		TargetID:  targetID,
		Reason:    reason,
		Actor:     actor,
		Note:      note,
	})
	l.nextID++

	return nil
}

func (l *MemoryAuditLog) Query(limit int) []AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	n := len(l.entries)
	if limit > 0 && limit < n {
		n = limit
	}

	// newest first
	result := make([]AuditEntry, n)
	for i := 0; i < n; i++ {
		result[i] = l.entries[len(l.entries)-1-i]
	}
	return result
}

// records every attestation decision for forensic review
// one entry per attestation attempt
// Log is append-only
type AttestationLog interface {
	// records a single attestation attempt with its outcome
	Record(entry AttestationRecord) error

	// returns the most recent attestation records (newest first)
	QueryAttestations(limit int) []AttestationRecord
}

// single attestation attempt outcome
type AttestationRecord struct {
	ID         int64
	Timestamp  time.Time
	ClientID   string
	HardwareID string  // hex-encoded, empty if unknown
	Result     string  // ok, nonce_fail, sig_fail, pcr_fail, integrity_mismatch, revoked, banned, parse_error
	DurationMs float64 // verification wall-clock time in milliseconds
	PCR14      string  // hex-encoded PCR14 value, empty if not available
	Details    string  // human-readable detail or error message
	RemoteAddr string  // client IP address
}

// implements AttestationLog using an in-memory slice
type MemoryAttestationLog struct {
	mu      sync.RWMutex
	entries []AttestationRecord
	nextID  int64
}

// creates an empty in-memory attestation log
func NewMemoryAttestationLog() *MemoryAttestationLog {
	return &MemoryAttestationLog{
		entries: make([]AttestationRecord, 0),
		nextID:  1,
	}
}

func (l *MemoryAttestationLog) Record(entry AttestationRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.ID = l.nextID
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	l.entries = append(l.entries, entry)
	l.nextID++
	return nil
}

func (l *MemoryAttestationLog) QueryAttestations(limit int) []AttestationRecord {
	l.mu.RLock()
	defer l.mu.RUnlock()

	n := len(l.entries)
	if limit > 0 && limit < n {
		n = limit
	}

	// newest first
	result := make([]AttestationRecord, n)
	for i := 0; i < n; i++ {
		result[i] = l.entries[len(l.entries)-1-i]
	}
	return result
}
