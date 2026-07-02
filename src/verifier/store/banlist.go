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
	"sort"
	"sync"
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
	UnbanHardware(tenant string, hardwareID [32]byte) error

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
		return hwid, errors.New("hardware ID must be exactly 64 lowercase hex characters")
	}
	for i := 0; i < len(hexStr); i++ {
		c := hexStr[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return hwid, errors.New("hardware ID must be exactly 64 lowercase hex characters")
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

// identifies one tenant's ban on one hardware identity
type banKey struct {
	tenant     string
	hardwareID [32]byte
}

// implements BanStore using an in-memory map (testing only)
type MemoryBanStore struct {
	mu       sync.RWMutex
	bans     map[banKey]*BanEntry
	auditLog AuditLog // optional audit trail
}

// creates an empty in-memory ban store
// if auditLog is non-nil, all mutations are recorded in the audit trail.
func NewMemoryBanStore(auditLog ...AuditLog) *MemoryBanStore {
	s := &MemoryBanStore{
		bans: make(map[banKey]*BanEntry),
	}
	if len(auditLog) > 0 {
		s.auditLog = auditLog[0]
	}
	return s
}

func (s *MemoryBanStore) BanHardware(tenant string, hardwareID [32]byte, reason RevocationReason, bannedBy, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := banKey{tenant: tenant, hardwareID: hardwareID}
	if _, exists := s.bans[key]; exists {
		return ErrAlreadyBanned
	}

	s.bans[key] = &BanEntry{
		Tenant:     tenant,
		HardwareID: hardwareID,
		Reason:     reason,
		BannedAt:   time.Now().UTC(),
		BannedBy:   bannedBy,
		Note:       note,
	}

	if s.auditLog != nil {
		if err := s.auditLog.Log(tenant, "ban", FormatHardwareID(hardwareID), string(reason), bannedBy, note); err != nil {
			return err
		}
	}

	return nil
}

func (s *MemoryBanStore) IsBanned(tenant string, hardwareID [32]byte) (*BanEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.bans[banKey{tenant: tenant, hardwareID: hardwareID}]
	if !exists {
		return nil, false
	}
	return entry, true
}

func (s *MemoryBanStore) UnbanHardware(tenant string, hardwareID [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := banKey{tenant: tenant, hardwareID: hardwareID}
	if _, exists := s.bans[key]; !exists {
		return ErrNotBanned
	}

	delete(s.bans, key)

	if s.auditLog != nil {
		if err := s.auditLog.Log(tenant, "unban", FormatHardwareID(hardwareID), "", "", ""); err != nil {
			return err
		}
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
	sortBanEntriesDesc(entries)
	return entries
}

func (s *MemoryBanStore) ListBansPage(limit, offset int) []BanEntry {
	entries := s.ListBans()
	if offset < 0 {
		offset = 0
	}
	if offset >= len(entries) {
		return []BanEntry{}
	}
	if limit <= 0 {
		return entries[offset:]
	}
	end := offset + limit
	if end > len(entries) {
		end = len(entries)
	}
	return entries[offset:end]
}

func (s *MemoryBanStore) ListBansAfter(limit int, nextID string) ([]BanEntry, error) {
	entries := s.ListBans()
	if limit <= 0 || len(entries) == 0 {
		return []BanEntry{}, nil
	}

	start := 0
	if nextID != "" {
		cursor, err := DecodeBanCursor(nextID)
		if err != nil {
			return nil, err
		}

		start = len(entries)
		for i, e := range entries {
			if e.BannedAt.Before(cursor.BannedAt) ||
				(e.BannedAt.Equal(cursor.BannedAt) && compareHardwareID(e.HardwareID, cursor.HardwareID) < 0) ||
				(e.BannedAt.Equal(cursor.BannedAt) && e.HardwareID == cursor.HardwareID && e.Tenant < cursor.Tenant) {
				start = i
				break
			}
		}
	}

	if start >= len(entries) {
		return []BanEntry{}, nil
	}

	end := start + limit
	if end > len(entries) {
		end = len(entries)
	}

	return entries[start:end], nil
}

func sortBanEntriesDesc(entries []BanEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].BannedAt.Equal(entries[j].BannedAt) {
			if c := compareHardwareID(entries[i].HardwareID, entries[j].HardwareID); c != 0 {
				return c > 0
			}
			return entries[i].Tenant > entries[j].Tenant
		}
		return entries[i].BannedAt.After(entries[j].BannedAt)
	})
}

func compareHardwareID(a, b [32]byte) int {
	for i := 0; i < len(a); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func (s *MemoryBanStore) CountBans() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.bans)
}

// implements AuditLog using an in-memory slice (testing only)
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

func (l *MemoryAuditLog) Log(tenant, action, targetID, reason, actor, note string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.entries = append(l.entries, AuditEntry{
		ID:        l.nextID,
		Timestamp: time.Now().UTC(),
		Tenant:    tenant,
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
	Tenant     string // CA-assigned tenant, empty when the report never authenticated
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
