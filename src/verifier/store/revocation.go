// SPDX-License-Identifier: MIT
// LOTA Verifier - AIK Revocation Management
//
// Manages client AIK revocations. Revoked client is permanently rejected
// from attestation until explicitly unrevoked by an administrator.
//
// Revocation check happens BEFORE nonce consumption in the
// verification pipeline. This prevents wasting nonces on known-bad clients
// and avoids any crypto operations for revoked identities.
//
// Revocation reasons follow a fixed taxonomy for consistent audit trails:
//   - cheating:         detected cheating via game server or manual review
//   - compromised:      AIK key material suspected compromised
//   - hardware_change:  legitimate hardware change requiring re-enrollment
//   - admin:            administrative action (catch-all)

package store

import (
	"errors"
	"sync"
	"time"
)

// categorizes why a client was revoked
type RevocationReason string

const (
	RevocationCheating       RevocationReason = "cheating"
	RevocationCompromised    RevocationReason = "compromised"
	RevocationHardwareChange RevocationReason = "hardware_change"
	RevocationAdmin          RevocationReason = "admin"
)

// lists all accepted reason values
var ValidRevocationReasons = []RevocationReason{
	RevocationCheating,
	RevocationCompromised,
	RevocationHardwareChange,
	RevocationAdmin,
}

// checks whether a string is an accepted revocation reason
func IsValidReason(reason string) bool {
	for _, r := range ValidRevocationReasons {
		if string(r) == reason {
			return true
		}
	}
	return false
}

// records an active AIK revocation
type RevocationEntry struct {
	ClientID  string
	Reason    RevocationReason
	RevokedAt time.Time
	RevokedBy string // administrator identifier
	Note      string // free-form justification
}

// revocation errors
var (
	ErrAlreadyRevoked = errors.New("client is already revoked")
	ErrNotRevoked     = errors.New("client is not revoked")
	ErrInvalidReason  = errors.New("invalid revocation reason")
)

// manages client AIK revocations
type RevocationStore interface {
	// marks a client's AIK as revoked
	// returns ErrAlreadyRevoked if the client is already revoked
	Revoke(clientID string, reason RevocationReason, revokedBy, note string) error

	// checks if a client's AIK has been revoked
	// returns the revocation entry and true if revoked, nil and false otherwise
	IsRevoked(clientID string) (*RevocationEntry, bool)

	// unrevoke removes the revocation for a client
	// returns ErrNotRevoked if the client is not currently revoked
	Unrevoke(clientID string) error

	// returns all active revocations
	ListRevocations() []RevocationEntry
}

// implements RevocationStore using an in-memory map
// for testing
type MemoryRevocationStore struct {
	mu          sync.RWMutex
	revocations map[string]*RevocationEntry // clientID -> entry
	auditLog    AuditLog                    // optional audit trail
}

// creates an empty in-memory revocation store
// if auditLog is non-nil, all mutations are recorded in the audit trail
func NewMemoryRevocationStore(auditLog ...AuditLog) *MemoryRevocationStore {
	s := &MemoryRevocationStore{
		revocations: make(map[string]*RevocationEntry),
	}
	if len(auditLog) > 0 {
		s.auditLog = auditLog[0]
	}
	return s
}

func (s *MemoryRevocationStore) Revoke(clientID string, reason RevocationReason, revokedBy, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.revocations[clientID]; exists {
		return ErrAlreadyRevoked
	}

	s.revocations[clientID] = &RevocationEntry{
		ClientID:  clientID,
		Reason:    reason,
		RevokedAt: time.Now().UTC(),
		RevokedBy: revokedBy,
		Note:      note,
	}

	if s.auditLog != nil {
		s.auditLog.Log("revoke", clientID, string(reason), revokedBy, note)
	}

	return nil
}

func (s *MemoryRevocationStore) IsRevoked(clientID string) (*RevocationEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.revocations[clientID]
	if !exists {
		return nil, false
	}
	return entry, true
}

func (s *MemoryRevocationStore) Unrevoke(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.revocations[clientID]; !exists {
		return ErrNotRevoked
	}

	delete(s.revocations, clientID)

	if s.auditLog != nil {
		s.auditLog.Log("unrevoke", clientID, "", "", "")
	}

	return nil
}

func (s *MemoryRevocationStore) ListRevocations() []RevocationEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := make([]RevocationEntry, 0, len(s.revocations))
	for _, entry := range s.revocations {
		entries = append(entries, *entry)
	}
	return entries
}
