// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - AIK revocation

package store

import (
	"errors"
	"time"
)

// RevocationReason is why a client was revoked or a hardware ID banned.
type RevocationReason string

const (
	RevocationCheating       RevocationReason = "cheating"
	RevocationCompromised    RevocationReason = "compromised"
	RevocationHardwareChange RevocationReason = "hardware_change"
	RevocationAdmin          RevocationReason = "admin"
)

// ValidRevocationReasons lists every accepted reason.
var ValidRevocationReasons = []RevocationReason{
	RevocationCheating,
	RevocationCompromised,
	RevocationHardwareChange,
	RevocationAdmin,
}

// IsValidReason reports whether reason is in ValidRevocationReasons.
func IsValidReason(reason string) bool {
	for _, r := range ValidRevocationReasons {
		if string(r) == reason {
			return true
		}
	}
	return false
}

// RevocationEntry is an active revocation. Tenant is the client's tenant
// when it was revoked; IsRevoked looks up the client ID alone.
type RevocationEntry struct {
	ClientID  string
	Tenant    string
	Reason    RevocationReason
	RevokedAt time.Time
	RevokedBy string // actor named by the request
	Note      string // free-form justification
}

var (
	ErrAlreadyRevoked = errors.New("client is already revoked")
	ErrNotRevoked     = errors.New("client is not revoked")
)

// RevocationStore holds the active client revocations.
type RevocationStore interface {
	// Revoke revokes clientID under tenant. It returns ErrAlreadyRevoked
	// if the client is revoked.
	Revoke(tenant, clientID string, reason RevocationReason, revokedBy, note string) error

	// IsRevoked returns the client's revocation and true, or nil and false.
	IsRevoked(clientID string) (*RevocationEntry, bool)

	// Unrevoke removes the client's revocation and logs reason and actor
	// to the audit trail. It returns ErrNotRevoked if the client is not
	// revoked.
	Unrevoke(clientID, reason, actor, note string) error

	// ListRevocations returns every active revocation.
	ListRevocations() []RevocationEntry
}
