// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
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
// Tenant records which tenant the client belonged to at revocation time
// so the operator surface can scope listings and mutations.
// Enforcement keys on the client ID, which the CA issues per tenant.
type RevocationEntry struct {
	ClientID  string
	Tenant    string
	Reason    RevocationReason
	RevokedAt time.Time
	RevokedBy string // administrator identifier
	Note      string // free-form justification
}

// revocation errors
var (
	ErrAlreadyRevoked = errors.New("client is already revoked")
	ErrNotRevoked     = errors.New("client is not revoked")
)

// manages client AIK revocations
type RevocationStore interface {
	// marks client's AIK as revoked, recording the tenant it belongs to
	// returns ErrAlreadyRevoked if already revoked
	Revoke(tenant, clientID string, reason RevocationReason, revokedBy, note string) error

	// checks if a client's AIK has been revoked
	// returns the revocation entry and true if revoked, nil and false otherwise
	IsRevoked(clientID string) (*RevocationEntry, bool)

	// unrevoke removes the revocation for a client
	// returns ErrNotRevoked if the client is not currently revoked
	//
	// reason and actor are recorded in the audit trail on the same terms as
	// Revoke's: restoring a client's access is the act a fleet most wants
	// signed, so the row that lifts a revocation names who did it and why.
	Unrevoke(clientID, reason, actor, note string) error

	// returns all active revocations
	ListRevocations() []RevocationEntry
}
