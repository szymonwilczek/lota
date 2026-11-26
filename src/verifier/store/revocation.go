// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - AIK revocation

package store

import (
	"errors"
	"strings"
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

	// IsRevoked returns the client's revocation and true, nil and false
	// when there is none, or an error when the store cannot tell.
	IsRevoked(clientID string) (*RevocationEntry, bool, error)

	// Unrevoke removes the client's revocation and logs reason and actor
	// to the audit trail. It returns ErrNotRevoked if the client is not
	// revoked.
	Unrevoke(clientID, reason, actor, note string) error

	// ListRevocations returns every active revocation.
	ListRevocations() []RevocationEntry

	// CountRevocationsIn counts the active revocations,
	// of tenants only when tenants is non-nil.
	CountRevocationsIn(tenants []string) (int, error)
}

// countInTenantsQuery builds a COUNT(*) over table, keeping the rows whose
// tenant is one of tenants when tenants is non-nil;
// ph returns the placeholder of the n-th argument.
func countInTenantsQuery(table string, tenants []string,
	ph func(n int) string,
) (q string, args []any) {
	q = "SELECT COUNT(*) FROM " + table
	if tenants == nil {
		return q, nil
	}
	if len(tenants) == 0 {
		return q + " WHERE 0 = 1", nil
	}
	args = make([]any, 0, len(tenants))
	set := make([]string, 0, len(tenants))
	for _, t := range tenants {
		args = append(args, t)
		set = append(set, ph(len(args)))
	}
	return q + " WHERE tenant IN (" + strings.Join(set, ", ") + ")", args
}
