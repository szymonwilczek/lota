// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - scoped API key file
//
// Monitoring API historically knows two keys, both from environment
// variables and both global: LOTA_ADMIN_API_KEY and LOTA_READER_API_KEY.
//
// Multi-tenant deployments need more:
// one operator per tenant, each with their own key, role, and tenant set.
//
// --api-keys-file names a YAML file of key entries:
//
//	keys:
//	  - key_sha256: <64 lowercase hex of sha256(key)>
//	    role: reader | admin
//	    tenants: ["acme", "beta"]   # or ["*"] for every tenant
//
// Only the SHA-256 of each key is stored, never the key itself.
// The file is reloaded on SIGHUP; file that fails to parse or validate leaves
// the previously loaded set in place.
// Environment keys keep working and stay global-scope for backwards compatibility.

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/szymonwilczek/lota/verifier/verify"
)

// APIKeyRole names an authorization tier.
// Admin implies reader.
type APIKeyRole string

const (
	RoleReader APIKeyRole = "reader"
	RoleAdmin  APIKeyRole = "admin"
)

// Principal describes an authenticated API caller:
// its tier and the tenants it may observe and act on.
type Principal struct {
	Role       APIKeyRole
	AllTenants bool
	Tenants    map[string]struct{}
}

// CanAdmin reports whether the principal may call mutating endpoints.
func (p *Principal) CanAdmin() bool {
	return p != nil && p.Role == RoleAdmin
}

// AllowsTenant reports whether the principal may act within a tenant.
func (p *Principal) AllowsTenant(tenant string) bool {
	if p == nil {
		return false
	}
	if p.AllTenants {
		return true
	}
	_, ok := p.Tenants[tenant]
	return ok
}

// one parsed key entry, keyed by the hash of the presented token
type apiKeyEntry struct {
	role       APIKeyRole
	allTenants bool
	tenants    map[string]struct{}
}

// APIKeySet is an immutable, validated key file.
// Server swaps whole sets atomically on reload.
type APIKeySet struct {
	byHash map[[32]byte]apiKeyEntry
}

// Len reports how many keys the set carries.
func (ks *APIKeySet) Len() int {
	if ks == nil {
		return 0
	}
	return len(ks.byHash)
}

// Lookup resolves a presented bearer token to its principal.
func (ks *APIKeySet) Lookup(token string) (*Principal, bool) {
	if ks == nil {
		return nil, false
	}
	entry, ok := ks.byHash[sha256.Sum256([]byte(token))]
	if !ok {
		return nil, false
	}
	return &Principal{
		Role:       entry.role,
		AllTenants: entry.allTenants,
		Tenants:    entry.tenants,
	}, true
}

// on-disk shape
type apiKeyFile struct {
	Keys []apiKeyFileEntry `yaml:"keys"`
}

type apiKeyFileEntry struct {
	KeySHA256 string     `yaml:"key_sha256"`
	Role      APIKeyRole `yaml:"role"`
	Tenants   []string   `yaml:"tenants"`
}

// LoadAPIKeysFile parses and validates a scoped API key file.
// Any invalid entry fails the whole load so typo cannot silently
// drop a key or widen a scope.
func LoadAPIKeysFile(path string) (*APIKeySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read API keys file: %w", err)
	}

	var file apiKeyFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("failed to parse API keys file: %w", err)
	}
	if len(file.Keys) == 0 {
		return nil, fmt.Errorf("API keys file %s defines no keys", path)
	}

	set := &APIKeySet{byHash: make(map[[32]byte]apiKeyEntry, len(file.Keys))}
	for i, e := range file.Keys {
		raw, err := hex.DecodeString(e.KeySHA256)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("key %d: key_sha256 must be 64 hex characters", i)
		}
		var hash [32]byte
		copy(hash[:], raw)
		if _, dup := set.byHash[hash]; dup {
			return nil, fmt.Errorf("key %d: duplicate key_sha256", i)
		}

		if e.Role != RoleReader && e.Role != RoleAdmin {
			return nil, fmt.Errorf("key %d: role must be reader or admin, got %q", i, e.Role)
		}

		if len(e.Tenants) == 0 {
			return nil, fmt.Errorf("key %d: tenants must not be empty (use [\"*\"] for all tenants)", i)
		}
		entry := apiKeyEntry{role: e.Role, tenants: make(map[string]struct{}, len(e.Tenants))}
		for _, tenant := range e.Tenants {
			if tenant == "*" {
				entry.allTenants = true
				continue
			}
			if !verify.ValidTenantName(tenant) {
				return nil, fmt.Errorf("key %d: invalid tenant %q", i, tenant)
			}
			entry.tenants[tenant] = struct{}{}
		}

		set.byHash[hash] = entry
	}

	return set, nil
}
