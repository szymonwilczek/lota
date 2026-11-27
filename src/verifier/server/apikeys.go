// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - scoped API key file

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/szymonwilczek/lota/verifier/verify"
)

// APIKeyRole names an authorization tier; admin implies reader.
type APIKeyRole string

const (
	RoleReader APIKeyRole = "reader"
	RoleAdmin  APIKeyRole = "admin"
)

// Principal is an authenticated API caller: its tier and the tenants it
// may see and act on.
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

type apiKeyEntry struct {
	role       APIKeyRole
	allTenants bool
	tenants    map[string]struct{}
}

// APIKeySet is a validated key file, never changed once loaded;
// a reload swaps in a new set.
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

type apiKeyFile struct {
	Keys []apiKeyFileEntry `yaml:"keys"`
}

type apiKeyFileEntry struct {
	KeySHA256 string     `yaml:"key_sha256"`
	Role      APIKeyRole `yaml:"role"`
	Tenants   []string   `yaml:"tenants"`
}

// LoadAPIKeysFile parses and validates a scoped API key file. One invalid
// entry, or no entry, fails the whole load, so a typo cannot drop a key or
// widen a scope.
func LoadAPIKeysFile(path string) (*APIKeySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read API keys file: %w", err)
	}

	var file apiKeyFile
	err = verify.DecodeYAMLDocument(data, &file)
	if errors.Is(err, verify.ErrExtraYAMLDocument) {
		return nil, fmt.Errorf("failed to parse API keys file %s: %w",
			path, err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse API keys file %s: "+
			"unknown key or malformed YAML", path)
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
			return nil, fmt.Errorf("key %d: role must be reader or admin", i)
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
				return nil, fmt.Errorf("key %d: invalid tenant name", i)
			}
			entry.tenants[tenant] = struct{}{}
		}

		set.byHash[hash] = entry
	}

	return set, nil
}
