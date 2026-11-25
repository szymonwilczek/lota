// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package enroll

import (
	"bufio"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrEKNotListed is returned for an EK a strict manifest does not list.
var ErrEKNotListed = errors.New("endorsement key not listed in the tenant manifest")

// DefaultTenant is the tenant of an admitted device no manifest entry or
// token assigns elsewhere; either may also assign it by name. Its AIK
// certificate carries no OU and its device ID no tenant prefix.
const DefaultTenant = "default"

// MaxTenantLen is the longest tenant name.
const MaxTenantLen = 64

// ValidTenantName reports whether name is 1..MaxTenantLen lower-case
// letters, digits and inner dashes, the grammar the verifier accepts.
func ValidTenantName(name string) bool {
	if name == "" || len(name) > MaxTenantLen {
		return false
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}

// EKFingerprint returns the lower-case hex SHA-256 of the EK modulus,
// the key of a manifest entry.
func EKFingerprint(ekPub *rsa.PublicKey) string {
	sum := sha256.Sum256(ekPub.N.Bytes())
	return hex.EncodeToString(sum[:])
}

// TenantManifest maps EK fingerprints to tenants.
type TenantManifest struct {
	byFingerprint map[string]string
	strict        bool
}

// LoadTenantManifest reads lines of "<ek_sha256> <tenant>"; blank and '#'
// lines are skipped. A malformed line, a duplicate fingerprint, an invalid
// tenant or a file with no entry fails the load. A strict manifest refuses
// an EK it does not list.
func LoadTenantManifest(path string, strict bool) (*TenantManifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open tenant manifest: %w", err)
	}
	defer f.Close()

	m := &TenantManifest{
		byFingerprint: make(map[string]string),
		strict:        strict,
	}

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: expected \"<ek_sha256> <tenant>\"", lineNo)
		}
		raw, err := hex.DecodeString(fields[0])
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("line %d: ek_sha256 must be 64 hex characters", lineNo)
		}
		key := hex.EncodeToString(raw)
		if _, dup := m.byFingerprint[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate ek_sha256", lineNo)
		}
		if !ValidTenantName(fields[1]) {
			return nil, fmt.Errorf("line %d: invalid tenant %q", lineNo, fields[1])
		}
		m.byFingerprint[key] = fields[1]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read tenant manifest: %w", err)
	}
	if len(m.byFingerprint) == 0 {
		return nil, fmt.Errorf("tenant manifest %s lists no devices", path)
	}
	return m, nil
}

// TenantFor returns the tenant listed for ekPub. An unlisted EK gets
// DefaultTenant, or ErrEKNotListed from a strict manifest; a nil manifest
// gives DefaultTenant.
func (m *TenantManifest) TenantFor(ekPub *rsa.PublicKey) (string, error) {
	if m == nil {
		return DefaultTenant, nil
	}
	if tenant, ok := m.byFingerprint[EKFingerprint(ekPub)]; ok {
		return tenant, nil
	}
	if m.strict {
		return "", ErrEKNotListed
	}
	return DefaultTenant, nil
}
