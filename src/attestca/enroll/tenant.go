// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Attestation CA - tenant assignment
//
// Multi-tenant deployment assigns each enrolling device a tenant.
// Enterprise path resolves the tenant from an operator-maintained manifest
// that maps an endorsement-key fingerprint to a tenant name.
// Tenant is written into the issued AIK certificate subject as single
// OrganizationalUnit and mixed into the device pseudonym, so the same TPM
// enrolling into two tenants yields two distinct, non-colliding device IDs.

package enroll

import (
	"bufio"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// DefaultTenant is the tenant of device with no manifest entry
// (when the manifest is non-strict) and the reserved name the verifier
// maps a certificate with no OrganizationalUnit to.
const DefaultTenant = "default"

// MaxTenantLen bounds tenant name.
// Mirrors the verifier's grammar so name accepted here is accepted by the relying party.
const MaxTenantLen = 64

// ValidTenantName reports whether name is a syntactically valid tenant:
// 1..MaxTenantLen characters of lowercase letters, digits, and inner
// dashes (no leading or trailing dash).
// Mirrors the verifier's ValidTenantName so the CA never issues tenant
// the verifier rejects.
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

// EKFingerprint returns the stable, non-secret fingerprint an operator uses
// to name an endorsement key in the tenant manifest:
// the SHA-256 of the EK public modulus, lowercase hex.
// It is not the device pseudonym (which is a keyed HMAC) and reveals nothing
// a holder of the EK certificate does not already know.
func EKFingerprint(ekPub *rsa.PublicKey) string {
	sum := sha256.Sum256(ekPub.N.Bytes())
	return hex.EncodeToString(sum[:])
}

// TenantManifest maps endorsement-key fingerprints to tenants.
// When strict is set an EK with no entry is refused enrollment
// (the manifest doubles as an EK allowlist);
// Otherwise an unlisted EK lands in the default tenant.
type TenantManifest struct {
	byFingerprint map[string]string
	strict        bool
}

// LoadTenantManifest reads and validates an EK-to-tenant manifest.
// File is one entry per line, "<ek_sha256> <tenant>", with blank lines
// and lines beginning with '#' ignored.
// Every entry must carry a 64-hex EK fingerprint and a valid tenant name;
// Duplicate fingerprint or any malformed line fails the whole load.
// When strict is set, an EK absent from the manifest is refused enrollment.
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

// TenantFor resolves the tenant of an endorsement key.
// Listed EK maps to its tenant; unlisted EK maps to the default tenant,
// or is refused when the manifest is strict.
func (m *TenantManifest) TenantFor(ekPub *rsa.PublicKey) (string, error) {
	if m == nil {
		return DefaultTenant, nil
	}
	if tenant, ok := m.byFingerprint[EKFingerprint(ekPub)]; ok {
		return tenant, nil
	}
	if m.strict {
		return "", fmt.Errorf("endorsement key not listed in the tenant manifest")
	}
	return DefaultTenant, nil
}
