// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Attestation CA - enrollment-token tenant assignment
//
// Gaming path assigns tenants to devices the operator has never seen:
// consumer machine cannot be pre-listed in an EK manifest, so it presents
// per-tenant enrollment token with its begin request instead.
// CA stores only the SHA-256 of each token, so the token file leaks no enrollable
// credential, and resolves the tenant from the digest of the presented token.

package enroll

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// MaxEnrollTokenLen bounds a presented token;
// Mirrors the wire cap so token the codec carries is never rejected here for size alone.
const MaxEnrollTokenLen = 128

var (
	// ErrTokenUnknown rejects a presented token that matches no
	// configured entry (including a CA with no token file at all).
	ErrTokenUnknown = errors.New("enrollment token not recognized")

	// ErrTokenRequired rejects a token-less enrollment on a CA that mandates tokens.
	ErrTokenRequired = errors.New("enrollment requires a token")
)

// EnrollmentTokens maps SHA-256 digests of enrollment tokens to tenants.
type EnrollmentTokens struct {
	byDigest map[string]string
}

// LoadEnrollmentTokens reads and validates a token-to-tenant file.
// File is one entry per line, "<token_sha256> <tenant>", with blank lines
// and lines beginning with '#' ignored.
// Every entry must carry a 64-hex token digest and a valid tenant name;
// Duplicate digest or any malformed line fails the whole load.
// Only digests are stored, never tokens:
// operator mints a token, hands it to the tenant's install flow,
// and records sha256(token) here.
func LoadEnrollmentTokens(path string) (*EnrollmentTokens, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open enrollment tokens: %w", err)
	}
	defer f.Close()

	t := &EnrollmentTokens{byDigest: make(map[string]string)}

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
			return nil, fmt.Errorf("line %d: expected \"<token_sha256> <tenant>\"", lineNo)
		}
		raw, err := hex.DecodeString(fields[0])
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("line %d: token_sha256 must be 64 hex characters", lineNo)
		}
		key := hex.EncodeToString(raw)
		if _, dup := t.byDigest[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate token_sha256", lineNo)
		}
		if !ValidTenantName(fields[1]) {
			return nil, fmt.Errorf("line %d: invalid tenant %q", lineNo, fields[1])
		}
		t.byDigest[key] = fields[1]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read enrollment tokens: %w", err)
	}
	if len(t.byDigest) == 0 {
		return nil, fmt.Errorf("enrollment token file %s lists no tokens", path)
	}
	return t, nil
}

// TenantFor resolves the tenant of a presented token.
// Token is hashed before the lookup, so the comparison never touches token
// bytes and the map key cannot be probed byte by byte.
// Unmatched token fails closed with ErrTokenUnknown;
// There is no default-tenant fallback, because device that presents token
// asks for an explicit assignment.
func (t *EnrollmentTokens) TenantFor(token []byte) (string, error) {
	if t == nil || len(token) == 0 || len(token) > MaxEnrollTokenLen {
		return "", ErrTokenUnknown
	}
	sum := sha256.Sum256(token)
	tenant, ok := t.byDigest[hex.EncodeToString(sum[:])]
	if !ok {
		return "", ErrTokenUnknown
	}
	return tenant, nil
}
