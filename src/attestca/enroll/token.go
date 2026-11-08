// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

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

// MaxEnrollTokenLen is the longest token TenantFor accepts,
// as wire.MaxEnrollTokenSize.
const MaxEnrollTokenLen = 128

var (
	// ErrTokenUnknown is returned for a token no entry matches.
	ErrTokenUnknown = errors.New("enrollment token not recognized")

	// ErrTokenRequired is returned by Begin for a token-less enrollment
	// under WithRequireToken.
	ErrTokenRequired = errors.New("enrollment requires a token")
)

// EnrollmentTokens maps SHA-256 digests of enrollment tokens to tenants.
type EnrollmentTokens struct {
	byDigest map[string]string
}

// LoadEnrollmentTokens reads lines of "<token_sha256> <tenant>"; blank and
// '#' lines are skipped. A malformed line, a duplicate digest, an invalid
// tenant or a file with no entry fails the load.
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

// TenantFor returns the tenant listed for the token's SHA-256. An empty,
// overlong or unlisted token, or a nil t, gives ErrTokenUnknown.
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
