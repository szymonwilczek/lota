// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package server

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// headerConstants parses include/lota_token.h so this package's copies
// of the wire-format constants can be compared against it
func headerConstants(t *testing.T) map[string]uint64 {
	t.Helper()
	path := filepath.Join("..", "..", "include", "lota_token.h")
	f, err := os.Open(path) // #nosec G304 -- fixed in-tree path
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	define := regexp.MustCompile(`^#define\s+(LOTA_[A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+|[0-9]+)\s*(?:/\*.*)?$`)
	out := make(map[string]uint64)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m := define.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		v, err := strconv.ParseUint(m[2], 0, 64)
		if err != nil {
			t.Fatalf("parse %s = %q: %v", m[1], m[2], err)
		}
		out[m[1]] = v
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return out
}

func TestConstantsMatchTokenHeader(t *testing.T) {
	hdr := headerConstants(t)
	for _, tc := range []struct {
		name string
		key  string
		got  uint64
	}{
		{"TokenMagic", "LOTA_TOKEN_MAGIC", uint64(TokenMagic)},
		{"TokenVersion", "LOTA_TOKEN_VERSION", uint64(TokenVersion)},
		{"TokenHeaderSize", "LOTA_TOKEN_HEADER_SIZE", uint64(TokenHeaderSize)},
		{"MaxProtectPIDs", "LOTA_TOKEN_MAX_PROTECT_PIDS", uint64(MaxProtectPIDs)},
	} {
		want, ok := hdr[tc.key]
		if !ok {
			t.Errorf("%s not found in include/lota_token.h", tc.key)
			continue
		}
		if tc.got != want {
			t.Errorf("%s = %d, but %s is %d", tc.name, tc.got, tc.key, want)
		}
	}
}

// TokenMaxSize must fit a full v2 token, 32-byte image digest per protected PID
func TestTokenMaxSizeCoversAFullV2Token(t *testing.T) {
	hdr := headerConstants(t)
	digest, ok := hdr["LOTA_TOKEN_IMAGE_DIGEST_SIZE"]
	if !ok {
		t.Fatal("LOTA_TOKEN_IMAGE_DIGEST_SIZE not found in include/lota_token.h")
	}
	worst := uint64(TokenHeaderSize) +
		uint64(MaxProtectPIDs)*(4+digest) +
		uint64(MaxAttestSize) + uint64(MaxSigSize)
	if uint64(TokenMaxSize) < worst {
		t.Errorf("TokenMaxSize = %d, below the %d-byte worst-case v2 token (%d PIDs)",
			TokenMaxSize, worst, MaxProtectPIDs)
	}
}
