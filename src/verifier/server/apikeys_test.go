// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - scoped API key file tests

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

func keyHashHex(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func writeKeysFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write keys file: %v", err)
	}
	return path
}

func TestLoadAPIKeysFile(t *testing.T) {
	path := writeKeysFile(t, fmt.Sprintf(`keys:
  - key_sha256: %s
    role: admin
    tenants: ["acme", "beta"]
  - key_sha256: %s
    role: reader
    tenants: ["*"]
`, keyHashHex("admin-acme"), keyHashHex("reader-all")))

	set, err := LoadAPIKeysFile(path)
	if err != nil {
		t.Fatalf("LoadAPIKeysFile: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2", set.Len())
	}

	p, ok := set.Lookup("admin-acme")
	if !ok || p.Role != RoleAdmin || p.AllTenants {
		t.Fatalf("admin-acme principal = %+v", p)
	}
	if !p.AllowsTenant("acme") || !p.AllowsTenant("beta") || p.AllowsTenant("other") {
		t.Fatalf("admin-acme tenant set wrong: %+v", p)
	}

	p, ok = set.Lookup("reader-all")
	if !ok || p.Role != RoleReader || !p.AllTenants {
		t.Fatalf("reader-all principal = %+v", p)
	}
	if !p.AllowsTenant("anything") {
		t.Fatal("wildcard principal must allow every tenant")
	}

	if _, ok := set.Lookup("wrong-key"); ok {
		t.Fatal("unknown key resolved to a principal")
	}
}

func TestLoadAPIKeysFileRejectsInvalid(t *testing.T) {
	hash := keyHashHex("k")
	cases := map[string]string{
		"empty file":      "keys: []\n",
		"bad hash":        "keys:\n  - key_sha256: nothex\n    role: admin\n    tenants: [\"*\"]\n",
		"bad role":        fmt.Sprintf("keys:\n  - key_sha256: %s\n    role: root\n    tenants: [\"*\"]\n", hash),
		"no tenants":      fmt.Sprintf("keys:\n  - key_sha256: %s\n    role: admin\n", hash),
		"invalid tenant":  fmt.Sprintf("keys:\n  - key_sha256: %s\n    role: admin\n    tenants: [\"Not Valid\"]\n", hash),
		"duplicate hash":  fmt.Sprintf("keys:\n  - key_sha256: %s\n    role: admin\n    tenants: [\"*\"]\n  - key_sha256: %s\n    role: reader\n    tenants: [\"*\"]\n", hash, hash),
		"not yaml at all": "{{{{",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadAPIKeysFile(writeKeysFile(t, content)); err == nil {
				t.Fatal("invalid keys file was accepted")
			}
		})
	}
}

// newScopedKeyAPI builds an API handler whose server carries the given
// scoped key set and NO env keys.
func newScopedKeyAPI(t *testing.T, set *APIKeySet) *http.ServeMux {
	t.Helper()

	aikStore := newCertStore(t)
	cfg := verify.DefaultConfig()
	cfg.RequireBootPCRs = false
	cfg.RequireInitramfsLock = false
	auditLog := store.NewMemoryAuditLog()
	cfg.RevocationStore = store.NewMemoryRevocationStore(auditLog)
	cfg.BanStore = store.NewMemoryBanStore(auditLog)
	v := verify.NewVerifier(cfg, aikStore)
	if err := v.AddPolicy(verify.DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy(DefaultPolicy) failed: %v", err)
	}

	srv := &Server{verifier: v, addr: ":8443"}
	srv.apiKeys.Store(set)
	mux := http.NewServeMux()
	NewAPIHandler(mux, v, srv, auditLog, nil, nil, nil, "", "")
	return mux
}

func TestScopedKeysAuthorize(t *testing.T) {
	path := writeKeysFile(t, fmt.Sprintf(`keys:
  - key_sha256: %s
    role: admin
    tenants: ["acme"]
  - key_sha256: %s
    role: reader
    tenants: ["acme"]
`, keyHashHex("scoped-admin"), keyHashHex("scoped-reader")))
	set, err := LoadAPIKeysFile(path)
	if err != nil {
		t.Fatalf("LoadAPIKeysFile: %v", err)
	}
	mux := newScopedKeyAPI(t, set)

	do := func(method, target, key string) int {
		req := httptest.NewRequest(method, target, nil)
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr.Code
	}

	// scoped keys gate the reader tier:
	// no key = 401,
	// bad key = 403
	if code := do("GET", "/api/v1/stats", ""); code != http.StatusUnauthorized {
		t.Fatalf("no key on reader endpoint: %d, want 401", code)
	}
	if code := do("GET", "/api/v1/stats", "wrong"); code != http.StatusForbidden {
		t.Fatalf("bad key on reader endpoint: %d, want 403", code)
	}
	if code := do("GET", "/api/v1/stats", "scoped-reader"); code != http.StatusOK {
		t.Fatalf("scoped reader key on reader endpoint: %d, want 200", code)
	}
	// admin implies reader
	if code := do("GET", "/api/v1/stats", "scoped-admin"); code != http.StatusOK {
		t.Fatalf("scoped admin key on reader endpoint: %d, want 200", code)
	}

	// admin tier: reader key must not mutate.
	// Use ban scoped to the key's own tenant so the mutation is not blocked
	// by tenant scoping (revoking an unknown client would 404 in the acme tenant).
	ban := func(key string) int {
		body := `{"hardware_id":"` + strings.Repeat("ab", 32) + `","tenant":"acme","reason":"admin","actor":"ops"}`
		req := httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+key)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr.Code
	}
	if code := ban("scoped-reader"); code != http.StatusForbidden {
		t.Fatalf("reader key on admin endpoint: %d, want 403", code)
	}
	if code := ban("scoped-admin"); code != http.StatusCreated {
		t.Fatalf("admin key on admin endpoint: %d, want 201", code)
	}

	// scoped admin key may not act in a tenant outside its set
	foreignBody := `{"hardware_id":"` + strings.Repeat("cd", 32) + `","tenant":"other","reason":"admin","actor":"ops"}`
	req := httptest.NewRequest("POST", "/api/v1/bans", strings.NewReader(foreignBody))
	req.Header.Set("Authorization", "Bearer scoped-admin")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("admin ban into a foreign tenant: %d, want 403", rr.Code)
	}
}

func TestReloadAPIKeysKeepsOldSetOnFailure(t *testing.T) {
	path := writeKeysFile(t, fmt.Sprintf(`keys:
  - key_sha256: %s
    role: reader
    tenants: ["*"]
`, keyHashHex("k1")))

	srv := &Server{scopedKeysFile: path, log: logging.Nop()}
	set, err := LoadAPIKeysFile(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	srv.apiKeys.Store(set)

	// corrupt the file: reload must fail and keep the previous set
	if err := os.WriteFile(path, []byte("keys: []\n"), 0o600); err != nil {
		t.Fatalf("corrupt file: %v", err)
	}
	if err := srv.ReloadAPIKeys(); err == nil {
		t.Fatal("reload of an empty keys file succeeded")
	}
	if _, ok := srv.apiKeySet().Lookup("k1"); !ok {
		t.Fatal("failed reload dropped the previous key set")
	}

	// valid rewrite swaps the set
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`keys:
  - key_sha256: %s
    role: admin
    tenants: ["acme"]
`, keyHashHex("k2"))), 0o600); err != nil {
		t.Fatalf("rewrite file: %v", err)
	}
	if err := srv.ReloadAPIKeys(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := srv.apiKeySet().Lookup("k1"); ok {
		t.Fatal("old key survived a successful reload")
	}
	if p, ok := srv.apiKeySet().Lookup("k2"); !ok || p.Role != RoleAdmin {
		t.Fatalf("new key not resolvable after reload: %+v", p)
	}
}
