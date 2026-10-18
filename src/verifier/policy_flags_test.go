// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// writePolicyFile drops a policy carrying a PCR pin, so nothing but the keys
// under test decides whether the document loads.
func writePolicyFile(t *testing.T, name, tenant string) string {
	t.Helper()

	body := "name: " + name + "\npcrs:\n  7: \"" + strings.Repeat("aa", 32) + "\"\n"
	if tenant != "" {
		body += "tenant: " + tenant + "\n"
	}

	path := filepath.Join(t.TempDir(), name+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func policyTestVerifier(t *testing.T) (*verify.Verifier, *bytes.Buffer, *slog.Logger) {
	t.Helper()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return verify.NewVerifier(verify.DefaultConfig(), store.NewMemoryStore()), &logs, logger
}

// Per-tenant policy needs a second policy to bind against: a single --policy
// left the tenant map with nothing in it, so every tenant on the instance was
// verified against the one document the flag could carry.
func TestLoadPoliciesBindsATenantToItsOwnPolicy(t *testing.T) {
	verifier, _, logger := policyTestVerifier(t)

	paths := []string{
		writePolicyFile(t, "fleet-base", ""),
		writePolicyFile(t, "acme-strict", "acme"),
	}
	if err := loadPolicies(logger, verifier, paths); err != nil {
		t.Fatalf("loadPolicies: %v", err)
	}

	if got := len(verifier.ListPolicies()); got != 2 {
		t.Fatalf("loaded %d policies, want 2", got)
	}

	active, ok := verifier.ActivePolicyConfig()
	if !ok || active.Name != "fleet-base" {
		t.Fatalf("active policy = %+v, want the first file", active)
	}
	if got := verifier.TenantBindings()["acme"]; got != "acme-strict" {
		t.Fatalf("tenant acme bound to %q, want acme-strict", got)
	}
}

// A second document that binds no tenant is unreachable: the active policy is
// the first file, and nothing else routes to it.
func TestLoadPoliciesWarnsAboutAPolicyNoClientCanReach(t *testing.T) {
	verifier, logs, logger := policyTestVerifier(t)

	paths := []string{
		writePolicyFile(t, "fleet-base", ""),
		writePolicyFile(t, "orphan", ""),
	}
	if err := loadPolicies(logger, verifier, paths); err != nil {
		t.Fatalf("loadPolicies: %v", err)
	}

	reported := []string{}
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "no client can reach it") {
			reported = append(reported, line)
		}
	}
	if len(reported) != 1 {
		t.Fatalf("expected exactly one unreachable policy, got %v", reported)
	}
	if !strings.Contains(reported[0], "policy=orphan") {
		t.Fatalf("the wrong policy was reported as unreachable: %s", reported[0])
	}
}

// Two documents under one name leave one policy loaded, and when the name is
// the active one the second file has silently replaced what the fleet verifies
// against.
func TestLoadPoliciesRefusesTwoFilesUnderOneName(t *testing.T) {
	verifier, _, logger := policyTestVerifier(t)

	paths := []string{
		writePolicyFile(t, "fleet-base", ""),
		writePolicyFile(t, "fleet-base", "acme"),
	}
	if err := loadPolicies(logger, verifier, paths); err == nil {
		t.Fatal("expected a duplicate policy name to be refused")
	}
}

// One unreadable file stops startup rather than leaving the fleet on whichever
// documents happened to load before it.
func TestLoadPoliciesStopsOnAFileItCannotLoad(t *testing.T) {
	verifier, _, logger := policyTestVerifier(t)

	paths := []string{
		writePolicyFile(t, "fleet-base", ""),
		filepath.Join(t.TempDir(), "missing.yaml"),
	}
	if err := loadPolicies(logger, verifier, paths); err == nil {
		t.Fatal("expected a missing policy file to stop the load")
	}
}
