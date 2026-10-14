// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// CA key source selection: which flag combinations the CA refuses to start on.
//
// The CA signing key is the root of every trust decision the fleet makes,
// so the one thing this must never do is take the on-disk key when the operator
// asked for a token. Every case below stops in run's validation, before a file
// is read or a listener is opened.

package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

// A configuration whose only defect is the one under test: every other
// required flag is present, so an error naming something else means the case
// reached further than it should have.
func hsmConfig(mutate func(*runConfig)) *runConfig {
	cfg := &runConfig{
		caCertPath:   "/nonexistent/ca.crt",
		tlsCertPath:  "/nonexistent/tls.crt",
		tlsKeyPath:   "/nonexistent/tls.key",
		pseudonymKey: "/nonexistent/pseudonym.key",
		ekRootBundle: "/nonexistent/ek-roots",
	}
	mutate(cfg)
	return cfg
}

func runErr(t *testing.T, cfg *runConfig) string {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := run("127.0.0.1:0", cfg, log)
	if err == nil {
		t.Fatal("expected a refusal, the CA started")
	}
	return err.Error()
}

// Each PKCS#11 flag names the key the operator meant to sign with, so each of
// them conflicts with -ca-key.
func TestOnDiskKeyConflictsWithEveryPKCS11Flag(t *testing.T) {
	cases := map[string]func(*pkcs11KeyConfig){
		"-ca-key-pkcs11-module": func(p *pkcs11KeyConfig) { p.module = "/usr/lib64/softhsm/libsofthsm2.so" },
		"-ca-key-pkcs11-token":  func(p *pkcs11KeyConfig) { p.token = "lota-ca" },
		"-ca-key-pkcs11-label":  func(p *pkcs11KeyConfig) { p.label = "lota-ca-key" },
		"-ca-key-pkcs11-id":     func(p *pkcs11KeyConfig) { p.id = "a1b2" },
	}

	for flag, set := range cases {
		t.Run(flag, func(t *testing.T) {
			cfg := hsmConfig(func(c *runConfig) {
				c.caKeyPath = "/nonexistent/ca.key"
				set(&c.pkcs11)
			})
			got := runErr(t, cfg)
			if !strings.Contains(got, "not both") {
				t.Fatalf("%s with -ca-key was not refused as a conflict: %s",
					flag, got)
			}
		})
	}
}

// A selector without a module cannot open anything, so it is a typo or a forgotten
// flag. Refuse it by name instead of ignoring it.
func TestSelectorWithoutModuleIsRefusedByName(t *testing.T) {
	cases := map[string]func(*pkcs11KeyConfig){
		"-ca-key-pkcs11-token": func(p *pkcs11KeyConfig) { p.token = "lota-ca" },
		"-ca-key-pkcs11-label": func(p *pkcs11KeyConfig) { p.label = "lota-ca-key" },
		"-ca-key-pkcs11-id":    func(p *pkcs11KeyConfig) { p.id = "a1b2" },
	}

	for flag, set := range cases {
		t.Run(flag, func(t *testing.T) {
			cfg := hsmConfig(func(c *runConfig) { set(&c.pkcs11) })
			got := runErr(t, cfg)
			if !strings.Contains(got, "-ca-key-pkcs11-module") {
				t.Fatalf("%s without a module did not name the missing module flag: %s",
					flag, got)
			}
			if !strings.Contains(got, flag) {
				t.Fatalf("%s without a module did not name the flag that was given: %s",
					flag, got)
			}
		})
	}
}

// The on-disk key stays supported for bring-up, so a CA with neither source
// still says which flag it wants.
func TestNeitherKeySourceNamesCaKey(t *testing.T) {
	got := runErr(t, hsmConfig(func(*runConfig) {}))
	if !strings.Contains(got, "missing required -ca-key") {
		t.Fatalf("a CA with no key source did not ask for -ca-key: %s", got)
	}
}
