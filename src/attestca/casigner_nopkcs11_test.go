// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
//go:build !pkcs11

package main

import (
	"strings"
	"testing"
)

// A build without PKCS#11 refuses a token key naming both fixes: the host
// rebuild with GO_TAGS=pkcs11 and, inside a container, the -hsm image.
func TestPKCS11RefusalNamesAvailableRoads(t *testing.T) {
	_, _, err := newPKCS11Signer(pkcs11KeyConfig{
		module: "/hsm/module.so",
		token:  "lota-ca",
		label:  "lota-ca-key",
		pin:    "1234",
	})
	if err == nil {
		t.Fatal("a build without PKCS#11 support accepted a token key")
	}

	msg := err.Error()
	for _, want := range []string{
		"built without PKCS#11 support",
		"GO_TAGS=pkcs11",
		"-hsm",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not name %q: %s", want, msg)
		}
	}
}
