// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package main

import "strings"

// pkcs11KeyConfig selects the CA key on a PKCS#11 token.
// The PIN comes from LOTA_CA_PKCS11_PIN, never from argv.
type pkcs11KeyConfig struct {
	module string
	token  string
	label  string // CKA_LABEL
	id     string // CKA_ID, hex
	pin    string
}

// requested reports whether any of the four PKCS#11 flags is set.
func (c pkcs11KeyConfig) requested() bool {
	return c.module != "" || c.token != "" || c.label != "" || c.id != ""
}

// flagsGiven lists the PKCS#11 flags that are set, for error messages.
func (c pkcs11KeyConfig) flagsGiven() string {
	var given []string

	for _, f := range []struct {
		name  string
		value string
	}{
		{"-ca-key-pkcs11-module", c.module},
		{"-ca-key-pkcs11-token", c.token},
		{"-ca-key-pkcs11-label", c.label},
		{"-ca-key-pkcs11-id", c.id},
	} {
		if f.value != "" {
			given = append(given, f.name)
		}
	}

	return strings.Join(given, ", ")
}
