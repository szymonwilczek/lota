// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Attestation CA - CA signing key source selection
//
// CA key is loaded as a crypto.Signer.
//
// Two sources are supported:
// - on-disk PKCS#8 PEM (the dev-only fallback, handled inline in run)
// - PKCS#11 token (HSM/SoftHSM)
//
// PKCS#11 path needs cgo and a PKCS#11 module, so it is compiled in only
// under the "pkcs11" build tag; the default build is pure-Go and rejects
// a PKCS#11 request with a clear error.
//
// newPKCS11Signer has a stub (casigner_nopkcs11.go) and a real implementation
// (casigner_pkcs11.go) selected by that tag.

package main

import "strings"

// pkcs11KeyConfig selects a CA signing key held in a PKCS#11 token.
// The PIN is taken from the environment, never a flag, so it does not
// land in the process argument list.
type pkcs11KeyConfig struct {
	module string // path to the PKCS#11 module (.so)
	token  string // token label the key lives on
	label  string // key object label (CKA_LABEL)
	id     string // optional key object id (CKA_ID), hex-encoded
	pin    string // user PIN, from LOTA_CA_PKCS11_PIN
}

// requested reports whether a PKCS#11 key source was asked for.
//
// Any of the four flags counts, not only the module.
// Three of them name *which* key to sign with, so an operator who gives one
// has asked for a token as plainly as one who gives the module.
func (c pkcs11KeyConfig) requested() bool {
	return c.module != "" || c.token != "" || c.label != "" || c.id != ""
}

// flagsGiven names the PKCS#11 flags this configuration carries, in the order
// they are documented, for an error message that can point at what was typed.
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
