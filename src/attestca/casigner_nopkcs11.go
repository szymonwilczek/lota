// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
//go:build !pkcs11

// Default (pure-Go) build:
// PKCS#11 support is not compiled in.
// PKCS#11 key request fails closed with a build hint
// rather than silently falling back to an on-disk key.

package main

import (
	"crypto"
	"errors"
)

func newPKCS11Signer(pkcs11KeyConfig) (crypto.Signer, func() error, error) {
	return nil, nil, errors.New(
		"this lota-attest-ca was built without PKCS#11 support; rebuild with -tags pkcs11")
}
