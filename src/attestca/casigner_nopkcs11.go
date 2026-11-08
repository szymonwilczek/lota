// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
//go:build !pkcs11

package main

import (
	"crypto"
	"errors"
)

// newPKCS11Signer always refuses: this build has no PKCS#11 support.
func newPKCS11Signer(pkcs11KeyConfig) (crypto.Signer, func() error, error) {
	return nil, nil, errors.New(
		"this lota-attest-ca was built without PKCS#11 support; " +
			"build one with `make attest-ca GO_TAGS=pkcs11`, " +
			"or run the -hsm tag of the attestca image, which carries it")
}
