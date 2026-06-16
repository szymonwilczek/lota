// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
//go:build pkcs11

// PKCS#11-backed CA signing key.
//
// Built only with -tags pkcs11 (needs cgo and a PKCS#11 module at runtime).
// crypto11 returns a crypto.Signer whose private key never leaves the token;
// the issuance path is unchanged.

package main

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ThalesGroup/crypto11"
)

// newPKCS11Signer opens the configured token and returns a signer for the
// CA key plus a close function for the token session.
//
// It fails closed: the module, token and a key selector (label or id) are required,
// the PIN must be present, and a key that cannot be found is an error rather than
// a silent fallback.
func newPKCS11Signer(c pkcs11KeyConfig) (crypto.Signer, func() error, error) {
	if c.module == "" || c.token == "" {
		return nil, nil, fmt.Errorf("pkcs11: -ca-key-pkcs11-module and -ca-key-pkcs11-token are required")
	}
	if c.label == "" && c.id == "" {
		return nil, nil, fmt.Errorf("pkcs11: a key selector is required (-ca-key-pkcs11-label or -ca-key-pkcs11-id)")
	}
	if c.pin == "" {
		return nil, nil, fmt.Errorf("pkcs11: token PIN is required in LOTA_CA_PKCS11_PIN")
	}

	var id []byte
	if c.id != "" {
		var err error
		id, err = hex.DecodeString(c.id)
		if err != nil {
			return nil, nil, fmt.Errorf("pkcs11: -ca-key-pkcs11-id is not hex: %w", err)
		}
	}
	var label []byte
	if c.label != "" {
		label = []byte(c.label)
	}

	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       c.module,
		TokenLabel: c.token,
		Pin:        c.pin,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("pkcs11: open token %q via %s: %w", c.token, c.module, err)
	}

	signer, err := ctx.FindKeyPair(id, label)
	if err != nil {
		return nil, nil, errors.Join(fmt.Errorf("pkcs11: find key pair: %w", err), ctx.Close())
	}
	if signer == nil {
		return nil, nil, errors.Join(
			fmt.Errorf("pkcs11: no key pair matches the given token, label or id"), ctx.Close())
	}
	return signer, ctx.Close, nil
}
