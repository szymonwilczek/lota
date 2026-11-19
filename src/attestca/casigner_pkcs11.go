// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package main

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ThalesGroup/crypto11"
)

// newPKCS11Signer opens the token and returns the CA key's signer and the
// function that closes the token. The module, the token, a label or an id,
// and the PIN are required; a key that is not found is an error.
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

	pairs, err := ctx.FindKeyPairs(id, label)
	if err != nil {
		return nil, nil, errors.Join(fmt.Errorf("pkcs11: find key pair: %w", err), ctx.Close())
	}
	signer, err := pickKeyPair(pairs, c)
	if err != nil {
		return nil, nil, errors.Join(err, ctx.Close())
	}
	return signer, ctx.Close, nil
}

// pickKeyPair returns the one key pair the selector names,
// and refuses none or several: the CA certificate is bound to a single key.
func pickKeyPair[S any](pairs []S, c pkcs11KeyConfig) (S, error) {
	var none S

	switch len(pairs) {
	case 1:
		return pairs[0], nil
	case 0:
		return none, fmt.Errorf("pkcs11: no key pair on token %q "+
			"matches label %q, id %q", c.token, c.label, c.id)
	default:
		return none, fmt.Errorf("pkcs11: %d key pairs on token %q "+
			"match label %q, id %q; %s", len(pairs), c.token,
			c.label, c.id, narrowKeyPair(c))
	}
}

// narrowKeyPair names the selector that is left to give,
// and an id of their own for pairs that share it too.
func narrowKeyPair(c pkcs11KeyConfig) string {
	const own = ", or give each its own id"

	switch {
	case c.id == "":
		return "select one with -ca-key-pkcs11-id" + own
	case c.label == "":
		return "select one with -ca-key-pkcs11-label" + own
	default:
		return "they share that label and id; give each its own id"
	}
}
