// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package server

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

// FuzzVerifyToken drives the full token verification path -- wire parse plus
// signature, nonce, and expiry checks -- against a fixed AIK public key with
// arbitrary token bytes. It must never panic and must return claims exactly
// when it returns no error.
func FuzzVerifyToken(f *testing.F) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("AIK key: %v", err)
	}
	aikPub := &priv.PublicKey

	var nonce [32]byte
	validUntil := uint64(time.Now().Add(time.Hour).Unix())
	validTok := buildTestToken(f, priv, validUntil, 0, nonce, 0, nil)

	f.Add(validTok)
	f.Add([]byte{})
	f.Add([]byte{0x4C, 0x4F, 0x54, 0x4B})

	f.Fuzz(func(t *testing.T, data []byte) {
		claims, err := VerifyToken(data, aikPub, nil)
		if (err == nil) != (claims != nil) {
			t.Fatalf("contract violated: err=%v claims=%v", err, claims)
		}
	})
}
