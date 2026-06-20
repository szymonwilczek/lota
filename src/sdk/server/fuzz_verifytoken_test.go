// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// FuzzVerifyToken drives the full token verification path.
// Mutating raw token bytes can never forge the RSA quote signature,
// and the previous harness additionally passed a nil expected-nonce,
// so every input was rejected at the ErrInvalidArg guard before any
// verification ran.
//
// Instead, fuzz the claim fields (expiry offset, flags, PCR mask, nonce)
// and RE-SIGN a self-consistent token with the test AIK, supplying the
// matching expected nonce.
// Every such token passes the signature, runtime-digest, PCR-mask and
// nonce-binding gates by construction, so the verifier's decision is
// governed only by the temporal policy.
func FuzzVerifyToken(f *testing.F) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("AIK key: %v", err)
	}
	aikPub := &priv.PublicKey

	// seeds: valid in-window token, expired one, far-future one
	f.Add([]byte("seed-nonce"), int64(120), uint32(0x07), uint32(0x4001))
	f.Add([]byte("expired"), int64(-3600), uint32(0), uint32(0))
	f.Add([]byte("future"), int64(10*365*24*3600), uint32(0), uint32(0))

	// deadband (seconds) around each temporal boundary;
	// inside it the wall-clock advance between building and verifying
	// could flip the verdict, so the exact class is not asserted there
	const guard = int64(5)

	f.Fuzz(func(t *testing.T, nonceSeed []byte, offset int64, flags, pcrMask uint32) {
		nonce := sha256.Sum256(nonceSeed)

		now := time.Now().Unix()
		validUntil := uint64(0)
		// offset is the token lifetime relative to now;
		// clamp to a non-negative absolute timestamp
		if abs := now + offset; abs > 0 {
			validUntil = uint64(abs)
		}

		tok := buildTestToken(t, priv, validUntil, flags, nonce, pcrMask, nil)
		claims, err := VerifyToken(tok, aikPub, nonce[:])

		// self-consistent token always yields claims, even on a temporal
		// rejection (the verifier returns claims alongside ErrExpired /
		// ErrFutureToken)
		if claims == nil {
			t.Fatalf("re-signed token produced no claims: %v", err)
		}

		switch {
		case validUntil > 0 && now-int64(validUntil) > guard:
			if !errors.Is(err, ErrExpired) || !claims.Expired {
				t.Fatalf("expired token (validUntil=%d now=%d) not flagged: err=%v expired=%v",
					validUntil, now, err, claims.Expired)
			}
		case validUntil > 0 && int64(validUntil)-now > DefaultMaxTokenAge+MaxClockSkew+guard:
			if !errors.Is(err, ErrFutureToken) {
				t.Fatalf("implausibly-future token (validUntil=%d) not rejected: err=%v", validUntil, err)
			}
		case validUntil == 0 || (int64(validUntil)-now > guard && int64(validUntil)-now < DefaultMaxTokenAge+MaxClockSkew-guard):
			if err != nil {
				t.Fatalf("valid in-window token rejected: %v", err)
			}
		default:
			// near a temporal boundary;
			// only the no-panic / claims invariant above is asserted
		}
	})
}
