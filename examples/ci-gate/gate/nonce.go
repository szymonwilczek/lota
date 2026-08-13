// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"sync"
	"time"
)

// Errors a nonce lookup can produce.
// Caller reports them verbatim, because "unknown" and "expired" mean different
// things to whoever is debugging a failing pipeline.
var (
	errUnknownNonce = errors.New("nonce was not issued by this gate")
	errStaleNonce   = errors.New("nonce expired before the token arrived")
)

// nonceStore hands out single-use challenges.
//
// Nonce is the whole reason a token presented to this gate cannot be replayed:
// it is generated here, it goes into the TPM quote, and it is consumed on first
// use whether the verification that follows succeeds or fails.
// Failed attempt that left its nonce spendable would let a caller grind against
// the gate with one captured token.
type nonceStore struct {
	mu     sync.Mutex
	issued map[[32]byte]time.Time
	ttl    time.Duration
	now    func() time.Time
}

func newNonceStore(ttl time.Duration) *nonceStore {
	return &nonceStore{
		issued: make(map[[32]byte]time.Time),
		ttl:    ttl,
		now:    time.Now,
	}
}

// issue returns a fresh challenge and the moment it stops being valid
func (s *nonceStore) issue() ([32]byte, time.Time, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, time.Time{}, err
	}

	expires := s.now().Add(s.ttl)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked()
	s.issued[nonce] = expires

	return nonce, expires, nil
}

// consume removes a nonce and reports whether it was live at that moment.
// nonce is spent by the attempt, not by the verdict.
func (s *nonceStore) consume(nonce [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	expires, ok := s.issued[nonce]
	if !ok {
		return errUnknownNonce
	}
	delete(s.issued, nonce)

	if !s.now().Before(expires) {
		return errStaleNonce
	}
	return nil
}

func (s *nonceStore) evictExpiredLocked() {
	now := s.now()
	for nonce, expires := range s.issued {
		if !now.Before(expires) {
			delete(s.issued, nonce)
		}
	}
}

func (s *nonceStore) outstanding() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.issued)
}

// constantTimeEqual keeps a caller from learning how much of a nonce it guessed
// correctly by timing the comparison.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
