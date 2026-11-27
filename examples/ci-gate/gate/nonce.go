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

// Errors consume returns; the gate passes them to the caller verbatim.
var (
	errUnknownNonce = errors.New("nonce was not issued by this gate")
	errStaleNonce   = errors.New("nonce expired before the token arrived")
)

// nonceStore hands out single-use challenges. consume spends a nonce whatever
// the verdict that follows, so a captured token gets one attempt.
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

// issue returns a fresh challenge and its expiry.
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

// consume removes a nonce and reports whether it was live.
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

// evictExpiredLocked drops a nonce one TTL after it expired, so a token
// late by less than that still reads as expired, not as unknown.
func (s *nonceStore) evictExpiredLocked() {
	now := s.now()
	for nonce, expires := range s.issued {
		if now.Sub(expires) >= s.ttl {
			delete(s.issued, nonce)
		}
	}
}

// constantTimeEqual compares without leaking through timing how many
// leading bytes match.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
