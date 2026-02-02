// SPDX-License-Identifier: MIT
// LOTA Verifier - Nonce/freshness verification module
//
// Ensures attestation reports are fresh and not replays.
// The nonce is included in TPM quote's extraData field.

package verify

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// manages outstanding challenges and prevents replay attacks
type NonceStore struct {
	mu       sync.RWMutex
	pending  map[string]nonceEntry
	lifetime time.Duration
}

type nonceEntry struct {
	nonce     [types.NonceSize]byte
	createdAt time.Time
	clientID  string // optional: bind nonce to specific client
}

// creates a new nonce store with specified lifetime
// IMPORTANT: Nonces older than lifetime are automatically rejected
func NewNonceStore(lifetime time.Duration) *NonceStore {
	ns := &NonceStore{
		pending:  make(map[string]nonceEntry),
		lifetime: lifetime,
	}

	go ns.cleanupLoop()

	return ns
}

// creates a new challenge with random nonce
// returns challenge ready to send to agent
func (ns *NonceStore) GenerateChallenge(clientID string, pcrMask uint32) (*types.Challenge, error) {
	var nonce [types.NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	ns.mu.Lock()
	defer ns.mu.Unlock()

	// nonce as key (TO THINK ON: hex would be cleaner but this is faster)
	key := string(nonce[:])
	ns.pending[key] = nonceEntry{
		nonce:     nonce,
		createdAt: time.Now(),
		clientID:  clientID,
	}

	return &types.Challenge{
		Magic:   types.ReportMagic,
		Version: types.ReportVersion,
		Nonce:   nonce,
		PCRMask: pcrMask,
		Flags:   0,
	}, nil
}

// checks if the nonce in report matches an outstanding challenge
// nonce is consumed (one-time use) to prevent replay
//
// SECURITY: This verifies TWO things:
// - report.TPM.Nonce matches stored challenge
// - Nonce inside TPMS_ATTEST (signed by TPM) matches stored challenge
func (ns *NonceStore) VerifyNonce(report *types.AttestationReport, clientID string) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	key := string(report.TPM.Nonce[:])
	entry, exists := ns.pending[key]

	if !exists {
		return errors.New("unknown nonce - possible replay attack")
	}

	// remove nonce (one-time use)
	delete(ns.pending, key)

	// check lifetime
	if time.Since(entry.createdAt) > ns.lifetime {
		return errors.New("nonce expired")
	}

	// verify client binding
	if entry.clientID != "" && entry.clientID != clientID {
		return errors.New("nonce bound to different client")
	}

	// verify nonce matches whats in report header
	if !bytes.Equal(entry.nonce[:], report.TPM.Nonce[:]) {
		return errors.New("nonce mismatch in report header")
	}

	// verify nonce inside tpms_attest (signed by tpm)
	if report.TPM.AttestSize == 0 {
		return errors.New("no attestation data - cannot verify nonce binding")
	}

	attestData := report.TPM.AttestData[:report.TPM.AttestSize]
	if err := VerifyNonceInAttest(attestData, entry.nonce[:]); err != nil {
		return fmt.Errorf("TPMS_ATTEST nonce verification failed: %w", err)
	}

	return nil
}

// periodically removes expired nonces
func (ns *NonceStore) cleanupLoop() {
	ticker := time.NewTicker(ns.lifetime / 2)
	defer ticker.Stop()

	for range ticker.C {
		ns.cleanup()
	}
}

func (ns *NonceStore) cleanup() {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	now := time.Now()
	for key, entry := range ns.pending {
		if now.Sub(entry.createdAt) > ns.lifetime {
			delete(ns.pending, key)
		}
	}
}

// returns number of outstanding challenges (for monitoring)
func (ns *NonceStore) PendingCount() int {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return len(ns.pending)
}

// checks report timestamp is recent
// this is an additional freshness check beyond nonce
func VerifyTimestamp(report *types.AttestationReport, maxAge time.Duration) error {
	reportTime := time.Unix(int64(report.Header.Timestamp), int64(report.Header.TimestampNs))
	age := time.Since(reportTime)

	if age < -time.Minute {
		// time traveller from the future
		return errors.New("report timestamp in future")
	}

	if age > maxAge {
		return errors.New("report timestamp too old")
	}

	return nil
}
