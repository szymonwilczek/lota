// SPDX-License-Identifier: MIT
// LOTA Verifier - Nonce/freshness verification module
//
// Ensures attestation reports are fresh and not replays.
// The nonce is included in TPM quote's extraData field.
//
// Anti-replay protections (for now, i keep track of them here):
//   - One-time nonce consumption (generate -> verify -> delete)
//   - Nonce TTL expiration (configurable lifetime)
//   - Client binding (nonce tied to specific client ID)
//   - Per-client rate limiting (prevents challenge flooding)
//   - Monotonic counter per client (detects reordering)
//   - Used nonce history (prevents reuse after restart)
//   - TPMS_ATTEST nonce binding (cryptographic proof from TPM)

package verify

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// abstracts used nonce storage for anti-replay protection
// memory backend is used by default; SQLite backend provides persistence
// across verifier restarts for production deployments
type UsedNonceBackend interface {
	// stores a nonce key as used at the given time
	Record(nonceKey string, usedAt time.Time) error

	// returns true if the nonce key has been recorded as used
	Contains(nonceKey string) bool

	// returns the number of stored used nonces
	Count() int

	// removes entries with usedAt older than the given cutoff
	Cleanup(olderThan time.Time)
}

// implements UsedNonceBackend using an in-memory map
// bounded by maxSize - evicts oldest entries when capacity is reached
type memoryUsedNonceBackend struct {
	nonces  map[string]time.Time
	maxSize int
}

func newMemoryUsedNonceBackend(maxSize int) *memoryUsedNonceBackend {
	return &memoryUsedNonceBackend{
		nonces:  make(map[string]time.Time, maxSize),
		maxSize: maxSize,
	}
}

func (m *memoryUsedNonceBackend) Record(nonceKey string, usedAt time.Time) error {
	// evict oldest if at capacity
	if len(m.nonces) >= m.maxSize {
		var oldestKey string
		var oldestTime time.Time

		for k, t := range m.nonces {
			if oldestTime.IsZero() || t.Before(oldestTime) {
				oldestKey = k
				oldestTime = t
			}
		}

		if oldestKey != "" {
			delete(m.nonces, oldestKey)
		}
	}

	m.nonces[nonceKey] = usedAt
	return nil
}

func (m *memoryUsedNonceBackend) Contains(nonceKey string) bool {
	_, exists := m.nonces[nonceKey]
	return exists
}

func (m *memoryUsedNonceBackend) Count() int {
	return len(m.nonces)
}

func (m *memoryUsedNonceBackend) Cleanup(olderThan time.Time) {
	for key, usedAt := range m.nonces {
		if usedAt.Before(olderThan) {
			delete(m.nonces, key)
		}
	}
}

// manages outstanding challenges and prevents replay attacks
type NonceStore struct {
	mu       sync.RWMutex
	pending  map[string]nonceEntry
	lifetime time.Duration

	// anti-replay: pluggable backend for used nonce history
	usedBackend UsedNonceBackend

	// per-client rate limiting
	clientChallenges map[string]clientState
	maxPending       int           // max outstanding challenges per client
	rateLimitWindow  time.Duration // rate limit window duration
	rateLimitMax     int           // max challenges per window

	// stop channel for cleanupLoop goroutine
	stopCh chan struct{}
}

type nonceEntry struct {
	nonce     [types.NonceSize]byte
	createdAt time.Time
	clientID  string // optional: bind nonce to specific client
	counter   uint64 // monotonic counter for ordering
}

// tracks per-client challenge state for rate limiting
type clientState struct {
	pendingCount    int       // outstanding challenges
	windowStart     time.Time // current rate limit window start
	windowCount     int       // challenges issued in current window
	attestCounter   uint64    // monotonic attestation counter
	lastAttestation time.Time // time of last successful attestation
}

// configuration for nonce store
type NonceStoreConfig struct {
	// how long a nonce remains valid
	Lifetime time.Duration

	// max outstanding challenges per client
	MaxPendingPerClient int

	// rate limit: max challenges per window
	RateLimitMax int

	// rate limit window duration
	RateLimitWindow time.Duration

	// max used nonces to remember (memory backend only)
	UsedNonceHistory int

	// pluggable used nonce backend (nil = in-memory with UsedNonceHistory cap)
	UsedBackend UsedNonceBackend
}

// returns sensible defaults
func DefaultNonceStoreConfig() NonceStoreConfig {
	return NonceStoreConfig{
		Lifetime:            5 * time.Minute,
		MaxPendingPerClient: 5,
		RateLimitMax:        30,
		RateLimitWindow:     time.Minute,
		UsedNonceHistory:    10000,
	}
}

// creates a new nonce store from config
// IMPORTANT: Nonces older than lifetime are automatically rejected
func NewNonceStoreFromConfig(cfg NonceStoreConfig) *NonceStore {
	backend := cfg.UsedBackend
	if backend == nil {
		backend = newMemoryUsedNonceBackend(cfg.UsedNonceHistory)
	}

	ns := &NonceStore{
		pending:          make(map[string]nonceEntry),
		lifetime:         cfg.Lifetime,
		usedBackend:      backend,
		clientChallenges: make(map[string]clientState),
		maxPending:       cfg.MaxPendingPerClient,
		rateLimitWindow:  cfg.RateLimitWindow,
		rateLimitMax:     cfg.RateLimitMax,
		stopCh:           make(chan struct{}),
	}

	go ns.cleanupLoop()

	return ns
}

// creates a new nonce store with specified lifetime
func NewNonceStore(lifetime time.Duration) *NonceStore {
	cfg := DefaultNonceStoreConfig()
	cfg.Lifetime = lifetime
	return NewNonceStoreFromConfig(cfg)
}

// creates a new challenge with random nonce
// returns challenge ready to send to agent
func (ns *NonceStore) GenerateChallenge(clientID string, pcrMask uint32) (*types.Challenge, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	// enforce per-client rate limiting
	if err := ns.checkRateLimit(clientID); err != nil {
		return nil, err
	}

	var nonce [types.NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	key := hex.EncodeToString(nonce[:])

	// paranoid check: ensure nonce was never used before
	if ns.usedBackend.Contains(key) {
		return nil, errors.New("nonce collision with used nonce - entropy failure")
	}

	// get and increment client counter
	cs := ns.clientChallenges[clientID]
	cs.attestCounter++
	cs.pendingCount++
	ns.clientChallenges[clientID] = cs

	ns.pending[key] = nonceEntry{
		nonce:     nonce,
		createdAt: time.Now(),
		clientID:  clientID,
		counter:   cs.attestCounter,
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

	key := hex.EncodeToString(report.TPM.Nonce[:])

	// check used nonce history first (detects replays after restart)
	if ns.usedBackend.Contains(key) {
		return errors.New("nonce already used - replay attack detected")
	}

	entry, exists := ns.pending[key]
	if !exists {
		return errors.New("unknown nonce - possible replay attack")
	}

	// check lifetime
	if time.Since(entry.createdAt) > ns.lifetime {
		delete(ns.pending, key)
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
	// compute binding nonce = SHA-256(challenge_nonce || hardware_id)
	// to verify that the TPM quote is bound to the reported hardware identity
	if report.TPM.AttestSize == 0 {
		return errors.New("no attestation data - cannot verify nonce binding")
	}

	bindingNonce := ComputeBindingNonce(entry.nonce, report)
	attestData := report.TPM.AttestData[:report.TPM.AttestSize]
	if err := VerifyNonceInAttest(attestData, bindingNonce[:]); err != nil {
		return fmt.Errorf("TPMS_ATTEST nonce verification failed: %w", err)
	}

	// all checks passed, consume nonce
	delete(ns.pending, key)

	// record as used
	ns.usedBackend.Record(key, time.Now())

	// update client state
	if cs, ok := ns.clientChallenges[entry.clientID]; ok {
		cs.pendingCount--
		if cs.pendingCount < 0 {
			cs.pendingCount = 0
		}
		cs.lastAttestation = time.Now()
		ns.clientChallenges[entry.clientID] = cs
	}

	return nil
}

// enforces per-client challenge rate limiting
func (ns *NonceStore) checkRateLimit(clientID string) error {
	cs, exists := ns.clientChallenges[clientID]

	if exists {
		// check outstanding challenge limit
		if cs.pendingCount >= ns.maxPending {
			return fmt.Errorf("too many outstanding challenges for client %s (%d/%d)",
				clientID, cs.pendingCount, ns.maxPending)
		}

		// check rate limit window
		now := time.Now()
		if now.Sub(cs.windowStart) > ns.rateLimitWindow {
			// reset window
			cs.windowStart = now
			cs.windowCount = 0
			ns.clientChallenges[clientID] = cs
		} else if cs.windowCount >= ns.rateLimitMax {
			return fmt.Errorf("rate limit exceeded for client %s (%d/%d per %v)",
				clientID, cs.windowCount, ns.rateLimitMax, ns.rateLimitWindow)
		}

		// increment window counter
		cs.windowCount++
		ns.clientChallenges[clientID] = cs
	} else {
		// new client - initialize state
		ns.clientChallenges[clientID] = clientState{
			windowStart: time.Now(),
			windowCount: 1,
		}
	}

	return nil
}

// stops the background cleanup goroutine
func (ns *NonceStore) Close() {
	close(ns.stopCh)
}

// periodically removes expired nonces
func (ns *NonceStore) cleanupLoop() {
	ticker := time.NewTicker(ns.lifetime / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ns.cleanup()
		case <-ns.stopCh:
			return
		}
	}
}

func (ns *NonceStore) cleanup() {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	now := time.Now()

	// clean expired pending nonces
	for key, entry := range ns.pending {
		if now.Sub(entry.createdAt) > ns.lifetime {
			// decrement client pending count
			if cs, ok := ns.clientChallenges[entry.clientID]; ok {
				cs.pendingCount--
				if cs.pendingCount < 0 {
					cs.pendingCount = 0
				}
				ns.clientChallenges[entry.clientID] = cs
			}
			delete(ns.pending, key)
		}
	}

	// clean old used nonce entries via backend
	usedCutoff := now.Add(-ns.lifetime * 3) // keep used 3x longer than lifetime
	ns.usedBackend.Cleanup(usedCutoff)

	// evict stale client entries to bound map growth
	clientCutoff := now.Add(-ns.lifetime * 3)
	for id, cs := range ns.clientChallenges {
		if cs.pendingCount <= 0 && cs.lastAttestation.Before(clientCutoff) {
			delete(ns.clientChallenges, id)
		}
	}
}

// returns number of outstanding challenges (for monitoring)
func (ns *NonceStore) PendingCount() int {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return len(ns.pending)
}

// returns number of used nonces in history (for monitoring)
func (ns *NonceStore) UsedCount() int {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.usedBackend.Count()
}

// returns per-client attestation counter (for monitoring)
func (ns *NonceStore) ClientCounter(clientID string) uint64 {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	if cs, ok := ns.clientChallenges[clientID]; ok {
		return cs.attestCounter
	}
	return 0
}

// returns per-client pending challenge count
func (ns *NonceStore) ClientPendingCount(clientID string) int {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	if cs, ok := ns.clientChallenges[clientID]; ok {
		return cs.pendingCount
	}
	return 0
}

// returns time of client's last successful attestation
func (ns *NonceStore) ClientLastAttestation(clientID string) time.Time {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	if cs, ok := ns.clientChallenges[clientID]; ok {
		return cs.lastAttestation
	}
	return time.Time{}
}

// returns all client IDs with active challenge state
func (ns *NonceStore) ListActiveClients() []string {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	clients := make([]string, 0, len(ns.clientChallenges))
	for id := range ns.clientChallenges {
		clients = append(clients, id)
	}
	return clients
}
