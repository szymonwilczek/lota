// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Nonce/freshness verification module

package verify

import (
	"container/list"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

const maxNonceGenerationAttempts = 8

// UsedNonceBackend holds the used-nonce history. Implementations must be safe
// for concurrent use: NonceStore calls them without its mutex.
type UsedNonceBackend interface {
	Record(nonceKey string, usedAt time.Time) error
	Contains(nonceKey string) (bool, error)
	Count() int

	// Cleanup drops the entries used before olderThan.
	Cleanup(olderThan time.Time)
}

// RoutedUsedNonceBackend keeps used nonces in the partition a route key picks.
// NonceStore routes by the client identity, so a replay's record and lookup
// land in the same partition.
type RoutedUsedNonceBackend interface {
	UsedNonceBackend
	RecordFor(routeKey, nonceKey string, usedAt time.Time) error
	ContainsFor(routeKey, nonceKey string) (bool, error)
}

// memoryUsedNonceBackend keeps up to maxSize used nonces and evicts the oldest
// to make room; maxSize <= 0 keeps none.
type memoryUsedNonceBackend struct {
	mu      sync.Mutex
	index   map[string]*list.Element
	order   list.List
	maxSize int
}

type usedNonceEntry struct {
	key    string
	usedAt time.Time
}

func newMemoryUsedNonceBackend(maxSize int) *memoryUsedNonceBackend {
	return &memoryUsedNonceBackend{
		index:   make(map[string]*list.Element, maxSize),
		maxSize: maxSize,
	}
}

func (m *memoryUsedNonceBackend) Record(nonceKey string, usedAt time.Time) error {
	if m.maxSize <= 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if elem, exists := m.index[nonceKey]; exists {
		m.order.Remove(elem)
		delete(m.index, nonceKey)
	}

	if len(m.index) >= m.maxSize {
		front := m.order.Front()
		if front != nil {
			entry, ok := front.Value.(usedNonceEntry)
			m.order.Remove(front)
			if ok {
				delete(m.index, entry.key)
			}
		}
	}

	elem := m.order.PushBack(usedNonceEntry{key: nonceKey, usedAt: usedAt})
	m.index[nonceKey] = elem
	return nil
}

func (m *memoryUsedNonceBackend) Contains(nonceKey string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, exists := m.index[nonceKey]
	return exists, nil
}

func (m *memoryUsedNonceBackend) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.index)
}

func (m *memoryUsedNonceBackend) Cleanup(olderThan time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for elem := m.order.Front(); elem != nil; {
		next := elem.Next()
		entry, ok := elem.Value.(usedNonceEntry)
		if ok && entry.usedAt.Before(olderThan) {
			m.order.Remove(elem)
			delete(m.index, entry.key)
		}
		elem = next
	}
}

// NonceStore issues challenges and consumes each nonce once.
type NonceStore struct {
	mu         sync.RWMutex
	pending    map[string]nonceEntry
	lifetime   time.Duration
	randReader io.Reader

	usedBackend   UsedNonceBackend
	routedBackend RoutedUsedNonceBackend // usedBackend when it is routed

	bindingChallenges  map[string]clientState // keyed by bindingID
	identityChallenges map[string]clientState // keyed by identityID

	maxPending      int // per bindingID
	rateLimitWindow time.Duration
	rateLimitMax    int // rounds per identityID per window

	stopCh chan struct{}
}

type nonceEntry struct {
	nonce     [types.NonceSize]byte
	createdAt time.Time
	bindingID string
}

type clientState struct {
	pendingCount    int
	windowStart     time.Time
	windowCount     int
	attestCounter   uint64
	lastAttestation time.Time
}

// NonceStoreConfig configures NewNonceStoreFromConfig.
type NonceStoreConfig struct {
	Lifetime time.Duration

	// MaxPendingPerClient bounds the outstanding challenges per binding.
	MaxPendingPerClient int

	// RateLimitMax bounds the rounds per identity in RateLimitWindow.
	RateLimitMax    int
	RateLimitWindow time.Duration

	// UsedNonceHistory caps the in-memory history used when UsedBackend is
	// nil; zero or less keeps none.
	UsedNonceHistory int
	UsedBackend      UsedNonceBackend

	// RandReader defaults to crypto/rand.Reader.
	RandReader io.Reader
}

// DefaultNonceStoreConfig returns the default nonce store configuration.
func DefaultNonceStoreConfig() NonceStoreConfig {
	return NonceStoreConfig{
		Lifetime:            5 * time.Minute,
		MaxPendingPerClient: 5,
		RateLimitMax:        30,
		RateLimitWindow:     time.Minute,
		UsedNonceHistory:    10000,
	}
}

// NewNonceStoreFromConfig starts the store's expiry sweep; Close stops it.
func NewNonceStoreFromConfig(cfg NonceStoreConfig) *NonceStore {
	backend := cfg.UsedBackend
	if backend == nil {
		backend = newMemoryUsedNonceBackend(cfg.UsedNonceHistory)
	}

	var routed RoutedUsedNonceBackend
	if r, ok := backend.(RoutedUsedNonceBackend); ok {
		routed = r
	}

	ns := &NonceStore{
		pending:            make(map[string]nonceEntry),
		lifetime:           cfg.Lifetime,
		randReader:         cfg.RandReader,
		usedBackend:        backend,
		routedBackend:      routed,
		bindingChallenges:  make(map[string]clientState),
		identityChallenges: make(map[string]clientState),
		maxPending:         cfg.MaxPendingPerClient,
		rateLimitWindow:    cfg.RateLimitWindow,
		rateLimitMax:       cfg.RateLimitMax,
		stopCh:             make(chan struct{}),
	}

	if ns.randReader == nil {
		ns.randReader = rand.Reader
	}

	go ns.cleanupLoop()

	return ns
}

// GenerateChallenge issues a challenge whose nonce is bound to bindingID.
func (ns *NonceStore) GenerateChallenge(bindingID string, pcrMask uint32) (*types.Challenge, error) {
	for range maxNonceGenerationAttempts {
		var nonce [types.NonceSize]byte
		if _, err := io.ReadFull(ns.randReader, nonce[:]); err != nil {
			return nil, fmt.Errorf("nonce generation failed: %w", err)
		}

		key := hex.EncodeToString(nonce[:])
		// a routed backend is not probed: no client is named yet
		if ns.routedBackend == nil {
			used, err := ns.usedBackend.Contains(key)
			if err != nil {
				return nil, fmt.Errorf("used-nonce history unavailable: %w", err)
			}
			if used {
				continue
			}
		}

		ns.mu.Lock()
		if _, exists := ns.pending[key]; exists {
			ns.mu.Unlock()
			continue
		}

		if err := ns.checkPendingLimit(bindingID); err != nil {
			ns.mu.Unlock()
			return nil, err
		}

		cs := ns.bindingChallenges[bindingID]
		cs.pendingCount++
		ns.bindingChallenges[bindingID] = cs

		ns.pending[key] = nonceEntry{
			nonce:     nonce,
			createdAt: time.Now(),
			bindingID: bindingID,
		}
		ns.mu.Unlock()

		return &types.Challenge{
			Magic:   types.ReportMagic,
			Version: types.ReportVersion,
			Nonce:   nonce,
			PCRMask: pcrMask,
			Flags:   types.ChallengeFlagBootCommitmentV1,
		}, nil
	}

	return nil, errors.New("nonce generation failed: repeated collisions")
}

// usedContains and usedRecord reach the history through the identity's
// partition when the backend is routed.
func (ns *NonceStore) usedContains(identityID, key string) (bool, error) {
	if ns.routedBackend != nil {
		return ns.routedBackend.ContainsFor(identityID, key)
	}
	return ns.usedBackend.Contains(key)
}

func (ns *NonceStore) usedRecord(identityID, key string, usedAt time.Time) error {
	if ns.routedBackend != nil {
		return ns.routedBackend.RecordFor(identityID, key, usedAt)
	}
	return ns.usedBackend.Record(key, usedAt)
}

// VerifyNonce consumes the report's nonce. It refuses a nonce already used,
// unknown, expired, issued to another binding, over the identity's rate limit,
// or absent from the quote's extraData as the binding nonce. A rate-limit
// refusal consumes the nonce; an extraData refusal leaves it pending.
// identityID is the client identity from the verified AIK certificate.
func (ns *NonceStore) VerifyNonce(report *types.AttestationReport, bindingID, identityID string) error {
	key := hex.EncodeToString(report.TPM.Nonce[:])

	used, err := ns.usedContains(identityID, key)
	if err != nil {
		return fmt.Errorf("used-nonce history unavailable, refusing the round: %w", err)
	}
	if used {
		return errors.New("nonce already used - replay attack detected")
	}

	ns.mu.Lock()
	entry, exists := ns.pending[key]
	if !exists {
		ns.mu.Unlock()
		return errors.New("unknown or expired nonce")
	}

	if time.Since(entry.createdAt) > ns.lifetime {
		ns.consumeLocked(key, entry.bindingID)
		ns.mu.Unlock()
		return errors.New("nonce expired")
	}

	if entry.bindingID != "" && entry.bindingID != bindingID {
		ns.mu.Unlock()
		return errors.New("nonce bound to different challenge")
	}

	if subtle.ConstantTimeCompare(entry.nonce[:], report.TPM.Nonce[:]) != 1 {
		ns.mu.Unlock()
		return errors.New("nonce mismatch in report header")
	}

	if err := ns.checkIdentityRateLimit(identityID); err != nil {
		ns.consumeLocked(key, entry.bindingID)
		ns.mu.Unlock()
		if recordErr := ns.usedRecord(identityID, key, time.Now()); recordErr != nil {
			return fmt.Errorf("%w; failed to record rejected nonce: %v", err, recordErr)
		}
		return err
	}
	ns.mu.Unlock()

	if report.TPM.AttestSize == 0 {
		return errors.New("no attestation data - cannot verify nonce binding")
	}

	if int(report.TPM.AttestSize) > len(report.TPM.AttestData) {
		return fmt.Errorf("invalid attestation size: %d > %d", report.TPM.AttestSize, len(report.TPM.AttestData))
	}

	bindingNonce := ComputeAttestationBindingNonce(entry.nonce, report)
	attestData := report.TPM.AttestData[:report.TPM.AttestSize]
	if err := VerifyNonceInAttest(attestData, bindingNonce[:]); err != nil {
		return fmt.Errorf("TPMS_ATTEST nonce verification failed: %w", err)
	}

	// a concurrent round may have consumed it during the unlocked check
	ns.mu.Lock()
	if _, still := ns.pending[key]; !still {
		ns.mu.Unlock()
		return errors.New("unknown or expired nonce")
	}
	ns.consumeLocked(key, entry.bindingID)

	ics := ns.identityChallenges[identityID]
	ics.attestCounter++
	ics.lastAttestation = time.Now()
	ns.identityChallenges[identityID] = ics
	ns.mu.Unlock()

	if err := ns.usedRecord(identityID, key, time.Now()); err != nil {
		return fmt.Errorf("failed to record used nonce: %w", err)
	}

	return nil
}

// consumeLocked drops a pending nonce and its binding's slot; ns.mu is held.
func (ns *NonceStore) consumeLocked(key, bindingID string) {
	delete(ns.pending, key)
	if cs, ok := ns.bindingChallenges[bindingID]; ok {
		cs.pendingCount--
		if cs.pendingCount < 0 {
			cs.pendingCount = 0
		}
		ns.bindingChallenges[bindingID] = cs
	}
}

// DiscardChallenge releases an unanswered challenge and its per-binding slot
// now rather than at sweep expiry. Only the issuing binding can discard it.
func (ns *NonceStore) DiscardChallenge(nonce [types.NonceSize]byte, bindingID string) {
	key := hex.EncodeToString(nonce[:])

	ns.mu.Lock()
	defer ns.mu.Unlock()

	entry, ok := ns.pending[key]
	if !ok || entry.bindingID != bindingID {
		return
	}
	ns.consumeLocked(key, bindingID)
}

func (ns *NonceStore) checkPendingLimit(bindingID string) error {
	cs, exists := ns.bindingChallenges[bindingID]

	if exists {
		if cs.pendingCount >= ns.maxPending {
			return fmt.Errorf("too many outstanding challenges for client %s (%d/%d)",
				bindingID, cs.pendingCount, ns.maxPending)
		}
		ns.bindingChallenges[bindingID] = cs
	} else {
		ns.bindingChallenges[bindingID] = clientState{
			windowStart: time.Now(),
			windowCount: 0,
		}
	}

	return nil
}

func (ns *NonceStore) checkIdentityRateLimit(identityID string) error {
	cs := ns.identityChallenges[identityID]
	now := time.Now()

	if cs.windowStart.IsZero() || now.Sub(cs.windowStart) > ns.rateLimitWindow {
		cs.windowStart = now
		cs.windowCount = 0
	} else if cs.windowCount >= ns.rateLimitMax {
		return fmt.Errorf("rate limit exceeded for hardware identity %s (%d/%d per %v)",
			identityID, cs.windowCount, ns.rateLimitMax, ns.rateLimitWindow)
	}

	cs.windowCount++
	ns.identityChallenges[identityID] = cs
	return nil
}

// Close stops the expiry sweep.
func (ns *NonceStore) Close() {
	close(ns.stopCh)
}

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
	now := time.Now()

	ns.mu.Lock()

	for key, entry := range ns.pending {
		if now.Sub(entry.createdAt) > ns.lifetime {
			if cs, ok := ns.bindingChallenges[entry.bindingID]; ok {
				cs.pendingCount--
				if cs.pendingCount < 0 {
					cs.pendingCount = 0
				}
				ns.bindingChallenges[entry.bindingID] = cs
			}
			delete(ns.pending, key)
		}
	}

	clientCutoff := now.Add(-ns.lifetime * 3)
	for id, cs := range ns.bindingChallenges {
		if cs.pendingCount <= 0 && cs.lastAttestation.Before(clientCutoff) {
			delete(ns.bindingChallenges, id)
		}
	}
	for id, cs := range ns.identityChallenges {
		if cs.lastAttestation.Before(clientCutoff) &&
			(cs.windowStart.IsZero() || cs.windowStart.Before(clientCutoff)) {
			delete(ns.identityChallenges, id)
		}
	}

	ns.mu.Unlock()

	// a used nonce outlives its pending entry
	ns.usedBackend.Cleanup(now.Add(-ns.lifetime * 3))
}

// PendingCount returns the number of outstanding challenges.
func (ns *NonceStore) PendingCount() int {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return len(ns.pending)
}

// UsedCount returns the size of the used-nonce history.
func (ns *NonceStore) UsedCount() int {
	return ns.usedBackend.Count()
}

func (ns *NonceStore) ClientCounter(clientID string) uint64 {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	if cs, ok := ns.identityChallenges[clientID]; ok {
		return cs.attestCounter
	}
	return 0
}

func (ns *NonceStore) ClientLastAttestation(clientID string) time.Time {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	if cs, ok := ns.identityChallenges[clientID]; ok {
		return cs.lastAttestation
	}
	return time.Time{}
}

// ForgetClient drops the identity's state; the used-nonce history stays.
func (ns *NonceStore) ForgetClient(clientID string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	delete(ns.identityChallenges, clientID)
}

// ListActiveClients returns the identities the store holds state for.
func (ns *NonceStore) ListActiveClients() []string {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	clients := make([]string, 0, len(ns.identityChallenges))
	for id := range ns.identityChallenges {
		clients = append(clients, id)
	}
	return clients
}
