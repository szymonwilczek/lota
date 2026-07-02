// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Session token store
//
// Session token is the 32-byte HMAC tag the verifier hands back after a
// successful attestation; the validation API (POST /api/v1/session/validate)
// looks it up to confirm a host attested OK until a deadline. The token
// itself is opaque and carries no claims, so validation needs the record the
// verifier remembered at issue time.
//
// SessionTokenStore abstracts where that record lives.
// Default in-memory store keeps single-node behaviour.
// Postgres store (pg_session.go) shares the records across instances so any
// verifier behind a load balancer can validate a token issued by any peer,
// and Consume marks a token used atomically across the whole fleet.

package verify

import (
	"sync"
	"time"
)

// SessionTokenStore remembers issued session tokens and answers validation
// queries. now is unix seconds
// Implementations treat a zero ValidUntil as "never expires" to match the
// issue path.
type SessionTokenStore interface {
	// Remember records a freshly issued token.
	Remember(token [32]byte, rec sessionTokenRecord)

	// Validate looks up a token, reports its status, and (when consume is
	// set and the token is not already consumed) marks it consumed. An
	// expired token is reported with Exists=false.
	Validate(token [32]byte, consume bool, now uint64) SessionTokenStatus
}

// in-memory SessionTokenStore; process-local, lost on restart.
// This keeps the historical single-node behaviour: tokens validate only on
// the instance that issued them.
type memorySessionTokenStore struct {
	mu    sync.Mutex
	index map[[32]byte]sessionTokenRecord
}

func newMemorySessionTokenStore() *memorySessionTokenStore {
	return &memorySessionTokenStore{index: make(map[[32]byte]sessionTokenRecord)}
}

func (m *memorySessionTokenStore) Remember(token [32]byte, rec sessionTokenRecord) {
	now := unixTimestamp(time.Now())

	m.mu.Lock()
	defer m.mu.Unlock()

	for k, r := range m.index {
		if r.ValidUntil > 0 && r.ValidUntil <= now {
			delete(m.index, k)
		}
	}

	m.index[token] = rec
}

func (m *memorySessionTokenStore) Validate(token [32]byte, consume bool, now uint64) SessionTokenStatus {
	st := SessionTokenStatus{}

	m.mu.Lock()
	defer m.mu.Unlock()

	for k, r := range m.index {
		if r.ValidUntil > 0 && r.ValidUntil <= now {
			delete(m.index, k)
		}
	}

	rec, ok := m.index[token]
	if !ok {
		return st
	}

	st.Exists = true
	st.ClientID = rec.ClientID
	st.Tenant = rec.Tenant
	st.HardwareID = rec.HardwareID
	st.ValidUntil = rec.ValidUntil
	st.ResultCode = rec.ResultCode
	st.Flags = rec.Flags
	st.PCRMask = rec.PCRMask
	st.Consumed = rec.Consumed
	st.Expired = rec.ValidUntil > 0 && rec.ValidUntil <= now

	if st.Expired {
		delete(m.index, token)
		st.Exists = false
		return st
	}

	if consume && !rec.Consumed {
		rec.Consumed = true
		m.index[token] = rec
		st.Consumed = true
	}

	return st
}
