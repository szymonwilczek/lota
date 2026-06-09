// SPDX-License-Identifier: MIT
// LOTA Attestation CA - enrollment state machine
//
// Drives one host through the credential-activation ceremony: verify the
// EK certificate, wrap a secret to that EK bound to the AIK name, and -
// only once the agent returns the activated secret - issue the AIK
// certificate. The pending challenge is the single piece of server state;
// it is bounded and expires so a flood of half-finished enrollments
// cannot exhaust memory.

package enroll

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/szymonwilczek/lota/attestca/ca"
	"github.com/szymonwilczek/lota/attestca/credential"
)

const (
	// DefaultSessionTTL bounds how long an agent has to activate a
	// credential before the pending challenge is swept.
	DefaultSessionTTL = 2 * time.Minute

	// DefaultMaxPending caps outstanding challenges so an unauthenticated
	// flood of Begin calls cannot grow the session map without bound.
	DefaultMaxPending = 4096

	sessionIDSize = 16
)

var (
	ErrUnknownSession     = errors.New("unknown or consumed enrollment session")
	ErrSessionExpired     = errors.New("enrollment session expired")
	ErrActivationMismatch = errors.New("activation secret does not match challenge")
	ErrEKKeyType          = errors.New("EK certificate does not carry an RSA key; enrollment requires an RSA endorsement key (TCG EK template H-1)")
	ErrAIKKeyType         = errors.New("AIK template does not carry an RSA key; enrollment requires an RSA AIK")
	ErrTooManyPending     = errors.New("too many outstanding enrollment sessions")
)

// Service issues AIK certificates after credential activation.
type Service struct {
	issuer       *ca.Issuer
	ttl          time.Duration
	maxPending   int
	pseudonymKey []byte

	now func() time.Time

	mu      sync.Mutex
	pending map[string]*session
}

type session struct {
	secret    []byte
	aikPub    *rsa.PublicKey
	deviceID  string
	createdAt time.Time
}

// Challenge is returned by Begin and carries the activation material the
// agent feeds to TPM2_ActivateCredential.
type Challenge struct {
	SessionID       string
	CredentialBlob  []byte
	EncryptedSecret []byte
}

// Option configures a Service.
type Option func(*Service)

// WithSessionTTL overrides the pending-challenge lifetime.
func WithSessionTTL(ttl time.Duration) Option {
	return func(s *Service) {
		if ttl > 0 {
			s.ttl = ttl
		}
	}
}

// WithMaxPending overrides the outstanding-session cap.
func WithMaxPending(n int) Option {
	return func(s *Service) {
		if n > 0 {
			s.maxPending = n
		}
	}
}

// WithClock overrides the time source (tests)
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// NewService builds an enrollment Service. pseudonymKey keys the stable,
// EK-derived device identifier placed in issued certificates
// It must be kept secret so a verifier cannot reverse a device ID back to its EK
func NewService(issuer *ca.Issuer, pseudonymKey []byte, opts ...Option) (*Service, error) {
	if issuer == nil {
		return nil, errors.New("nil issuer")
	}
	if len(pseudonymKey) < 16 {
		return nil, errors.New("pseudonym key too short")
	}
	s := &Service{
		issuer:       issuer,
		ttl:          DefaultSessionTTL,
		maxPending:   DefaultMaxPending,
		pseudonymKey: append([]byte(nil), pseudonymKey...),
		now:          time.Now,
		pending:      make(map[string]*session),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Begin verifies the EK certificate and AIK template, wraps a fresh
// activation secret, and records the pending session. The returned
// Challenge must be activated by the agent and handed back to Complete.
func (s *Service) Begin(ekCertDER, aikTPMTPublic []byte) (*Challenge, error) {
	now := s.now()

	ekCert, err := s.issuer.VerifyEKCertificate(ekCertDER, now)
	if err != nil {
		return nil, fmt.Errorf("EK verification: %w", err)
	}
	ekPub, ok := ekCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrEKKeyType
	}

	aikPublic, aikName, err := credential.ValidateAIK(aikTPMTPublic)
	if err != nil {
		return nil, fmt.Errorf("AIK validation: %w", err)
	}
	aikKey, err := aikPublic.Key()
	if err != nil {
		return nil, fmt.Errorf("AIK key: %w", err)
	}
	aikRSA, ok := aikKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrAIKKeyType
	}

	ch, err := credential.GenerateChallenge(ekPub, aikName)
	if err != nil {
		return nil, fmt.Errorf("MakeCredential: %w", err)
	}

	sessionID, err := randomHex(sessionIDSize)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if len(s.pending) >= s.maxPending {
		return nil, ErrTooManyPending
	}
	s.pending[sessionID] = &session{
		secret:    ch.Secret,
		aikPub:    aikRSA,
		deviceID:  s.deviceID(ekPub),
		createdAt: now,
	}

	return &Challenge{
		SessionID:       sessionID,
		CredentialBlob:  ch.CredentialBlob,
		EncryptedSecret: ch.EncryptedSecret,
	}, nil
}

// Complete consumes a pending session: it compares the activated secret
// in constant time and, on a match, issues the AIK certificate.
// The session is removed whether or not activation succeeds, so a wrong
// secret burns the challenge.
func (s *Service) Complete(sessionID string, recoveredSecret []byte) (aikCertDER []byte, deviceID string, err error) {
	now := s.now()

	s.mu.Lock()
	sess, ok := s.pending[sessionID]
	if ok {
		delete(s.pending, sessionID)
	}
	s.mu.Unlock()

	if !ok {
		return nil, "", ErrUnknownSession
	}
	if now.Sub(sess.createdAt) > s.ttl {
		return nil, "", ErrSessionExpired
	}
	if subtle.ConstantTimeCompare(recoveredSecret, sess.secret) != 1 {
		return nil, "", ErrActivationMismatch
	}

	der, err := s.issuer.IssueAIKCertificate(sess.aikPub, sess.deviceID, now)
	if err != nil {
		return nil, "", fmt.Errorf("issuing AIK certificate: %w", err)
	}
	return der, sess.deviceID, nil
}

// PendingCount reports outstanding sessions (monitoring)
func (s *Service) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

func (s *Service) sweepLocked(now time.Time) {
	for id, sess := range s.pending {
		if now.Sub(sess.createdAt) > s.ttl {
			delete(s.pending, id)
		}
	}
}

// deviceID derives a stable, privacy-preserving identifier from the EK
// modulus. The same TPM always maps to the same ID so the operator can
// correlate re-enrollments, but the keyed hash cannot be reversed to the
// EK by a verifier that only sees the issued certificate.
func (s *Service) deviceID(ekPub *rsa.PublicKey) string {
	mac := hmacSHA256(s.pseudonymKey, ekPub.N.Bytes())
	return hex.EncodeToString(mac)
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("session id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
