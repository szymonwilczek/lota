// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

// Package enroll runs credential-activation enrollment: Begin checks the EK
// certificate and the AIK template and wraps a secret to the EK, Complete
// issues the AIK certificate once that secret comes back.
// Pending challenges are held in memory, capped and expiring.
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
	// DefaultSessionTTL is how long a pending challenge stays valid.
	DefaultSessionTTL = 2 * time.Minute

	// DefaultMaxPending caps the pending challenges.
	DefaultMaxPending = 4096

	sessionIDSize = 16
)

// Errors returned by Begin and Complete.
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
	tenants      *TenantManifest   // nil = every device in the default tenant
	tokens       *EnrollmentTokens // nil = every presented token is rejected
	requireToken bool

	now func() time.Time

	mu      sync.Mutex
	pending map[string]*session
}

type session struct {
	secret    []byte
	aikPub    *rsa.PublicKey
	deviceID  string
	tenant    string
	createdAt time.Time
}

// Challenge is what Begin returns for the agent's TPM2_ActivateCredential.
type Challenge struct {
	SessionID       string
	CredentialBlob  []byte
	EncryptedSecret []byte
}

// Option configures a Service.
type Option func(*Service)

// WithSessionTTL replaces DefaultSessionTTL; a non-positive ttl is ignored.
func WithSessionTTL(ttl time.Duration) Option {
	return func(s *Service) {
		if ttl > 0 {
			s.ttl = ttl
		}
	}
}

// WithMaxPending replaces DefaultMaxPending; a non-positive n is ignored.
func WithMaxPending(n int) Option {
	return func(s *Service) {
		if n > 0 {
			s.maxPending = n
		}
	}
}

// WithTenantManifest assigns a token-less device its tenant by EK from m.
// Without it such a device enrolls into DefaultTenant.
func WithTenantManifest(m *TenantManifest) Option {
	return func(s *Service) {
		s.tenants = m
	}
}

// WithEnrollmentTokens assigns a device that presents a token its tenant
// from t. Without it every presented token is refused.
func WithEnrollmentTokens(t *EnrollmentTokens) Option {
	return func(s *Service) {
		s.tokens = t
	}
}

// WithRequireToken refuses an enrollment that presents no token.
func WithRequireToken() Option {
	return func(s *Service) {
		s.requireToken = true
	}
}

// NewService returns a Service that issues through issuer. pseudonymKey
// keys the device ID of issued certificates and must be at least 16 bytes.
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

// Begin checks the EK certificate, with ekChainDER as path material, and
// the AIK template, assigns the tenant and records a pending challenge for
// Complete. A non-empty token decides the tenant and is never replaced by
// the manifest or DefaultTenant; without one the manifest decides, unless
// WithRequireToken is set.
func (s *Service) Begin(ekCertDER, aikTPMTPublic, token []byte, ekChainDER [][]byte) (*Challenge, error) {
	now := s.now()

	ekCert, err := s.issuer.VerifyEKCertificate(ekCertDER, ekChainDER, now)
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

	var tenant string
	switch {
	case len(token) > 0:
		tenant, err = s.tokens.TenantFor(token)
	case s.requireToken:
		err = ErrTokenRequired
	default:
		tenant, err = s.tenants.TenantFor(ekPub)
	}
	if err != nil {
		return nil, fmt.Errorf("tenant assignment: %w", err)
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
		deviceID:  s.deviceID(ekPub, tenant),
		tenant:    tenant,
		createdAt: now,
	}

	return &Challenge{
		SessionID:       sessionID,
		CredentialBlob:  ch.CredentialBlob,
		EncryptedSecret: ch.EncryptedSecret,
	}, nil
}

// Complete removes the session, then checks its age and, in constant time,
// the activated secret; on a match it issues the AIK certificate.
// An expired session or a wrong secret burns the challenge.
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

	der, err := s.issuer.IssueAIKCertificate(sess.aikPub, sess.deviceID, sess.tenant, now)
	if err != nil {
		return nil, "", fmt.Errorf("issuing AIK certificate: %w", err)
	}
	return der, sess.deviceID, nil
}

func (s *Service) sweepLocked(now time.Time) {
	for id, sess := range s.pending {
		if now.Sub(sess.createdAt) > s.ttl {
			delete(s.pending, id)
		}
	}
}

// deviceID is the hex HMAC-SHA256, under the pseudonym key, of the EK
// modulus, prefixed with the tenant and a NUL unless the tenant is
// DefaultTenant. A tenant name holds no NUL, so two (named tenant, EK) pairs
// never share an input.
func (s *Service) deviceID(ekPub *rsa.PublicKey, tenant string) string {
	input := ekPub.N.Bytes()
	if tenant != DefaultTenant {
		buf := make([]byte, 0, len(tenant)+1+len(input))
		buf = append(buf, tenant...)
		buf = append(buf, 0x00)
		buf = append(buf, input...)
		input = buf
	}
	mac := hmacSHA256(s.pseudonymKey, input)
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
