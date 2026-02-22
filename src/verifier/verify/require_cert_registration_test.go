// SPDX-License-Identifier: MIT

package verify

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
)

type trackingCertStore struct {
	calledVerify   bool
	calledRegister bool

	inner store.AIKStore
}

func (t *trackingCertStore) GetAIK(clientID string) (*rsa.PublicKey, error) {
	return t.inner.GetAIK(clientID)
}

func (t *trackingCertStore) RegisterAIK(clientID string, pubKey *rsa.PublicKey) error {
	return t.inner.RegisterAIK(clientID, pubKey)
}

func (t *trackingCertStore) RegisterAIKWithCert(clientID string, pubKey *rsa.PublicKey, aikCert, ekCert []byte) error {
	t.calledRegister = true
	return t.inner.RegisterAIK(clientID, pubKey)
}

func (t *trackingCertStore) VerifyCertificatesForAIK(pubKey *rsa.PublicKey, aikCertDER, ekCertDER []byte) error {
	t.calledVerify = true
	return nil
}

func (t *trackingCertStore) RegisterHardwareID(clientID string, hardwareID [32]byte) error {
	return t.inner.RegisterHardwareID(clientID, hardwareID)
}

func (t *trackingCertStore) GetHardwareID(clientID string) ([32]byte, error) {
	return t.inner.GetHardwareID(clientID)
}

func (t *trackingCertStore) ListClients() []string {
	return t.inner.ListClients()
}

func (t *trackingCertStore) GetRegisteredAt(clientID string) (time.Time, error) {
	return t.inner.GetRegisteredAt(clientID)
}

func (t *trackingCertStore) RotateAIK(clientID string, newKey *rsa.PublicKey) error {
	return t.inner.RotateAIK(clientID, newKey)
}

func TestRequireCert_NewClientMissingCerts_NoRegistrationSideEffects(t *testing.T) {
	// when RequireCert is true, verifier must reject before touching persistent state

	baseStore := store.NewMemoryStore()
	tracked := &trackingCertStore{inner: baseStore}

	cfg := DefaultConfig()
	cfg.NonceLifetime = 1 * time.Second
	cfg.RequireCert = true

	verifier := NewVerifier(cfg, tracked)
	verifier.AddPolicy(DefaultPolicy())
	verifier.SetActivePolicy("default")

	clientID := "test-client-require-cert"
	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	pcr14 := [32]byte{}
	for i := range pcr14 {
		pcr14[i] = byte(0x14 ^ i)
	}

	// intentionally includes no AIK/EK certs
	reportData := createValidReport(t, clientID, challenge.Nonce, pcr14)

	_, err = verifier.VerifyReport(clientID, reportData)
	if err == nil {
		t.Fatalf("expected error when RequireCert=true and report contains no certs")
	}

	if tracked.calledVerify {
		t.Fatalf("expected VerifyCertificatesForAIK not to be called when certs are missing")
	}
	if tracked.calledRegister {
		t.Fatalf("expected RegisterAIKWithCert not to be called when certs are missing")
	}

	// ensure AIK was not registered as a side effect
	if _, gerr := baseStore.GetAIK(persistentClientID(clientID)); gerr == nil {
		t.Fatalf("SECURITY FAILURE: AIK was registered despite missing certs")
	}
}
