// SPDX-License-Identifier: MIT

package verify

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

type trackingCertStore struct {
	calledVerify   bool
	calledRegister bool

	inner store.AIKStore
}

func makeTestDERCert(t *testing.T, key *rsa.PrivateKey, cn string) []byte {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"LOTA test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}
	return der
}

func injectCerts(t *testing.T, report []byte, aikCert, ekCert []byte) []byte {
	t.Helper()
	if len(aikCert) > 0 && len(aikCert) > types.MaxAIKCertSize {
		t.Fatalf("AIK cert too large: %d", len(aikCert))
	}
	if len(ekCert) > 0 && len(ekCert) > types.MaxEKCertSize {
		t.Fatalf("EK cert too large: %d", len(ekCert))
	}

	out := make([]byte, len(report))
	copy(out, report)

	offset := 16 +
		types.PCRCount*types.HashSize +
		4 +
		types.MaxSigSize +
		2 +
		types.MaxAttestSize +
		2 +
		types.MaxAIKPubSize +
		2

	aikCertOffset := offset
	aikCertSizeOffset := aikCertOffset + types.MaxAIKCertSize
	ekCertOffset := aikCertSizeOffset + 2
	ekCertSizeOffset := ekCertOffset + types.MaxEKCertSize
	for i := 0; i < types.MaxAIKCertSize; i++ {
		out[aikCertOffset+i] = 0
	}
	for i := 0; i < types.MaxEKCertSize; i++ {
		out[ekCertOffset+i] = 0
	}
	copy(out[aikCertOffset:], aikCert)
	copy(out[ekCertOffset:], ekCert)
	binary.LittleEndian.PutUint16(out[aikCertSizeOffset:], uint16(len(aikCert)))
	binary.LittleEndian.PutUint16(out[ekCertSizeOffset:], uint16(len(ekCert)))

	return out
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
	if err := verifier.AddPolicy(DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy(DefaultPolicy) failed: %v", err)
	}
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

func TestRequireCert_NewClientRejectsMismatchedHardwareIDEK(t *testing.T) {
	baseStore := store.NewMemoryStore()
	tracked := &trackingCertStore{inner: baseStore}

	cfg := DefaultConfig()
	cfg.NonceLifetime = 1 * time.Second
	cfg.RequireCert = true

	verifier := NewVerifier(cfg, tracked)
	if err := verifier.AddPolicy(DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy(DefaultPolicy) failed: %v", err)
	}
	if err := verifier.SetActivePolicy("default"); err != nil {
		t.Fatalf("SetActivePolicy(default) failed: %v", err)
	}

	challengeID := "first-connect-mismatch"
	challenge, err := verifier.GenerateChallenge(challengeID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	pcr14 := [32]byte{}
	for i := range pcr14 {
		pcr14[i] = byte(0x41 ^ i)
	}

	reportData := createValidReport(t, challengeID, challenge.Nonce, pcr14)

	aikKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(AIK cert): %v", err)
	}
	ekKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(EK cert): %v", err)
	}
	aikCertDER := makeTestDERCert(t, aikKey, "test-aik")
	ekCertDER := makeTestDERCert(t, ekKey, "test-ek")

	reportData = injectCerts(t, reportData, aikCertDER, ekCertDER)

	res, err := verifier.VerifyReport(challengeID, reportData)
	if err == nil {
		t.Fatalf("expected verification failure for hardware_id/EK mismatch")
	}
	if res == nil || res.Result != types.VerifySigFail {
		t.Fatalf("expected VerifySigFail, got result=%+v err=%v", res, err)
	}
	if !strings.Contains(err.Error(), "hardware_id/EK mismatch") {
		t.Fatalf("expected hardware_id/EK mismatch error, got: %v", err)
	}
	if !tracked.calledVerify {
		t.Fatalf("expected certificate verification path to execute")
	}
	if tracked.calledRegister {
		t.Fatalf("registration must not occur on hardware_id/EK mismatch")
	}
}
