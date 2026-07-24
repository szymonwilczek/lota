// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package enroll

import (
	"crypto/rsa"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/attestca/ca"
	"github.com/szymonwilczek/lota/attestca/internal/tpmtest"
)

func newTestService(tb testing.TB, opts ...Option) (*Service, tpmtest.Root) {
	tb.Helper()
	root := tpmtest.NewVendorRoot(tb, "tpm-vendor-root")
	caCertPEM, caKeyPEM := tpmtest.LOTACAPEM(tb)
	issuer, err := ca.NewIssuer(ca.IssuerConfig{
		CACertPEM:  caCertPEM,
		CAKeyPEM:   caKeyPEM,
		EKRootPEMs: [][]byte{tpmtest.PEM("CERTIFICATE", root.DER)},
	})
	if err != nil {
		tb.Fatalf("NewIssuer: %v", err)
	}
	svc, err := NewService(issuer, []byte("pseudonym-key-0123456789abcdef"), opts...)
	if err != nil {
		tb.Fatalf("NewService: %v", err)
	}
	return svc, root
}

func TestEnrollFullCeremony(t *testing.T) {
	svc, root := newTestService(t)
	ek := tpmtest.NewEKCert(t, root)
	aikTPMT, aikName := tpmtest.AIKTemplate(t)

	ch, err := svc.Begin(ek.CertDER, aikTPMT, nil)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if svc.PendingCount() != 1 {
		t.Fatalf("pending=%d, want 1", svc.PendingCount())
	}

	recovered := tpmtest.SoftwareActivate(t, ek.Priv, aikName, ch.CredentialBlob, ch.EncryptedSecret)

	certDER, deviceID, err := svc.Complete(ch.SessionID, recovered)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if len(certDER) == 0 || deviceID == "" {
		t.Fatal("empty certificate or device id")
	}
	if svc.PendingCount() != 0 {
		t.Fatalf("session not consumed: pending=%d", svc.PendingCount())
	}
}

func TestEnrollDeviceIDStableAcrossEnrollments(t *testing.T) {
	svc, root := newTestService(t)
	ek := tpmtest.NewEKCert(t, root)

	id := func() string {
		aikTPMT, aikName := tpmtest.AIKTemplate(t)
		ch, err := svc.Begin(ek.CertDER, aikTPMT, nil)
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		recovered := tpmtest.SoftwareActivate(t, ek.Priv, aikName, ch.CredentialBlob, ch.EncryptedSecret)
		_, deviceID, err := svc.Complete(ch.SessionID, recovered)
		if err != nil {
			t.Fatalf("Complete: %v", err)
		}
		return deviceID
	}

	first, second := id(), id()
	if first != second {
		t.Fatal("same EK produced different device IDs")
	}
}

func TestEnrollWrongSecretRejected(t *testing.T) {
	svc, root := newTestService(t)
	ek := tpmtest.NewEKCert(t, root)
	aikTPMT, _ := tpmtest.AIKTemplate(t)

	ch, err := svc.Begin(ek.CertDER, aikTPMT, nil)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	bogus := make([]byte, 32)
	if _, _, err := svc.Complete(ch.SessionID, bogus); err == nil {
		t.Fatal("accepted wrong activation secret")
	}

	// session must be burned even on failure
	if svc.PendingCount() != 0 {
		t.Fatalf("failed session not consumed: pending=%d", svc.PendingCount())
	}
}

func TestEnrollWrongEKCannotActivate(t *testing.T) {
	svc, root := newTestService(t)
	issueEK := tpmtest.NewEKCert(t, root)
	attackerEK := tpmtest.NewEKCert(t, root)
	aikTPMT, _ := tpmtest.AIKTemplate(t)

	ch, err := svc.Begin(issueEK.CertDER, aikTPMT, nil)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// activation seed is OAEP-wrapped to the issuing EK
	// TPM holding any other EK cannot decrypt it, so it
	// can never recover the secret Complete demands
	seedLen := int(ch.EncryptedSecret[0])<<8 | int(ch.EncryptedSecret[1])
	if _, err := rsa.DecryptOAEP(sha256.New(), nil, attackerEK.Priv,
		ch.EncryptedSecret[2:2+seedLen], append([]byte("IDENTITY"), 0)); err == nil {
		t.Fatal("seed decrypted under the wrong EK")
	}
}

func TestEnrollUnknownSession(t *testing.T) {
	svc, _ := newTestService(t)
	if _, _, err := svc.Complete("deadbeef", make([]byte, 32)); err == nil {
		t.Fatal("accepted unknown session id")
	}
}

func TestEnrollSessionExpiry(t *testing.T) {
	now := time.Now()
	clock := &now
	svc, root := newTestService(t, WithSessionTTL(time.Minute),
		WithClock(func() time.Time { return *clock }))
	ek := tpmtest.NewEKCert(t, root)
	aikTPMT, aikName := tpmtest.AIKTemplate(t)

	ch, err := svc.Begin(ek.CertDER, aikTPMT, nil)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	recovered := tpmtest.SoftwareActivate(t, ek.Priv, aikName, ch.CredentialBlob, ch.EncryptedSecret)

	*clock = now.Add(2 * time.Minute)
	if _, _, err := svc.Complete(ch.SessionID, recovered); err == nil {
		t.Fatal("accepted expired session")
	}
}

func TestEnrollRejectsUntrustedEK(t *testing.T) {
	svc, _ := newTestService(t)
	rogue := tpmtest.NewVendorRoot(t, "rogue-vendor")
	ek := tpmtest.NewEKCert(t, rogue)
	aikTPMT, _ := tpmtest.AIKTemplate(t)

	if _, err := svc.Begin(ek.CertDER, aikTPMT, nil); err == nil {
		t.Fatal("accepted EK from untrusted root")
	}
}

func TestEnrollMaxPending(t *testing.T) {
	svc, root := newTestService(t, WithMaxPending(1))
	ek := tpmtest.NewEKCert(t, root)

	aik1, _ := tpmtest.AIKTemplate(t)
	if _, err := svc.Begin(ek.CertDER, aik1, nil); err != nil {
		t.Fatalf("first Begin: %v", err)
	}
	aik2, _ := tpmtest.AIKTemplate(t)
	if _, err := svc.Begin(ek.CertDER, aik2, nil); err == nil {
		t.Fatal("exceeded max pending without error")
	}
}

func TestNewServiceValidation(t *testing.T) {
	if _, err := NewService(nil, []byte("0123456789abcdef")); err == nil {
		t.Fatal("accepted nil issuer")
	}
	root := tpmtest.NewVendorRoot(t, "vendor")
	caCertPEM, caKeyPEM := tpmtest.LOTACAPEM(t)
	issuer, _ := ca.NewIssuer(ca.IssuerConfig{
		CACertPEM:  caCertPEM,
		CAKeyPEM:   caKeyPEM,
		EKRootPEMs: [][]byte{tpmtest.PEM("CERTIFICATE", root.DER)},
	})
	if _, err := NewService(issuer, []byte("short")); err == nil {
		t.Fatal("accepted short pseudonym key")
	}
}
