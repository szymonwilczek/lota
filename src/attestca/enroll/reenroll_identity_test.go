// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package enroll

import (
	"bytes"
	"testing"

	"github.com/szymonwilczek/lota/attestca/internal/tpmtest"
)

func TestReenrollOntoOwnKeyKeepsTheDeviceID(t *testing.T) {
	svc, root := newTestService(t)
	ek := tpmtest.NewEKCert(t, root)

	enrol := func() (string, []byte) {
		aikTPMT, aikName := tpmtest.AIKTemplate(t)
		ch, err := svc.Begin(ek.CertDER, aikTPMT, nil, nil)
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		recovered := tpmtest.SoftwareActivate(t, ek.Priv, aikName, ch.CredentialBlob, ch.EncryptedSecret)
		_, id, err := svc.Complete(ch.SessionID, recovered)
		if err != nil {
			t.Fatalf("Complete: %v", err)
		}
		name, err := aikName.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return id, name
	}

	sharedID, sharedKey := enrol()
	ownID, ownKey := enrol()
	if bytes.Equal(sharedKey, ownKey) {
		t.Fatal("the two enrolments used the same attestation key")
	}
	if sharedID != ownID {
		t.Fatalf("a new attestation key moved the device ID: %s -> %s", sharedID, ownID)
	}

	other, err := NewService(svc.issuer, []byte("another-pseudonym-key-fedcba9876"))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if other.deviceID(&ek.Priv.PublicKey, DefaultTenant) == sharedID {
		t.Fatal("the CA's pseudonym key does not enter the device ID")
	}
}
