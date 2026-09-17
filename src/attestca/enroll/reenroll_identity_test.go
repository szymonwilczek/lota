// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package enroll

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/attestca/internal/tpmtest"
)

// A new attestation key keeps the device ID; only the tenant and the CA's
// pseudonym key move it, and the page must say so.
var newKeyNewDevice = []*regexp.Regexp{
	regexp.MustCompile(`(?i)pseudonym\s+is\s+derived\s+from\s+the\s+(attestation\s+)?key`),
	regexp.MustCompile(`(?i)moves\s+with\s+it`),
	regexp.MustCompile(`(?i)a\s+device\s+it\s+has\s+not\s+met`),
	regexp.MustCompile(`(?i)re-?establish\w*\s+the\s+baseline`),
}

func paragraphContaining(t *testing.T, path, needle string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for p := range strings.SplitSeq(string(raw), "\n\n") {
		flat := strings.Join(strings.Fields(p), " ")
		if strings.Contains(flat, needle) {
			return flat
		}
	}
	t.Fatalf("%s has no paragraph containing %q", path, needle)
	return ""
}

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

func TestReenrollPageSaysWhatMovesThePseudonym(t *testing.T) {
	para := paragraphContaining(t, caEnrollmentPage,
		"created before the publisher's identity entered the TPM creation template")

	for _, claim := range newKeyNewDevice {
		if m := claim.FindString(para); m != "" {
			t.Errorf("the page says re-enrolling onto a new key %q; the device ID is made of the EK, "+
				"the tenant and the CA's pseudonym key, so the publisher meets the device it knows", m)
		}
	}
	var missing []string
	for _, want := range []string{"same device ID", "tenant", "pseudonym key"} {
		if !strings.Contains(para, want) {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		t.Errorf("the paragraph does not say %q:\n%s", missing, para)
	}
}
