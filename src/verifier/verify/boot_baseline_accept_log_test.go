// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/types"
)

// Logs through logging.New, so lines carry level names (level=SECURITY),
// not slog's numeric fallback.
func acceptLogVerifier(t *testing.T, buf *bytes.Buffer, policy *PCRPolicy,
	requireBootEnrollment bool,
) *Verifier {
	t.Helper()

	cfg := DefaultConfig()
	cfg.NonceLifetime = 1 * time.Second
	cfg.RequireBootEnrollment = requireBootEnrollment
	cfg.Logger = logging.New(logging.Options{
		Level:  "debug",
		Format: "text",
		Output: buf,
	})

	v := NewVerifier(cfg, newCertStore(t))
	if err := v.AddPolicy(policy); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if err := v.SetActivePolicy(policy.Name); err != nil {
		t.Fatalf("SetActivePolicy: %v", err)
	}
	return v
}

// Runs one first attestation, returns its first-use boot baseline line.
func firstUseBootAcceptLine(t *testing.T, v *Verifier, logs *bytes.Buffer,
	clientID string,
) string {
	t.Helper()

	challenge, err := v.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	report := createValidReport(t, clientID, challenge.Nonce, fixturePCR14())
	result, err := v.VerifyReport(clientID, report)
	if err != nil {
		t.Fatalf("VerifyReport: %v", err)
	}
	if result.Result != types.VerifyOK {
		t.Fatalf("expected VerifyOK, got %d", result.Result)
	}

	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "boot baseline") &&
			strings.Contains(line, "first-use") {
			return line
		}
	}
	t.Fatalf("no first-use boot baseline record in the log:\n%s", logs.String())
	return ""
}

// A first-use pin under --allow-tofu-boot-baseline trusts unauthenticated
// firmware state; it logs at SECURITY like the anchored accept.
func TestVerify_UnanchoredBootPinIsLoggedAtSecurityLevel(t *testing.T) {
	var logs bytes.Buffer

	// no PCR0/1/7 pins, no require_secureboot: only the flag can pin
	v := acceptLogVerifier(t, &logs, DefaultPolicy(), false)

	line := firstUseBootAcceptLine(t, v, &logs, "tofu-accept-unanchored")

	if !strings.Contains(line, "level=SECURITY") {
		t.Fatalf("the unanchored pin is not a security event:\n%s", line)
	}
	if !strings.Contains(line, "allow-tofu-boot-baseline") {
		t.Fatalf("the accept does not name what allowed it:\n%s", line)
	}
}

// The anchored accept names its anchor; a field, not the level,
// tells the two apart.
func TestVerify_AnchoredBootPinNamesItsAnchor(t *testing.T) {
	var logs bytes.Buffer

	policy := DefaultPolicy()
	policy.Name = "anchored"
	policy.RequireSecureBoot = true

	v := acceptLogVerifier(t, &logs, policy, true)

	line := firstUseBootAcceptLine(t, v, &logs, "tofu-accept-anchored")

	if !strings.Contains(line, "level=SECURITY") {
		t.Fatalf("the anchored pin is not a security event:\n%s", line)
	}
	if !strings.Contains(line, "Secure Boot anchor") {
		t.Fatalf("the accept does not name the anchor that allowed it:\n%s",
			line)
	}
	if strings.Contains(line, "allow-tofu-boot-baseline") {
		t.Fatalf("an anchored accept is blamed on the flag:\n%s", line)
	}
}
