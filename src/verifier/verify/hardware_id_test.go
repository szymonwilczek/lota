// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - hardware identity on the surfaces an operator acts through

package verify

import (
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

// runs one attestation round with the given ban store and attestation log
func attestWithLog(t *testing.T, clientID string, bans store.BanStore,
	attestLog store.AttestationLog) (*Verifier, *types.VerifyResult) {
	t.Helper()

	cfg := DefaultConfig()
	cfg.RequireBootEnrollment = false
	cfg.NonceLifetime = 1 * time.Second
	cfg.BanStore = bans
	cfg.AttestationLog = attestLog
	verifier := NewVerifier(cfg, newCertStore(t))
	if err := verifier.AddPolicy(DefaultPolicy()); err != nil {
		t.Fatalf("AddPolicy(DefaultPolicy) failed: %v", err)
	}
	if err := verifier.SetActivePolicy("default"); err != nil {
		t.Fatalf("SetActivePolicy(default) failed: %v", err)
	}

	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	reportData := createValidReport(t, clientID, challenge.Nonce, fixturePCR14())
	result, _ := verifier.VerifyReport(clientID, reportData)
	return verifier, result
}

// The attestation record's hardware ID must be the ban store's key,
// in the form the ban endpoint accepts.
func TestIntegration_AttestationRecordCarriesBannableHardwareID(t *testing.T) {
	const clientID = "hwid-log-client"

	attestLog := store.NewMemoryAttestationLog()
	_, result := attestWithLog(t, clientID, nil, attestLog)
	if result.Result != types.VerifyOK {
		t.Fatalf("result = %d, want VerifyOK", result.Result)
	}

	records := attestLog.QueryAttestations(1)
	if len(records) != 1 {
		t.Fatalf("attestation records = %d, want 1", len(records))
	}

	want := store.FormatHardwareID(devicePseudonymHWID(t, clientID))
	if records[0].HardwareID != want {
		t.Fatalf("recorded hardware_id = %q, want %q", records[0].HardwareID, want)
	}
	if _, err := store.ParseHardwareID(records[0].HardwareID); err != nil {
		t.Fatalf("recorded hardware_id is not one the ban endpoint takes: %v", err)
	}
}

// The hardware ID on a refused round bans that hardware unedited.
func TestIntegration_RejectedRoundNamesTheHardwareToBan(t *testing.T) {
	const clientID = "hwid-banned-client"
	hwid := devicePseudonymHWID(t, clientID)

	bans := store.NewMemoryBanStore()
	if err := bans.BanHardware(DefaultTenant, hwid, store.RevocationCheating, "op", ""); err != nil {
		t.Fatalf("BanHardware: %v", err)
	}

	attestLog := store.NewMemoryAttestationLog()
	_, result := attestWithLog(t, clientID, bans, attestLog)
	if result.Result != types.VerifyBanned {
		t.Fatalf("result = %d, want VerifyBanned", result.Result)
	}

	records := attestLog.QueryAttestations(1)
	if len(records) != 1 {
		t.Fatalf("attestation records = %d, want 1", len(records))
	}
	parsed, err := store.ParseHardwareID(records[0].HardwareID)
	if err != nil {
		t.Fatalf("hardware_id on a rejected round is not bannable: %v", err)
	}
	if parsed != hwid {
		t.Fatal("hardware_id on a rejected round names other hardware than the ban")
	}
}

// ClientInfo reports the same hardware ID as the attestation record.
func TestClientInfoNamesTheHardwareIdentity(t *testing.T) {
	const clientID = "hwid-info-client"

	verifier, result := attestWithLog(t, clientID, nil, nil)
	if result.Result != types.VerifyOK {
		t.Fatalf("result = %d, want VerifyOK", result.Result)
	}

	info, found := verifier.ClientInfo(testPseudonym(clientID))
	if !found {
		t.Fatal("ClientInfo(pseudonym) not found")
	}
	want := store.FormatHardwareID(devicePseudonymHWID(t, clientID))
	if info.HardwareID != want {
		t.Fatalf("client record hardware_id = %q, want %q", info.HardwareID, want)
	}
}
