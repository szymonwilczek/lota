// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - device tenant extraction tests

package verify

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

func certWithOUs(ous ...string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{CommonName: "aa", OrganizationalUnit: ous},
	}
}

func TestTenantFromCertificate(t *testing.T) {
	cases := []struct {
		name    string
		cert    *x509.Certificate
		want    string
		wantErr bool
	}{
		{"no OU is the default tenant", certWithOUs(), DefaultTenant, false},
		{"valid tenant", certWithOUs("acme-corp"), "acme-corp", false},
		{"single char", certWithOUs("a"), "a", false},
		{"digits", certWithOUs("title42"), "title42", false},
		{"empty OU entry", certWithOUs(""), "", true},
		{"uppercase", certWithOUs("Acme"), "", true},
		{"leading dash", certWithOUs("-acme"), "", true},
		{"trailing dash", certWithOUs("acme-"), "", true},
		{"underscore", certWithOUs("ac_me"), "", true},
		{"path smuggling", certWithOUs("a/b"), "", true},
		{"too long", certWithOUs(strings.Repeat("a", MaxTenantLen+1)), "", true},
		{"max length ok", certWithOUs(strings.Repeat("a", MaxTenantLen)), strings.Repeat("a", MaxTenantLen), false},
		{"two OU entries are ambiguous", certWithOUs("acme", "acme"), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TenantFromCertificate(tc.cert)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("TenantFromCertificate accepted %v", tc.cert.Subject.OrganizationalUnit)
				}
				return
			}
			if err != nil {
				t.Fatalf("TenantFromCertificate: %v", err)
			}
			if got != tc.want {
				t.Fatalf("tenant = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidTenantName(t *testing.T) {
	valid := []string{"a", "default", "acme-corp", "t1", "0", strings.Repeat("x", MaxTenantLen)}
	for _, name := range valid {
		if !ValidTenantName(name) {
			t.Errorf("ValidTenantName(%q) = false, want true", name)
		}
	}
	invalid := []string{"", "-a", "a-", "A", "a.b", "a b", "a/b", strings.Repeat("x", MaxTenantLen+1)}
	for _, name := range invalid {
		if ValidTenantName(name) {
			t.Errorf("ValidTenantName(%q) = true, want false", name)
		}
	}
}

// attestWithCertOUs runs one full attestation whose AIK certificate
// carries the given OU entries and returns the verify outcome
func attestWithCertOUs(t *testing.T, clientID string, ous []string) (*types.VerifyResult, error) {
	t.Helper()

	aikStore := newCertStore(t)
	verifier := createTestVerifier(t, aikStore)

	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	pcr14 := [32]byte{}
	for i := range pcr14 {
		pcr14[i] = byte(0x14 ^ i)
	}

	testAIKCertOUs = ous
	defer func() { testAIKCertOUs = nil }()
	reportData := createValidReport(t, clientID, challenge.Nonce, pcr14)

	return verifier.VerifyReport(clientID, reportData)
}

// attestVerifierWithCertOUs is attestWithCertOUs but returns
// the verifier so tests can inspect post-attestation state.
func attestVerifierWithCertOUs(t *testing.T, clientID string, ous []string) (*Verifier, *types.VerifyResult, error) {
	t.Helper()

	aikStore := newCertStore(t)
	verifier := createTestVerifier(t, aikStore)

	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	pcr14 := [32]byte{}
	for i := range pcr14 {
		pcr14[i] = byte(0x14 ^ i)
	}

	testAIKCertOUs = ous
	defer func() { testAIKCertOUs = nil }()
	reportData := createValidReport(t, clientID, challenge.Nonce, pcr14)

	result, err := verifier.VerifyReport(clientID, reportData)
	return verifier, result, err
}

func TestIntegration_TenantCertAttests(t *testing.T) {
	verifier, result, err := attestVerifierWithCertOUs(t, "tenant-client-ok", []string{"acme-corp"})
	if err != nil {
		t.Fatalf("attestation with a tenant OU failed: %v", err)
	}
	if result.Result != types.VerifyOK {
		t.Fatalf("result = %d, want VerifyOK", result.Result)
	}

	// verifier keys client state by the certificate CN
	// (the device pseudonym), not by the challenge ID
	info, found := verifier.ClientInfo(testPseudonym("tenant-client-ok"))
	if !found {
		t.Fatal("client not found after attestation")
	}
	if info.Tenant != "acme-corp" {
		t.Fatalf("ClientInfo.Tenant = %q, want the certificate tenant", info.Tenant)
	}
}

func TestIntegration_NoOUCertIsDefaultTenant(t *testing.T) {
	verifier, result, err := attestVerifierWithCertOUs(t, "tenant-client-plain", nil)
	if err != nil {
		t.Fatalf("attestation without an OU failed: %v", err)
	}
	if result.Result != types.VerifyOK {
		t.Fatalf("result = %d, want VerifyOK", result.Result)
	}

	info, found := verifier.ClientInfo(testPseudonym("tenant-client-plain"))
	if !found {
		t.Fatal("client not found after attestation")
	}
	if info.Tenant != DefaultTenant {
		t.Fatalf("ClientInfo.Tenant = %q, want %q", info.Tenant, DefaultTenant)
	}
}

func TestSQLiteBaselineStore_Tenant(t *testing.T) {
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()
	s := NewSQLiteBaselineStore(db)

	if err := s.SetClientTenant("ghost", "acme"); err == nil {
		t.Fatal("SetClientTenant stamped a client with no baseline row")
	}

	pcr14 := [32]byte{0x14}
	if res, _ := s.CheckAndUpdate("host1", pcr14); res != TOFUFirstUse {
		t.Fatal("CheckAndUpdate first use failed")
	}

	// freshly migrated row is in the default tenant
	if tenant, err := s.ClientTenant("host1"); err != nil || tenant != DefaultTenant {
		t.Fatalf("ClientTenant before stamp = %q, %v; want default", tenant, err)
	}

	if err := s.SetClientTenant("host1", "acme"); err != nil {
		t.Fatalf("SetClientTenant: %v", err)
	}
	if tenant, err := s.ClientTenant("host1"); err != nil || tenant != "acme" {
		t.Fatalf("ClientTenant = %q, %v; want acme", tenant, err)
	}

	if err := s.ClearBaseline("host1"); err != nil {
		t.Fatalf("ClearBaseline: %v", err)
	}
	if tenant, err := s.ClientTenant("host1"); err != nil || tenant != DefaultTenant {
		t.Fatalf("ClientTenant after clear = %q, %v; want default", tenant, err)
	}
}

func TestBaselineStore_TenantLifecycle(t *testing.T) {
	s := NewBaselineStore()

	if err := s.SetClientTenant("ghost", "acme"); err == nil {
		t.Fatal("SetClientTenant stamped a client with no baseline row")
	}

	pcr14 := [32]byte{0x14}
	if res, _ := s.CheckAndUpdate("host1", pcr14); res != TOFUFirstUse {
		t.Fatalf("CheckAndUpdate = %v, want TOFUFirstUse", res)
	}

	if tenant, err := s.ClientTenant("host1"); err != nil || tenant != DefaultTenant {
		t.Fatalf("ClientTenant before stamp = %q, %v; want default", tenant, err)
	}

	if err := s.SetClientTenant("host1", "acme"); err != nil {
		t.Fatalf("SetClientTenant: %v", err)
	}
	if tenant, err := s.ClientTenant("host1"); err != nil || tenant != "acme" {
		t.Fatalf("ClientTenant = %q, %v; want acme", tenant, err)
	}

	if err := s.ClearBaseline("host1"); err != nil {
		t.Fatalf("ClearBaseline: %v", err)
	}
	if tenant, err := s.ClientTenant("host1"); err != nil || tenant != DefaultTenant {
		t.Fatalf("ClientTenant after clear = %q, %v; want default", tenant, err)
	}
}

func TestIntegration_InvalidTenantCertRejected(t *testing.T) {
	result, err := attestWithCertOUs(t, "tenant-client-bad", []string{"Not A Tenant"})
	if err == nil {
		t.Fatal("attestation with a malformed tenant OU was accepted")
	}
	if result.Result != types.VerifySigFail {
		t.Fatalf("result = %d, want VerifySigFail (fail-closed)", result.Result)
	}
}

func TestIntegration_AmbiguousTenantCertRejected(t *testing.T) {
	result, err := attestWithCertOUs(t, "tenant-client-two", []string{"acme", "evil"})
	if err == nil {
		t.Fatal("attestation with two tenant OUs was accepted")
	}
	if result.Result != types.VerifySigFail {
		t.Fatalf("result = %d, want VerifySigFail (fail-closed)", result.Result)
	}
}

// attestWithBanStore runs one full attestation with the given ban store
// installed and the AIK certificate carrying the given tenant OU
func attestWithBanStore(t *testing.T, clientID string, ous []string, bans store.BanStore) (*types.VerifyResult, error) {
	t.Helper()

	cfg := DefaultConfig()
	cfg.RequireBootPCRs = false
	cfg.RequireInitramfsLock = false
	cfg.NonceLifetime = 1 * time.Second
	cfg.BanStore = bans
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

	pcr14 := [32]byte{}
	for i := range pcr14 {
		pcr14[i] = byte(0x14 ^ i)
	}

	testAIKCertOUs = ous
	defer func() { testAIKCertOUs = nil }()
	reportData := createValidReport(t, clientID, challenge.Nonce, pcr14)

	return verifier.VerifyReport(clientID, reportData)
}

// devicePseudonymHWID returns the hardware identity the verifier derives
// for test client: hex-decoded certificate pseudonym
func devicePseudonymHWID(t *testing.T, clientID string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(testPseudonym(clientID))
	if err != nil || len(raw) != 32 {
		t.Fatalf("test pseudonym is not a 32-byte hex identity: %v", err)
	}
	var hwid [32]byte
	copy(hwid[:], raw)
	return hwid
}

func TestIntegration_HardwareBanIsPerTenant(t *testing.T) {
	const clientID = "tenant-ban-client"
	hwid := devicePseudonymHWID(t, clientID)

	// banned in a DIFFERENT tenant: the client must attest cleanly
	bans := store.NewMemoryBanStore()
	if err := bans.BanHardware("other-game", hwid, store.RevocationCheating, "op", ""); err != nil {
		t.Fatalf("BanHardware(other-game): %v", err)
	}
	result, err := attestWithBanStore(t, clientID, []string{"acme-corp"}, bans)
	if err != nil {
		t.Fatalf("attestation rejected by a foreign tenant's ban: %v", err)
	}
	if result.Result != types.VerifyOK {
		t.Fatalf("result = %d, want VerifyOK", result.Result)
	}

	// banned in the client's OWN tenant: attestation must fail
	if err := bans.BanHardware("acme-corp", hwid, store.RevocationCheating, "op", ""); err != nil {
		t.Fatalf("BanHardware(acme-corp): %v", err)
	}
	result, err = attestWithBanStore(t, clientID, []string{"acme-corp"}, bans)
	if err == nil {
		t.Fatal("attestation accepted despite a ban in the client's tenant")
	}
	if result.Result != types.VerifyBanned {
		t.Fatalf("result = %d, want VerifyBanned", result.Result)
	}
}

func TestIntegration_DefaultTenantClientHitsDefaultBans(t *testing.T) {
	const clientID = "tenant-ban-plain"
	hwid := devicePseudonymHWID(t, clientID)

	// certificate without an OU lands in the default tenant,
	// so a default-tenant ban still rejects it
	bans := store.NewMemoryBanStore()
	if err := bans.BanHardware(DefaultTenant, hwid, store.RevocationCheating, "op", ""); err != nil {
		t.Fatalf("BanHardware(default): %v", err)
	}
	result, err := attestWithBanStore(t, clientID, nil, bans)
	if err == nil {
		t.Fatal("attestation accepted despite a default-tenant ban")
	}
	if result.Result != types.VerifyBanned {
		t.Fatalf("result = %d, want VerifyBanned", result.Result)
	}
}
