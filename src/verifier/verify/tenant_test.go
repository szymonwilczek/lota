// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - device tenant extraction tests

package verify

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"

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

func TestIntegration_TenantCertAttests(t *testing.T) {
	result, err := attestWithCertOUs(t, "tenant-client-ok", []string{"acme-corp"})
	if err != nil {
		t.Fatalf("attestation with a tenant OU failed: %v", err)
	}
	if result.Result != types.VerifyOK {
		t.Fatalf("result = %d, want VerifyOK", result.Result)
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
