// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package enroll

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/attestca/internal/tpmtest"
)

// tokenDigest formats sha256(token) the way the token file records it.
func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// writeTokens writes a token file mapping each token to its tenant.
func writeTokens(t *testing.T, entries map[string]string) *EnrollmentTokens {
	t.Helper()
	var b strings.Builder
	b.WriteString("# tokens\n\n")
	for token, tenant := range entries {
		b.WriteString(tokenDigest(token) + " " + tenant + "\n")
	}
	tokens, err := LoadEnrollmentTokens(writeManifest(t, b.String()))
	if err != nil {
		t.Fatalf("LoadEnrollmentTokens: %v", err)
	}
	return tokens
}

func TestLoadEnrollmentTokensRejectsInvalid(t *testing.T) {
	digest := tokenDigest("tok")
	cases := map[string]string{
		"empty":          "# only comments\n",
		"short hash":     "abcd acme\n",
		"bad tenant":     digest + " Not-Valid\n",
		"missing tenant": digest + "\n",
		"extra field":    digest + " acme extra\n",
		"duplicate":      digest + " acme\n" + digest + " beta\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadEnrollmentTokens(writeManifest(t, content)); err == nil {
				t.Fatal("invalid token file was accepted")
			}
		})
	}
}

func TestTenantForToken(t *testing.T) {
	tokens := writeTokens(t, map[string]string{"alpha-token": "alpha"})

	if got, err := tokens.TenantFor([]byte("alpha-token")); err != nil || got != "alpha" {
		t.Fatalf("TenantFor(listed) = %q, %v; want alpha", got, err)
	}
	if _, err := tokens.TenantFor([]byte("wrong-token")); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("TenantFor(unlisted) = %v, want ErrTokenUnknown", err)
	}
	if _, err := tokens.TenantFor(nil); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("TenantFor(nil) = %v, want ErrTokenUnknown", err)
	}
	if _, err := tokens.TenantFor([]byte(strings.Repeat("x", MaxEnrollTokenLen+1))); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("TenantFor(oversize) = %v, want ErrTokenUnknown", err)
	}

	// no token set configured at all: every token fails closed
	var none *EnrollmentTokens
	if _, err := none.TenantFor([]byte("alpha-token")); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("nil set TenantFor = %v, want ErrTokenUnknown", err)
	}
}

func TestEnrollAssignsTenantFromToken(t *testing.T) {
	tokens := writeTokens(t, map[string]string{"beta-token": "beta"})
	svc, root := newTestService(t, WithEnrollmentTokens(tokens))
	ek := tpmtest.NewEKCert(t, root)

	cert, deviceID := enrollWith(t, svc, ek, []byte("beta-token"))
	if len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != "beta" {
		t.Fatalf("tenant OU = %v, want [beta]", cert.Subject.OrganizationalUnit)
	}
	if cert.Subject.CommonName != deviceID {
		t.Fatalf("CN %q != device id %q", cert.Subject.CommonName, deviceID)
	}

	// the same TPM without token lands in the default tenant with distinct pseudonym
	defCert, defID := enrollWith(t, svc, ek, nil)
	if len(defCert.Subject.OrganizationalUnit) != 0 {
		t.Fatalf("token-less enrollment carried an OU: %v", defCert.Subject.OrganizationalUnit)
	}
	if defID == deviceID {
		t.Fatal("token tenant did not change the device pseudonym")
	}
}

func TestEnrollRejectsUnknownToken(t *testing.T) {
	tokens := writeTokens(t, map[string]string{"beta-token": "beta"})
	svc, root := newTestService(t, WithEnrollmentTokens(tokens))
	ek := tpmtest.NewEKCert(t, root)
	aikTPMT, _ := tpmtest.AIKTemplate(t)

	if _, err := svc.Begin(ek.CertDER, aikTPMT, []byte("wrong-token")); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("Begin(unknown token) = %v, want ErrTokenUnknown", err)
	}
	// token rejection must not spend a session
	if svc.PendingCount() != 0 {
		t.Fatalf("rejected enrollment left a pending session: %d", svc.PendingCount())
	}

	// CA with no token set rejects every presented token instead of silently ignoring it
	plain, root2 := newTestService(t)
	ek2 := tpmtest.NewEKCert(t, root2)
	if _, err := plain.Begin(ek2.CertDER, aikTPMT, []byte("beta-token")); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("token against token-less CA = %v, want ErrTokenUnknown", err)
	}
}

func TestEnrollRequireToken(t *testing.T) {
	tokens := writeTokens(t, map[string]string{"beta-token": "beta"})
	svc, root := newTestService(t, WithEnrollmentTokens(tokens), WithRequireToken())
	ek := tpmtest.NewEKCert(t, root)
	aikTPMT, _ := tpmtest.AIKTemplate(t)

	if _, err := svc.Begin(ek.CertDER, aikTPMT, nil); !errors.Is(err, ErrTokenRequired) {
		t.Fatalf("token-less Begin = %v, want ErrTokenRequired", err)
	}
	if svc.PendingCount() != 0 {
		t.Fatalf("rejected enrollment left a pending session: %d", svc.PendingCount())
	}
	cert, _ := enrollWith(t, svc, ek, []byte("beta-token"))
	if len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != "beta" {
		t.Fatalf("tenant OU = %v, want [beta]", cert.Subject.OrganizationalUnit)
	}
}

func TestTokenOverridesEKManifest(t *testing.T) {
	root := tpmtest.NewVendorRoot(t, "tpm-vendor-root")
	ek := tpmtest.NewEKCert(t, root)

	// strict manifest that does NOT list this EK:
	// valid token still enrolls the device, because presented token
	// is the explicit assignment and the EK manifest path is not consulted
	other := tpmtest.NewEKCert(t, root)
	manifest, err := LoadTenantManifest(
		writeManifest(t, EKFingerprint(&other.Priv.PublicKey)+" acme\n"), true)
	if err != nil {
		t.Fatalf("LoadTenantManifest: %v", err)
	}
	tokens := writeTokens(t, map[string]string{"beta-token": "beta"})
	svc, _ := newTestServiceWithRoot(t, root,
		WithTenantManifest(manifest), WithEnrollmentTokens(tokens))

	cert, _ := enrollWith(t, svc, ek, []byte("beta-token"))
	if len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != "beta" {
		t.Fatalf("tenant OU = %v, want [beta]", cert.Subject.OrganizationalUnit)
	}

	// without the token the strict manifest still bars the unlisted EK
	aikTPMT, _ := tpmtest.AIKTemplate(t)
	if _, err := svc.Begin(ek.CertDER, aikTPMT, nil); err == nil {
		t.Fatal("strict manifest enrolled an unlisted EK without a token")
	}
}
