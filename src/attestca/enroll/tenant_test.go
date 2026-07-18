// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package enroll

import (
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/attestca/ca"
	"github.com/szymonwilczek/lota/attestca/internal/tpmtest"
)

// newTestServiceWithRoot builds a Service that trusts the given vendor
// root, so a caller can enroll the same EK against several services.
func newTestServiceWithRoot(tb testing.TB, root tpmtest.Root, opts ...Option) (*Service, tpmtest.Root) {
	tb.Helper()
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

func TestValidTenantName(t *testing.T) {
	valid := []string{"a", "default", "acme-corp", "t1", "0", strings.Repeat("x", MaxTenantLen)}
	for _, name := range valid {
		if !ValidTenantName(name) {
			t.Errorf("ValidTenantName(%q) = false, want true", name)
		}
	}
	invalid := []string{"", "-a", "a-", "A", "a.b", "a b", "a/b", "ac_me", strings.Repeat("x", MaxTenantLen+1)}
	for _, name := range invalid {
		if ValidTenantName(name) {
			t.Errorf("ValidTenantName(%q) = true, want false", name)
		}
	}
}

func writeManifest(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

func TestLoadTenantManifest(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	fp2 := strings.Repeat("cd", 32)
	path := writeManifest(t, "# comment\n\n"+fp+" acme\n"+fp2+"   beta\n")

	m, err := LoadTenantManifest(path, false)
	if err != nil {
		t.Fatalf("LoadTenantManifest: %v", err)
	}
	if got := m.byFingerprint[fp]; got != "acme" {
		t.Fatalf("fp -> %q, want acme", got)
	}
	if got := m.byFingerprint[fp2]; got != "beta" {
		t.Fatalf("fp2 -> %q, want beta", got)
	}
}

func TestLoadTenantManifestRejectsInvalid(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	cases := map[string]string{
		"empty":          "# only comments\n",
		"short hash":     "abcd acme\n",
		"bad tenant":     fp + " Not-Valid\n",
		"missing tenant": fp + "\n",
		"extra field":    fp + " acme extra\n",
		"duplicate":      fp + " acme\n" + fp + " beta\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadTenantManifest(writeManifest(t, content), false); err == nil {
				t.Fatal("invalid manifest was accepted")
			}
		})
	}
}

func TestTenantForDefaultAndStrict(t *testing.T) {
	root := tpmtest.NewVendorRoot(t, "tpm-vendor-root")
	ek := tpmtest.NewEKCert(t, root)
	ekPub := &ek.Priv.PublicKey

	// nil manifest: everything is the default tenant
	var nilm *TenantManifest
	if got, err := nilm.TenantFor(ekPub); err != nil || got != DefaultTenant {
		t.Fatalf("nil manifest TenantFor = %q, %v; want default", got, err)
	}

	// listed EK maps to its tenant
	path := writeManifest(t, EKFingerprint(ekPub)+" acme\n")
	m, err := LoadTenantManifest(path, false)
	if err != nil {
		t.Fatalf("LoadTenantManifest: %v", err)
	}
	if got, err := m.TenantFor(ekPub); err != nil || got != "acme" {
		t.Fatalf("listed EK TenantFor = %q, %v; want acme", got, err)
	}

	// unlisted EK: default when lax, rejected when strict
	other := tpmtest.NewEKCert(t, root)
	if got, err := m.TenantFor(&other.Priv.PublicKey); err != nil || got != DefaultTenant {
		t.Fatalf("unlisted lax TenantFor = %q, %v; want default", got, err)
	}

	strictPath := writeManifest(t, EKFingerprint(ekPub)+" acme\n")
	sm, err := LoadTenantManifest(strictPath, true)
	if err != nil {
		t.Fatalf("LoadTenantManifest strict: %v", err)
	}
	if _, err := sm.TenantFor(&other.Priv.PublicKey); err == nil {
		t.Fatal("strict manifest accepted an unlisted EK")
	}
}

// enrollWith runs a full ceremony, presenting an optional enrollment token,
// and returns the issued certificate and device id.
func enrollWith(t *testing.T, svc *Service, ek tpmtest.EK, token []byte) (*x509.Certificate, string) {
	t.Helper()
	aikTPMT, aikName := tpmtest.AIKTemplate(t)
	ch, err := svc.Begin(ek.CertDER, aikTPMT, token)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	recovered := tpmtest.SoftwareActivate(t, ek.Priv, aikName, ch.CredentialBlob, ch.EncryptedSecret)
	certDER, deviceID, err := svc.Complete(ch.SessionID, recovered)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, deviceID
}

func TestEnrollAssignsTenantFromManifest(t *testing.T) {
	svcDefault, root := newTestService(t)
	ek := tpmtest.NewEKCert(t, root)

	// baseline: no manifest -> default tenant, no OU
	defCert, defID := enrollWith(t, svcDefault, ek, nil)
	if len(defCert.Subject.OrganizationalUnit) != 0 {
		t.Fatalf("default enrollment carried an OU: %v", defCert.Subject.OrganizationalUnit)
	}

	// manifest maps this EK to acme
	path := writeManifest(t, EKFingerprint(&ek.Priv.PublicKey)+" acme\n")
	m, err := LoadTenantManifest(path, false)
	if err != nil {
		t.Fatalf("LoadTenantManifest: %v", err)
	}
	svcTenant, _ := newTestServiceWithRoot(t, root, WithTenantManifest(m))
	acmeCert, acmeID := enrollWith(t, svcTenant, ek, nil)

	if len(acmeCert.Subject.OrganizationalUnit) != 1 || acmeCert.Subject.OrganizationalUnit[0] != "acme" {
		t.Fatalf("tenant OU = %v, want [acme]", acmeCert.Subject.OrganizationalUnit)
	}
	if acmeCert.Subject.CommonName != acmeID {
		t.Fatalf("CN %q != device id %q", acmeCert.Subject.CommonName, acmeID)
	}
	// the same TPM in a different tenant must not collide on the device id
	if acmeID == defID {
		t.Fatal("tenant did not change the device pseudonym: cross-tenant collision")
	}
}

// TestDefaultTenantKeepsLegacyPseudonym pins the default-tenant device ID
// to the pre-tenant EK-only derivation, so a device enrolled before tenant
// assignment re-enrolls under the same pseudonym and keeps its verifier
// state (baselines, standing revocations) across a CA upgrade.
func TestDefaultTenantKeepsLegacyPseudonym(t *testing.T) {
	svc, root := newTestService(t)
	ek := tpmtest.NewEKCert(t, root)

	_, id := enrollWith(t, svc, ek, nil)
	legacy := hex.EncodeToString(hmacSHA256(
		[]byte("pseudonym-key-0123456789abcdef"), ek.Priv.PublicKey.N.Bytes()))
	if id != legacy {
		t.Fatalf("default-tenant device ID %q != legacy EK-only derivation %q", id, legacy)
	}
}

func TestEnrollStrictManifestRejectsUnlistedEK(t *testing.T) {
	root := tpmtest.NewVendorRoot(t, "tpm-vendor-root")
	listed := tpmtest.NewEKCert(t, root)
	path := writeManifest(t, EKFingerprint(&listed.Priv.PublicKey)+" acme\n")
	m, err := LoadTenantManifest(path, true)
	if err != nil {
		t.Fatalf("LoadTenantManifest: %v", err)
	}
	svc, _ := newTestServiceWithRoot(t, root, WithTenantManifest(m))

	unlisted := tpmtest.NewEKCert(t, root)
	aikTPMT, _ := tpmtest.AIKTemplate(t)
	if _, err := svc.Begin(unlisted.CertDER, aikTPMT, nil); err == nil {
		t.Fatal("strict manifest enrolled an unlisted EK")
	}
	// strict rejection must not spend a session
	if svc.PendingCount() != 0 {
		t.Fatalf("rejected enrollment left a pending session: %d", svc.PendingCount())
	}
}
