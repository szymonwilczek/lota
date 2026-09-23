// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package ca

import (
	"errors"
	"testing"
	"time"
)

// firmwarePKI models the shape a firmware TPM ships with: an EK leaf several
// levels below the vendor root, where the certificates nearest the leaf are
// published nowhere and live only on the chip, and the ones nearer the root
// can be fetched and pinned by the operator ahead of time.
type firmwarePKI struct {
	root      certAndKey
	published []certAndKey // operator can obtain these and pin them
	onChip    []certAndKey // only the device has these
	ekDER     []byte
}

func newFirmwarePKI(tb testing.TB) firmwarePKI {
	tb.Helper()
	root := makeRoot(tb, "vendor-ondie-root")
	issuing := makeIntermediate(tb, root, "vendor-ondie-intermediate")
	platform := makeIntermediate(tb, issuing, "vendor-ondie-issuing")
	rom := makeIntermediate(tb, platform, "vendor-rom-ca")
	kernel := makeIntermediate(tb, rom, "vendor-kernel-ca")
	ptt := makeIntermediate(tb, kernel, "vendor-ptt-svn")
	ekDER, _ := makeEKCert(tb, ptt, nil)
	return firmwarePKI{
		root:      root,
		published: []certAndKey{issuing, platform},
		onChip:    []certAndKey{rom, kernel, ptt},
		ekDER:     ekDER,
	}
}

func (p firmwarePKI) issuer(tb testing.TB, pinned ...certAndKey) *Issuer {
	tb.Helper()
	caCertPEM, caKeyPEM := makeLOTACAPEM(tb)
	pems := make([][]byte, 0, len(pinned))
	for _, c := range pinned {
		pems = append(pems, pemBlock("CERTIFICATE", c.der))
	}
	is, err := NewIssuer(IssuerConfig{CACertPEM: caCertPEM, CAKeyPEM: caKeyPEM, EKRootPEMs: pems})
	if err != nil {
		tb.Fatalf("NewIssuer: %v", err)
	}
	return is
}

func (p firmwarePKI) onChipDER() [][]byte {
	out := make([][]byte, 0, len(p.onChip))
	for _, c := range p.onChip {
		out = append(out, c.der)
	}
	return out
}

// The certificates between the leaf and the published part of the vendor PKI
// exist only on the chip, so the device is the only party that can supply
// them. Without them a correctly configured CA -- right root, pinned, and the
// published intermediates alongside it -- still has a hole in the path and
// refuses a genuine TPM.
func TestVerifyEKCertificateNeedsDeviceSuppliedIntermediates(t *testing.T) {
	pki := newFirmwarePKI(t)
	is := pki.issuer(t, append([]certAndKey{pki.root}, pki.published...)...)

	if _, err := is.VerifyEKCertificate(pki.ekDER, nil, time.Now()); !errors.Is(err, ErrEKChain) {
		t.Fatalf("leaf without the on-chip intermediates: want ErrEKChain, got %v", err)
	}
	if _, err := is.VerifyEKCertificate(pki.ekDER, pki.onChipDER(), time.Now()); err != nil {
		t.Fatalf("leaf with the on-chip intermediates: %v", err)
	}
}

// The published intermediates are the operator's half of the same path: they
// are pinned in the bundle so the CA fetches nothing while an enrollment is in
// flight. A device that supplies its half is still refused without them.
func TestVerifyEKCertificateNeedsPinnedIntermediates(t *testing.T) {
	pki := newFirmwarePKI(t)
	is := pki.issuer(t, pki.root)

	if _, err := is.VerifyEKCertificate(pki.ekDER, pki.onChipDER(), time.Now()); !errors.Is(err, ErrEKChain) {
		t.Fatalf("root alone: want ErrEKChain, got %v", err)
	}
}

// The whole point of the supplied chain is that it is path material and
// nothing more. A device that sends its own self-signed root, and a leaf
// issued under it, must be refused -- otherwise any host could name its own
// manufacturer and the pinned bundle would decide nothing.
func TestSuppliedChainCannotWidenTheTrustSet(t *testing.T) {
	pki := newFirmwarePKI(t)
	is := pki.issuer(t, append([]certAndKey{pki.root}, pki.published...)...)

	rogueRoot := makeRoot(t, "rogue-vendor-root")
	rogueIssuing := makeIntermediate(t, rogueRoot, "rogue-issuing")
	rogueEK, _ := makeEKCert(t, rogueIssuing, nil)

	supplied := [][]byte{rogueIssuing.der, rogueRoot.der}
	if _, err := is.VerifyEKCertificate(rogueEK, supplied, time.Now()); !errors.Is(err, ErrEKChain) {
		t.Fatalf("self-signed chain from the device: want ErrEKChain, got %v", err)
	}

	// and the same anchor cannot be smuggled in beside a genuine chain
	mixed := append(pki.onChipDER(), rogueRoot.der, rogueIssuing.der)
	if _, err := is.VerifyEKCertificate(rogueEK, mixed, time.Now()); !errors.Is(err, ErrEKChain) {
		t.Fatalf("rogue leaf beside a genuine chain: want ErrEKChain, got %v", err)
	}
}

// The chain arrives from a peer that has proved nothing, so unusable elements
// are dropped.
func TestSuppliedChainIgnoresUnusableElements(t *testing.T) {
	pki := newFirmwarePKI(t)
	is := pki.issuer(t, append([]certAndKey{pki.root}, pki.published...)...)

	supplied := append([][]byte{{0x30, 0x01, 0xFF}, {}}, pki.onChipDER()...)
	if _, err := is.VerifyEKCertificate(pki.ekDER, supplied, time.Now()); err != nil {
		t.Fatalf("chain carrying unparseable elements: %v", err)
	}
}

// A platform whose leaf is issued directly by a pinned root supplies no chain
// and has to keep verifying exactly as it does today.
func TestVerifyEKCertificateWithoutChainStillWorks(t *testing.T) {
	root := makeRoot(t, "discrete-tpm-root")
	caCertPEM, caKeyPEM := makeLOTACAPEM(t)
	is, err := NewIssuer(IssuerConfig{
		CACertPEM:  caCertPEM,
		CAKeyPEM:   caKeyPEM,
		EKRootPEMs: [][]byte{pemBlock("CERTIFICATE", root.der)},
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	ekDER, _ := makeEKCert(t, root, nil)
	if _, err := is.VerifyEKCertificate(ekDER, nil, time.Now()); err != nil {
		t.Fatalf("leaf under a pinned root: %v", err)
	}
}
