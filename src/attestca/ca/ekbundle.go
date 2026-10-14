// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Attestation CA - pinned multi-vendor EK trust bundle
//
// A deployment trusts EK certificates from several TPM manufacturers
// (Infineon, Intel, STM, AMD fTPM, Microsoft/AMD vTPM, ...).
// The roots themselves are published by each vendor and fetched out of band;
// what LOTA ships and version-controls is the pin manifest -- a fingerprint
// per certificate -- so a swapped or injected certificate cannot widen
// the trust set without the change showing up in the manifest.
//
// A bundle carries two kinds of certificate and the manifest says which is
// which. A root anchors a chain. An intermediate is path material: a firmware
// TPM keeps the certificates nearest its EK on the chip and sends them with
// the enrollment request, but the ones above those are published only by
// the vendor, so the operator has to supply them -- without making them
// anchors, which would trust one manufacturer branch as if it were the whole
// PKI.
//
// The loader is fail-closed: every manifest pin must resolve to a present,
// parseable certificate whose SHA-256 matches, every certificate in the bundle
// directory must be covered by a pin, every entry must carry a class
// the certificate can actually hold, and a bundle that anchors nothing is refused.

package ca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// EKBundleManifestName is the pin manifest a bundle directory must carry.
const EKBundleManifestName = "ek-roots.manifest"

// Manifest classes.
// A root is a trust anchor; an intermediate completes a path to one
// and never anchors a chain itself.
const (
	EKClassRoot         = "root"
	EKClassIntermediate = "intermediate"
)

var (
	ErrEKBundleManifest = errors.New("EK root bundle manifest is missing or unreadable")
	ErrEKBundleEmpty    = errors.New("EK root bundle manifest lists no roots")
	ErrEKBundleEntry    = errors.New("EK root bundle manifest entry is malformed")
	ErrEKBundleDup      = errors.New("EK root bundle manifest has a duplicate pin or filename")
	ErrEKBundleMissing  = errors.New("EK root bundle is missing a pinned root file")
	ErrEKBundlePEM      = errors.New("EK root bundle file is not a single certificate")
	ErrEKPinMismatch    = errors.New("EK root fingerprint does not match its pin")
	ErrEKBundleUnpinned = errors.New("EK root bundle directory holds an unpinned certificate")
	ErrEKBundleClass    = errors.New("EK root bundle manifest entry has no usable class")
	ErrEKBundleNoAnchor = errors.New("EK root bundle manifest pins no root, so it anchors no chain")
)

// EKBundle is a loaded trust bundle split the way the issuer consumes it:
// anchors a chain may terminate at, and path material it may build through.
type EKBundle struct {
	Roots         [][]byte // PEM, self-signed, trust anchors
	Intermediates [][]byte // PEM, path material only
}

// ekBundleEntry is one parsed manifest line: a SHA-256 pin over the
// certificate DER and the PEM file that must carry it.
type ekBundleEntry struct {
	pin      string // lowercase hex SHA-256 of the certificate DER
	filename string // PEM file relative to the bundle directory
	class    string // EKClassRoot or EKClassIntermediate
	label    string // free-text vendor label, for diagnostics only
}

// LoadEKRootBundle loads a pinned multi-vendor EK trust bundle from dir
// and returns it split into anchors and path material,
// ready for IssuerConfig.EKRootPEMs and IssuerConfig.EKIntermediatePEMs.
//
// dir must contain a pin manifest (EKBundleManifestName). Each non-empty,
// non-comment line is:
//
//	<sha256-hex>  <pem-filename>  <class>  <vendor label...>
//
// The load fails closed: a manifest that is absent, empty, or malformed; a
// pinned file that is missing, unparseable, or carries more than one
// certificate; a fingerprint that does not match its pin; a class the certificate
// cannot hold, because a root is self-signed and an intermediate is not; a bundle
// pinning no root at all; or a stray certificate in dir that no pin covers
// -- any of these is a hard error so the trusted manufacturer set cannot drift
// from the version-controlled manifest.
func LoadEKRootBundle(dir string) (*EKBundle, error) {
	manifestPath := filepath.Join(dir, EKBundleManifestName)
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrEKBundleManifest, manifestPath, err)
	}

	entries, err := parseEKBundleManifest(manifest)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, ErrEKBundleEmpty
	}

	pinned := make(map[string]struct{}, len(entries))
	out := &EKBundle{}
	for _, e := range entries {
		path := filepath.Join(dir, e.filename)
		der, pemBytes, err := readSingleCertPEM(path)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(der)
		got := hex.EncodeToString(sum[:])
		if got != e.pin {
			return nil, fmt.Errorf("%w: %s: pinned %s, found %s",
				ErrEKPinMismatch, e.filename, e.pin, got)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrEKBundlePEM, path, err)
		}

		// the class is a claim about the certificate, so it is checked against
		// the certificate: an anchor must be self-signed, and path material
		// must not be, or the operator has pinned something other than what
		// they wrote down
		selfSigned := isSelfSigned(cert)
		switch {
		case e.class == EKClassRoot && !selfSigned:
			return nil, fmt.Errorf("%w: %s is classed %s but is issued by %q",
				ErrEKBundleClass, e.filename, EKClassRoot, cert.Issuer)
		case e.class == EKClassIntermediate && selfSigned:
			return nil, fmt.Errorf("%w: %s is classed %s but is self-signed",
				ErrEKBundleClass, e.filename, EKClassIntermediate)
		}
		pinned[e.filename] = struct{}{}
		if e.class == EKClassRoot {
			out.Roots = append(out.Roots, pemBytes)
		} else {
			out.Intermediates = append(out.Intermediates, pemBytes)
		}
	}

	if len(out.Roots) == 0 {
		return nil, ErrEKBundleNoAnchor
	}
	if err := rejectUnpinnedCerts(dir, pinned); err != nil {
		return nil, err
	}
	return out, nil
}

// isSelfSigned reports whether a certificate is its own issuer by name
// and by signature -- the name alone is a claim anyone can make.
func isSelfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

// parseEKBundleManifest decodes manifest lines into pinned entries and
// rejects duplicate pins or filenames so two lines cannot disagree.
func parseEKBundleManifest(data []byte) ([]ekBundleEntry, error) {
	var entries []ekBundleEntry
	seenPin := map[string]struct{}{}
	seenFile := map[string]struct{}{}

	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("%w: line %d", ErrEKBundleEntry, i+1)
		}
		pin := strings.ToLower(fields[0])
		if len(pin) != sha256.Size*2 || !isHex(pin) {
			return nil, fmt.Errorf("%w: line %d: bad SHA-256 pin", ErrEKBundleEntry, i+1)
		}
		filename := fields[1]
		if filename != filepath.Base(filename) || filename == "." || filename == ".." {
			return nil, fmt.Errorf("%w: line %d: filename must be a bare name", ErrEKBundleEntry, i+1)
		}
		if _, dup := seenPin[pin]; dup {
			return nil, fmt.Errorf("%w: pin %s", ErrEKBundleDup, pin)
		}
		if _, dup := seenFile[filename]; dup {
			return nil, fmt.Errorf("%w: file %s", ErrEKBundleDup, filename)
		}
		class := fields[2]
		if class != EKClassRoot && class != EKClassIntermediate {
			return nil, fmt.Errorf("%w: line %d: class must be %s or %s, not %q",
				ErrEKBundleClass, i+1, EKClassRoot, EKClassIntermediate, class)
		}
		seenPin[pin] = struct{}{}
		seenFile[filename] = struct{}{}
		entries = append(entries, ekBundleEntry{
			pin:      pin,
			filename: filename,
			class:    class,
			label:    strings.Join(fields[3:], " "),
		})
	}
	return entries, nil
}

// readSingleCertPEM reads a PEM file that must hold exactly one CERTIFICATE
// block, returning its DER and the re-encoded PEM. More than one
// certificate is rejected so a pin is unambiguous.
func readSingleCertPEM(path string) (der, pemBytes []byte, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s: %v", ErrEKBundleMissing, path, err)
	}

	var certDER []byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if certDER != nil {
			return nil, nil, fmt.Errorf("%w: %s", ErrEKBundlePEM, path)
		}
		certDER = block.Bytes
	}
	if certDER == nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrEKBundlePEM, path)
	}
	if _, err := x509.ParseCertificate(certDER); err != nil {
		return nil, nil, fmt.Errorf("%w: %s: %v", ErrEKBundlePEM, path, err)
	}
	return certDER, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

// rejectUnpinnedCerts fails if the bundle directory holds a .pem file that
// no manifest entry pins, closing the door on an injected root that a less
// careful loader might otherwise pick up.
func rejectUnpinnedCerts(dir string, pinned map[string]struct{}) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrEKBundleManifest, dir, err)
	}
	var stray []string
	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasSuffix(name, ".pem") {
			continue
		}
		if _, ok := pinned[name]; !ok {
			stray = append(stray, name)
		}
	}
	if len(stray) > 0 {
		sort.Strings(stray)
		return fmt.Errorf("%w: %s", ErrEKBundleUnpinned, strings.Join(stray, ", "))
	}
	return nil
}

func isHex(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
