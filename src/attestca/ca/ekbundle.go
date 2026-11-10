// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

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

// EKClassRoot and EKClassIntermediate are the manifest classes:
// a root must be self-signed, an intermediate must not be.
const (
	EKClassRoot         = "root"
	EKClassIntermediate = "intermediate"
)

// Errors returned by LoadEKRootBundle.
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

// EKBundle is a loaded bundle: Roots for IssuerConfig.EKRootPEMs,
// Intermediates for IssuerConfig.EKIntermediatePEMs.
type EKBundle struct {
	Roots         [][]byte // PEM, self-signed
	Intermediates [][]byte // PEM, not self-signed
}

type ekBundleEntry struct {
	pin      string // lowercase hex SHA-256 of the DER
	filename string // bare name inside the bundle directory
	class    string
}

// LoadEKRootBundle loads the bundle in dir. Each line of EKBundleManifestName
// that is not empty and does not start with '#' is
//
//	<sha256-hex>  <pem-filename>  <class>  [label...]
//
// It fails on a missing or empty manifest, a malformed or duplicate line,
// a pinned file that is missing or does not hold exactly one certificate,
// a DER whose SHA-256 is not its pin, a root that is not self-signed or an
// intermediate that is, a manifest with no root, and a .pem file in dir
// that no line pins.
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

// isSelfSigned checks the issuer name and the signature.
func isSelfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

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
		})
	}
	return entries, nil
}

// readSingleCertPEM returns the DER and re-encoded PEM of the one CERTIFICATE
// block in path; blocks of other types are skipped.
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

// rejectUnpinnedCerts fails on a .pem file in dir, in any letter case,
// that pinned does not name; other files and subdirectories are not checked.
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
		if !strings.EqualFold(filepath.Ext(name), ".pem") {
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
