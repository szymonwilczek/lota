// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

// Package crl loads CRLs signed by trusted CAs and checks certificates
// against them; the verifier uses it for AIK certificates and the
// attestation CA for EK certificates.
package crl

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"
)

// Errors returned by BuildSet and Check.
var (
	ErrCertificateRevoked   = errors.New("certificate is revoked by configured CRL")
	ErrCRLStale             = errors.New("CRL is past its NextUpdate; refusing to trust issuer")
	ErrCRLSignature         = errors.New("CRL signature verification failed against trusted CAs")
	ErrCRLNoIssuer          = errors.New("CRL issuer is not among trusted CAs")
	ErrCRLMissingNextUpdate = errors.New("CRL is missing NextUpdate; RFC 5280 §5.1.2.5 requires it for production use")
	ErrCRLWeakSignature     = errors.New("CRL signature algorithm is not on the production allow-list")
	ErrNoTrustedCAs         = errors.New("no trusted CAs configured for CRL verification")
)

// x509.CheckSignatureFrom still accepts ECDSA-SHA1; no SHA-1 is allowed here.
var allowedSignatureAlgorithms = map[x509.SignatureAlgorithm]struct{}{
	x509.SHA256WithRSA:    {},
	x509.SHA384WithRSA:    {},
	x509.SHA512WithRSA:    {},
	x509.SHA256WithRSAPSS: {},
	x509.SHA384WithRSAPSS: {},
	x509.SHA512WithRSAPSS: {},
	x509.ECDSAWithSHA256:  {},
	x509.ECDSAWithSHA384:  {},
	x509.ECDSAWithSHA512:  {},
	x509.PureEd25519:      {},
}

// Set holds verified CRLs keyed by canonical issuer DN.
// A nil or empty Set revokes nothing.
type Set struct {
	byIssuer map[string][]*x509.RevocationList
}

// NewSet returns an empty Set.
func NewSet() *Set {
	return &Set{
		byIssuer: make(map[string][]*x509.RevocationList),
	}
}

// BuildSet loads every CRL in paths and returns them as a Set, or an error
// if any CRL fails to read, parse or verify. Each CRL must carry NextUpdate,
// use an algorithm of allowedSignatureAlgorithms and be signed by a CA in cas
// whose subject matches its issuer. A file holds one DER CRL or PEM blocks,
// of which only "X509 CRL" blocks are read. With no paths the Set is empty.
func BuildSet(paths []string, cas []*x509.Certificate) (*Set, error) {
	set := NewSet()
	for _, path := range paths {
		if err := set.loadAndVerify(path, cas); err != nil {
			return nil, fmt.Errorf("failed to load CRL %s: %w", path, err)
		}
	}
	return set, nil
}

func (s *Set) loadAndVerify(path string, cas []*x509.Certificate) error {
	if len(cas) == 0 {
		return ErrNoTrustedCAs
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read CRL %s: %w", path, err)
	}

	crls, err := parseCRL(data)
	if err != nil {
		return fmt.Errorf("parse CRL %s: %w", path, err)
	}

	for idx, crl := range crls {
		if err := s.verifyAndAdd(path, idx, crl, cas); err != nil {
			return err
		}
	}
	return nil
}

// verifyAndAdd reports a refused CRL by path and zero-based block index.
func (s *Set) verifyAndAdd(path string, idx int,
	crl *x509.RevocationList, cas []*x509.Certificate,
) error {
	// without NextUpdate a CRL would never go stale
	if crl.NextUpdate.IsZero() {
		return fmt.Errorf("%w: %s (block %d)",
			ErrCRLMissingNextUpdate, path, idx)
	}

	if _, ok := allowedSignatureAlgorithms[crl.SignatureAlgorithm]; !ok {
		return fmt.Errorf("%w: %s (block %d): %s",
			ErrCRLWeakSignature, path, idx, crl.SignatureAlgorithm)
	}

	// the key Check looks the certificate's issuer up by
	crlKey, err := canonicalIssuerKey(crl.RawIssuer)
	if err != nil {
		return fmt.Errorf("%s (block %d): canonicalise CRL issuer DN: %w",
			path, idx, err)
	}

	var sigErr error
	verified := false
	for _, ca := range cas {
		caKey, err := canonicalIssuerKey(ca.RawSubject)
		if err != nil {
			sigErr = fmt.Errorf("canonicalise CA subject DN: %w", err)
			continue
		}
		if caKey != crlKey {
			continue
		}
		if err := crl.CheckSignatureFrom(ca); err != nil {
			sigErr = err
			continue
		}
		verified = true
		break
	}
	if !verified {
		if sigErr != nil {
			return fmt.Errorf("%w: %s (block %d): %v",
				ErrCRLSignature, path, idx, sigErr)
		}
		return fmt.Errorf("%w: %s (block %d)", ErrCRLNoIssuer, path, idx)
	}

	s.byIssuer[crlKey] = append(s.byIssuer[crlKey], crl)
	return nil
}

// canonicalIssuerKey maps a DER Name to a key that ignores string type,
// AVA order inside an RDN, and case and whitespace of string values.
// RDN order is kept.
func canonicalIssuerKey(rawIssuer []byte) (string, error) {
	var seq pkix.RDNSequence
	if _, err := asn1.Unmarshal(rawIssuer, &seq); err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, rdn := range seq {
		sorted := make([]pkix.AttributeTypeAndValue, len(rdn))
		copy(sorted, rdn)
		sort.Slice(sorted, func(i, j int) bool {
			return cmpOID(sorted[i].Type, sorted[j].Type) < 0
		})
		for k, ava := range sorted {
			if k > 0 {
				sb.WriteByte(0x1f)
			}
			sb.WriteString(ava.Type.String())
			sb.WriteByte('=')
			switch v := ava.Value.(type) {
			case string:
				sb.WriteString(foldDirectoryString(v))
			case []byte:
				sb.WriteString(foldDirectoryString(string(v)))
			default:
				fmt.Fprintf(&sb, "%v", ava.Value)
			}
		}
		sb.WriteByte(0x1e)
	}
	return sb.String(), nil
}

// foldDirectoryString trims, collapses whitespace runs to one space and
// lowercases; there is no Unicode normalisation.
func foldDirectoryString(s string) string {
	fields := strings.Fields(s)
	return strings.ToLower(strings.Join(fields, " "))
}

func cmpOID(a, b asn1.ObjectIdentifier) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

func parseCRL(data []byte) ([]*x509.RevocationList, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		crl, err := x509.ParseRevocationList(data)
		if err != nil {
			return nil, err
		}
		return []*x509.RevocationList{crl}, nil
	}

	var out []*x509.RevocationList
	for blockIdx := 0; block != nil; blockIdx++ {
		if block.Type == "X509 CRL" {
			crl, err := x509.ParseRevocationList(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PEM block %d: %w", blockIdx, err)
			}
			out = append(out, crl)
		}
		block, rest = pem.Decode(rest)
	}
	if len(out) == 0 {
		return nil, errors.New("no X509 CRL PEM blocks found")
	}
	return out, nil
}

// Check returns ErrCertificateRevoked if a CRL of cert's issuer lists its
// serial, stale CRLs included, and ErrCRLStale if every such CRL is past
// NextUpdate at now. It returns nil when the Set holds no CRL of that issuer
// or the issuer cannot be parsed, so cert's chain must be verified first.
func (s *Set) Check(cert *x509.Certificate, now time.Time) error {
	if s == nil || len(s.byIssuer) == 0 {
		return nil
	}

	key, err := canonicalIssuerKey(cert.RawIssuer)
	if err != nil {
		return nil
	}
	crls, ok := s.byIssuer[key]
	if !ok || len(crls) == 0 {
		return nil
	}

	freshSeen := false
	for _, crl := range crls {
		if !crl.NextUpdate.IsZero() && !now.After(crl.NextUpdate) {
			freshSeen = true
		}

		// stale CRLs too: a fresh one must not hide a revocation
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber == nil {
				continue
			}
			if cmpSerial(entry.SerialNumber, cert.SerialNumber) == 0 {
				return fmt.Errorf("%w: serial=%s revocation_time=%s",
					ErrCertificateRevoked,
					cert.SerialNumber.String(),
					entry.RevocationTime.UTC().Format(time.RFC3339))
			}
		}
	}

	if !freshSeen {
		return fmt.Errorf("%w: issuer=%q", ErrCRLStale, cert.Issuer.String())
	}
	return nil
}

// Size returns the number of CRLs in s.
func (s *Set) Size() int {
	if s == nil {
		return 0
	}
	n := 0
	for _, crls := range s.byIssuer {
		n += len(crls)
	}
	return n
}

func cmpSerial(a, b *big.Int) int {
	if a == nil || b == nil {
		return -1
	}
	return a.Cmp(b)
}
