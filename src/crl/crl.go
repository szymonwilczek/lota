// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA - Certificate Revocation List (CRL) verification
//
// Shared CRL engine for the LOTA services that consume operator-supplied
// revocation feeds: the verifier checks AIK certificates against the
// deployment CA's CRLs and the attestation CA checks endorsement-key
// certificates against TPM manufacturer CRLs.
//
// Both load RFC 5280 CRLs at startup, verify each CRL signature against
// their configured trust anchors, and consult a lookup by (issuer, serial)
// before accepting a certificate.
//
// Production deployments refresh a CRL feed by writing the new file
// atomically onto the configured path and sending the daemon SIGHUP:
// the signal handler rebuilds the set via BuildSet, which re-validates
// every CRL against the trusted CAs, and atomically swaps the active set
// on success.
//
// Failed reload leaves the previous set in place so a malformed update cannot
// drop revocations on the floor.
//
// Stale CRLs (NextUpdate < now) fail closed.
//
// CRLs without a NextUpdate field are rejected at load time (RFC 5280 p5.1.2.5):
// without an upper bound on freshness the staleness check has no semantic meaning.

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

// revocation lookup errors
var (
	ErrCertificateRevoked   = errors.New("certificate is revoked by configured CRL")
	ErrCRLStale             = errors.New("CRL is past its NextUpdate; refusing to trust issuer")
	ErrCRLSignature         = errors.New("CRL signature verification failed against trusted CAs")
	ErrCRLNoIssuer          = errors.New("CRL issuer is not among trusted CAs")
	ErrCRLMissingNextUpdate = errors.New("CRL is missing NextUpdate; RFC 5280 §5.1.2.5 requires it for production use")
	ErrCRLWeakSignature     = errors.New("CRL signature algorithm is not on the production allow-list")
	ErrNoTrustedCAs         = errors.New("no trusted CAs configured for CRL verification")
)

// allowedSignatureAlgorithms enumerates the signature algorithms a CRL
// signature MUST use to be honored.
// Nothing below is SHA-1: CRL signature decides whether revocation is visible
// at all, so collision-prone digest is not acceptable there.
//
// The list exists because Go's own check is more permissive than that.
// x509.CheckSignatureFrom refuses MD5 and RSA-SHA1, but it still accepts ECDSA-SHA1,
// so relying on it alone would honor CRL LOTA should not.
// This allow-list is the narrower gate, not compatibility shim.
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

// Set holds CRLs grouped by issuer subject DN.
//
// Single set may contain multiple CRLs. Lookups iterate every list
// whose Issuer matches the certificate Issuer; the cert is revoked if
// any matching list contains its serial number, and the issuer is
// flagged stale if every matching list is past NextUpdate.
type Set struct {
	byIssuer map[string][]*x509.RevocationList
}

func NewSet() *Set {
	return &Set{
		byIssuer: make(map[string][]*x509.RevocationList),
	}
}

// BuildSet parses every CRL path against the supplied trust anchors and
// returns a fully-validated set.
// Callers use it for both the initial startup build and the SIGHUP hot-swap
// path so the two apply identical gates.
// On any error the caller keeps its previous set.
func BuildSet(paths []string, cas []*x509.Certificate) (*Set, error) {
	set := NewSet()
	for _, path := range paths {
		if err := set.loadAndVerify(path, cas); err != nil {
			return nil, fmt.Errorf("failed to load CRL %s: %w", path, err)
		}
	}
	return set, nil
}

// loadAndVerify parses a CRL file, verifies every CRL it contains
// against the supplied CA pool, and adds each accepted CRL to the set.
// File may carry multiple concatenated PEM "X509 CRL" blocks and each
// block is validated independently.
// CRL whose signature does not chain to any configured CA, or whose NextUpdate
// is absent, is rejected up front so misconfiguration surfaces at startup rather
// than at attestation time.
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

// verifyAndAdd applies the per-CRL freshness and signature gates and,
// on success, attaches the CRL to byIssuer under its raw subject DN.
// Errors are wrapped with the source path and the zero-based index of
// the CRL inside the file so operators can tell which block in a
// multi-CRL bundle was rejected.
func (s *Set) verifyAndAdd(path string, idx int,
	crl *x509.RevocationList, cas []*x509.Certificate,
) error {
	// RFC 5280 p5.1.2.5 marks NextUpdate as OPTIONAL at the ASN.1 level
	// but mandates it for production profiles.
	// Without NextUpdate the staleness check in Check() has no upper bound,
	// so a CRL that omits the field would silently be honored forever -
	// defeating the fail-closed contract documented at the top of this file.
	// Reject at load time so operators see the misconfiguration at startup
	// instead at the first attestation.
	if crl.NextUpdate.IsZero() {
		return fmt.Errorf("%w: %s (block %d)",
			ErrCRLMissingNextUpdate, path, idx)
	}

	if _, ok := allowedSignatureAlgorithms[crl.SignatureAlgorithm]; !ok {
		return fmt.Errorf("%w: %s (block %d): %s",
			ErrCRLWeakSignature, path, idx, crl.SignatureAlgorithm)
	}

	// Signature must verify against one of the trusted CA certificates
	// whose Subject matches the CRL Issuer DN.
	// Match runs against canonicalIssuerKey() on both sides instead of
	// bytes.Equal on RawSubject / RawIssuer: a CA that re-encoded its DN
	// between issuing its own cert and signing the CRL (PrintableString
	// vs UTF8String for the same ASCII text, swapped AVA order inside
	// a multi-AVA RDN, whitespace / case drift in non-CN attributes -
	// all permitted by RFC 5280 p4.1.2.4) would otherwise fail the
	// byte-equal gate, drop the CRL at load time, and silently land in
	// the "no CRL configured for this issuer" fail-open branch at
	// lookup time.
	// Anchoring both sides to canonicalIssuerKey() keeps the same
	// canonicalisation invariant the runtime lookup path already uses,
	// so a load-time accept implies a lookup-time hit for the same DN.
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
			// CA whose Subject DN cannot be parsed should never
			// have made it into the trust store; skip it instead
			// of letting one malformed CA mask other roots
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

// canonicalIssuerKey produces a deterministic lookup key for an
// X.500 Name encoded as DER bytes.
// Production TPM manufacturer CAs re-encode the same logical issuer
// DN in subtly different ways across CRL refreshes (PrintableString
// vs UTF8String for the same ASCII value, swapped order of AVAs inside
// a multi-AVA RDN, leading/trailing whitespace, case in non-CN
// attributes), and the raw byte-equal key the original implementation
// used would index each variation under a separate bucket so a cert.Issuer
// that matched one variation would miss the others.
// Anchor the key to the parsed RDN sequence with per-RDN AVA sorting + case
// + whitespace folding of DirectoryString-shaped values.
//
// This function intentionally preserves the RDN order itself: RFC
// 5280 Names are hierarchical (C, O, OU, CN ...) and reordering
// RDNs would change identity.
// Only the unordered multi-AVA SET inside one RDN gets sorted.
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
				sb.WriteByte(0x1f) // unit separator: between AVAs in an RDN
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
		sb.WriteByte(0x1e) // record separator: between RDNs
	}
	return sb.String(), nil
}

// foldDirectoryString applies RFC 4518 string-prep style folding for
// caseIgnoreMatch attribute matching: trim surrounding whitespace,
// collapse internal whitespace to single SPACE, lowercase.
// This is the minimal set that handles the common variations seen
// across CA re-encodes and is intentionally narrower than the full
// RFC 4518 machinery (no Unicode normalisation, no character mapping
// table) to keep the code readable.
func foldDirectoryString(s string) string {
	fields := strings.Fields(s) // collapses any run of whitespace
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

// parseCRL accepts a CRL file in PEM (-----BEGIN X509 CRL-----) form,
// including bundles that concatenate multiple PEM blocks in one file
// (one CRL per BEGIN/END pair).
// Non-CRL PEM blocks are skipped so a bundle interleaved with informational
// headers or trust-anchor copies still loads cleanly.
// Single DER-encoded CRL is also accepted for tooling convenience.
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

// Check returns nil if cert is not present in any matching CRL.
// Caller is expected to invoke this only after chain verification has
// already established the certificate's issuer is trusted.
func (s *Set) Check(cert *x509.Certificate, now time.Time) error {
	if s == nil || len(s.byIssuer) == 0 {
		return nil
	}

	// Match the certificate's issuer DN against the canonicalised key
	// the load path used.
	// Failure to parse the cert's RawIssuer is treated as
	// "no CRL configured for this issuer": x509.ParseCertificate already
	// accepted the cert, so the RawIssuer bytes are well-formed ASN.1,
	// but if a future codepath feeds in a malformed DER, leans
	// fail-open instead fail-noisy here - the caller has already
	// gated on chain verification.
	key, err := canonicalIssuerKey(cert.RawIssuer)
	if err != nil {
		return nil
	}
	crls, ok := s.byIssuer[key]
	if !ok || len(crls) == 0 {
		// no CRL configured for this issuer: nothing to check
		return nil
	}

	freshSeen := false
	for _, crl := range crls {
		// loadAndVerify rejects CRLs without NextUpdate, but defend in
		// depth: any zero NextUpdate that reaches this path is treated
		// as immediately stale
		if !crl.NextUpdate.IsZero() && !now.After(crl.NextUpdate) {
			freshSeen = true
		}

		// scan every matching CRL regardless of its freshness
		// staleness may only add distrust, never erase a revocation already
		// published for this issuer:
		// skipping stale CRLs here would let fresh sibling mask a revocation
		// carried only by a now-stale one
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

	// no CRL for this issuer is current:
	// with no fresh revocation feed the certificate cannot be proven unrevoked,
	// so fail closed
	if !freshSeen {
		return fmt.Errorf("%w: issuer=%q", ErrCRLStale, cert.Issuer.String())
	}
	return nil
}

// Size returns the total number of CRLs held
// Useful for startup logs and unit-test assertions
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
