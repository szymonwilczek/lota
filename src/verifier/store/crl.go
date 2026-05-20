// SPDX-License-Identifier: MIT
// LOTA Verifier - Certificate Revocation List (CRL) support
//
// Loads operator-supplied CRLs (RFC 5280) at verifier startup, verifies
// each CRL signature against the trusted CA roots configured on the
// CertificateStore, and exposes a lookup by (issuer, serial) that the
// EK/AIK verification paths consult before accepting a certificate.
//
// Production deployments refresh a CRL feed by writing the new file
// atomically onto the configured --ek-crl path and sending the verifier
// SIGHUP: the signal handler in src/verifier/main.go calls
// CertificateStore.ReloadCRLs(), which re-validates every CRL against
// the trusted CAs and atomically swaps the active set on success. A
// failed reload leaves the previous set in place so a malformed update
// cannot drop revocations on the floor. Stale CRLs (NextUpdate < now)
// fail closed. CRLs without a NextUpdate field are rejected at load
// time (RFC 5280 p5.1.2.5): without an upper bound on freshness the
// staleness check has no semantic meaning.

package store

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
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
)

// crlAllowedSignatureAlgorithms enumerates the signature algorithms a
// CRL signature MUST use to be honored. Go's x509.CheckSignatureFrom
// already refuses MD5 and RSA-SHA1, but it still accepts ECDSA-SHA1
// and other legacy combinations.
var crlAllowedSignatureAlgorithms = map[x509.SignatureAlgorithm]struct{}{
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

// revocationListSet holds CRLs grouped by issuer subject DN.
//
// A single set may contain multiple CRLs. Lookups iterate every list
// whose Issuer matches the certificate Issuer; the cert is revoked if
// any matching list contains its serial number, and the issuer is
// flagged stale if every matching list is past NextUpdate.
type revocationListSet struct {
	byIssuer map[string][]*x509.RevocationList
}

func newRevocationListSet() *revocationListSet {
	return &revocationListSet{
		byIssuer: make(map[string][]*x509.RevocationList),
	}
}

// loadAndVerify parses a CRL file, verifies every CRL it contains
// against the supplied CA pool, and adds each accepted CRL to the set.
// A file may carry multiple concatenated PEM "X509 CRL" blocks and each
// block is validated independently. A CRL whose signature does not chain
// to any configured CA, or whose NextUpdate is absent, is rejected up
// front so misconfiguration surfaces at startup rather than at attestation time.
func (s *revocationListSet) loadAndVerify(path string, cas []*x509.Certificate) error {
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
func (s *revocationListSet) verifyAndAdd(path string, idx int,
	crl *x509.RevocationList, cas []*x509.Certificate) error {

	// RFC 5280 p5.1.2.5 marks NextUpdate as OPTIONAL at the ASN.1 level
	// but mandates it for production profiles. Without NextUpdate the
	// staleness check in check() has no upper bound, so a CRL that omits
	// the field would silently be honored forever - defeating the
	// fail-closed contract documented at the top of this file. Reject
	// at load time so operators see the misconfiguration at startup
	// rather than at the first attestation.
	if crl.NextUpdate.IsZero() {
		return fmt.Errorf("%w: %s (block %d)",
			ErrCRLMissingNextUpdate, path, idx)
	}

	if _, ok := crlAllowedSignatureAlgorithms[crl.SignatureAlgorithm]; !ok {
		return fmt.Errorf("%w: %s (block %d): %s",
			ErrCRLWeakSignature, path, idx, crl.SignatureAlgorithm)
	}

	// signature must verify against one of the trusted CA certificates
	// whose Subject matches the CRL Issuer DN.
	var sigErr error
	verified := false
	for _, ca := range cas {
		if !bytes.Equal(ca.RawSubject, crl.RawIssuer) {
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

	key := string(crl.RawIssuer)
	s.byIssuer[key] = append(s.byIssuer[key], crl)
	return nil
}

// parseCRL accepts a CRL file in PEM (-----BEGIN X509 CRL-----) form,
// including bundles that concatenate multiple PEM blocks in one file
// (one CRL per BEGIN/END pair). Non-CRL PEM blocks are skipped so a
// bundle interleaved with informational headers or trust-anchor copies
// still loads cleanly. A single DER-encoded CRL is also accepted for
// tooling convenience.
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

// check returns nil if cert is not present in any matching CRL. The
// caller is expected to invoke this only after chain verification has
// already established the certificate's issuer is trusted.
func (s *revocationListSet) check(cert *x509.Certificate, now time.Time) error {
	if s == nil || len(s.byIssuer) == 0 {
		return nil
	}

	crls, ok := s.byIssuer[string(cert.RawIssuer)]
	if !ok || len(crls) == 0 {
		// no CRL configured for this issuer: nothing to check
		return nil
	}

	allStale := true
	for _, crl := range crls {
		// loadAndVerify rejects CRLs without NextUpdate, but defend in
		// depth: any zero NextUpdate that reaches this path is treated
		// as immediately stale rather than as "never expires".
		if crl.NextUpdate.IsZero() || now.After(crl.NextUpdate) {
			continue
		}
		allStale = false

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

	if allStale {
		return fmt.Errorf("%w: issuer=%q", ErrCRLStale, cert.Issuer.String())
	}
	return nil
}

// size returns the total number of CRLs held; useful for startup logs
// and unit-test assertions.
func (s *revocationListSet) size() int {
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
