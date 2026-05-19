// SPDX-License-Identifier: MIT
// LOTA Verifier - Certificate Revocation List (CRL) support
//
// Loads operator-supplied CRLs (RFC 5280) at verifier startup, verifies
// each CRL signature against the trusted CA roots configured on the
// CertificateStore, and exposes a lookup by (issuer, serial) that the
// EK/AIK verification paths consult before accepting a certificate.
//
// CRL refresh is intentionally out of scope: production deployments are
// expected to redeploy the verifier (or atomically replace the CRL files
// and SIGHUP it) when a TPM manufacturer publishes a new revocation feed.
// Stale CRLs (NextUpdate < now) fail closed.

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
	ErrCertificateRevoked = errors.New("certificate is revoked by configured CRL")
	ErrCRLStale           = errors.New("CRL is past its NextUpdate; refusing to trust issuer")
	ErrCRLSignature       = errors.New("CRL signature verification failed against trusted CAs")
	ErrCRLNoIssuer        = errors.New("CRL issuer is not among trusted CAs")
)

// revocationListSet holds CRLs grouped by issuer subject DN.
//
// A single set may contain multiple CRLs (TPM manufacturers commonly
// publish per-model or per-batch lists). Lookups iterate every list
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

// loadAndVerify parses one PEM-encoded CRL file, verifies it against the
// supplied CA pool, and adds it to the set. A CRL whose signature does
// not chain to any configured CA is rejected up front so misconfiguration
// surfaces at startup rather than at attestation time.
func (s *revocationListSet) loadAndVerify(path string, cas []*x509.Certificate) error {
	if len(cas) == 0 {
		return ErrNoTrustedCAs
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read CRL %s: %w", path, err)
	}

	crl, err := parseCRL(data)
	if err != nil {
		return fmt.Errorf("parse CRL %s: %w", path, err)
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
			return fmt.Errorf("%w: %v", ErrCRLSignature, sigErr)
		}
		return ErrCRLNoIssuer
	}

	key := string(crl.RawIssuer)
	s.byIssuer[key] = append(s.byIssuer[key], crl)
	return nil
}

// parseCRL accepts a CRL file in PEM (-----BEGIN X509 CRL-----) form.
// DER input is also accepted for tooling convenience.
func parseCRL(data []byte) (*x509.RevocationList, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseRevocationList(block.Bytes)
	}
	return x509.ParseRevocationList(data)
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
		if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
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
