// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

// Package ca verifies EK certificates against pinned manufacturer roots
// and CRLs and signs AIK certificates with the CA key.
package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/szymonwilczek/lota/crl"
)

// hasTCGEKOID accepts this OID as an extended key usage or a policy.
var oidTCGEKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 1}

// enroll.DefaultTenant; enroll imports ca, so ca cannot import it.
const defaultTenant = "default"

// Critical extensions an EK certificate may carry that crypto/x509 leaves
// unhandled: a subject alternative name with no DNS, email, IP or URI name,
// and subject directory attributes.
var (
	oidSubjectAltName        = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidSubjectDirectoryAttrs = asn1.ObjectIdentifier{2, 5, 29, 9}
)

func dropTPMCriticalExtensions(oids []asn1.ObjectIdentifier) []asn1.ObjectIdentifier {
	out := oids[:0:0]
	for _, oid := range oids {
		if oid.Equal(oidSubjectAltName) || oid.Equal(oidSubjectDirectoryAttrs) {
			continue
		}
		out = append(out, oid)
	}
	return out
}

const (
	// MinEKKeyBits is the smallest EK or AIK RSA modulus accepted.
	MinEKKeyBits = 2048

	// DefaultAIKCertTTL is the AIK certificate lifetime used when
	// IssuerConfig.AIKCertTTL is not positive.
	DefaultAIKCertTTL = 24 * time.Hour
)

// Errors returned by NewIssuer and VerifyEKCertificate.
var (
	ErrNoEKRoots        = errors.New("no trusted EK manufacturer roots configured")
	ErrEKParse          = errors.New("failed to parse EK certificate")
	ErrEKChain          = errors.New("EK certificate does not chain to a trusted manufacturer root")
	ErrEKExpired        = errors.New("EK certificate is expired")
	ErrEKNotYet         = errors.New("EK certificate is not yet valid")
	ErrEKMissingOID     = errors.New("EK certificate missing TCG TPM 2.0 OID (2.23.133.8.1)")
	ErrEKKeyType        = errors.New("EK certificate public key is not RSA; enrollment requires an RSA endorsement key (TCG EK template H-1)")
	ErrEKKeySize        = errors.New("EK certificate RSA key too small")
	ErrCANotCA          = errors.New("CA certificate is not a certificate authority")
	ErrCAKeyMismatch    = errors.New("CA private key does not match CA certificate")
	ErrUnsupportedCAKey = errors.New("unsupported CA signing key type")

	ErrEKWeakKey = errors.New(
		"EK RSA modulus carries the ROCA (CVE-2017-15361) fingerprint")
)

// Issuer verifies EK certificates and mints AIK certificates.
type Issuer struct {
	caCert  *x509.Certificate
	caKey   crypto.Signer
	ekRoots *x509.CertPool
	certTTL time.Duration

	// pinned intermediates and every root that is not self-signed
	ekIntermediates *x509.CertPool

	// roots and intermediates by raw Subject, for missingLink: a CertPool
	// cannot be walked
	ekPathCerts map[string]*x509.Certificate

	// roots and intermediates: the certificates a CRL may be signed by
	ekRootCerts []*x509.Certificate

	ekCRLPaths []string
	ekCRLs     atomic.Pointer[crl.Set]
}

// IssuerConfig configures a new Issuer.
type IssuerConfig struct {
	// CACertPEM is the CA certificate that signs AIK certificates;
	// it must be a CA.
	CACertPEM []byte

	// CAKeyPEM is the PKCS#8 ECDSA, Ed25519 or RSA CA key,
	// read only when CASigner is nil.
	CAKeyPEM []byte

	// CASigner takes precedence over CAKeyPEM.
	// Either key must match the CA certificate.
	CASigner crypto.Signer

	// EKRootPEMs are the anchors an EK chain must end at;
	// at least one is required.
	EKRootPEMs [][]byte

	// EKIntermediatePEMs are path material, never an anchor.
	EKIntermediatePEMs [][]byte

	// EKCRLPaths are manufacturer CRL files, loaded as crl.BuildSet does;
	// each CRL must be signed by a certificate of EKRootPEMs or
	// EKIntermediatePEMs.
	EKCRLPaths []string

	// AIKCertTTL is the AIK certificate lifetime.
	AIKCertTTL time.Duration
}

// NewIssuer builds an Issuer and loads its CRL files. It fails on a CA
// certificate that is not a CA, a CA key that does not parse, is not
// supported or does not match it, no EK root, and a certificate or CRL that
// does not load.
func NewIssuer(cfg IssuerConfig) (*Issuer, error) {
	caCert, err := parseCertPEM(cfg.CACertPEM)
	if err != nil {
		return nil, fmt.Errorf("CA certificate: %w", err)
	}
	if !caCert.IsCA {
		return nil, ErrCANotCA
	}

	caKey := cfg.CASigner
	if caKey == nil {
		caKey, err = parseSignerPEM(cfg.CAKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("CA key: %w", err)
		}
	}
	if caKey.Public() == nil {
		return nil, ErrUnsupportedCAKey
	}
	if !publicKeysMatch(caKey.Public(), caCert.PublicKey) {
		return nil, ErrCAKeyMismatch
	}

	if len(cfg.EKRootPEMs) == 0 {
		return nil, ErrNoEKRoots
	}
	ekRoots := x509.NewCertPool()
	ekIntermediates := x509.NewCertPool()
	ekPathCerts := map[string]*x509.Certificate{}
	var ekRootCerts []*x509.Certificate
	for i, rootPEM := range cfg.EKRootPEMs {
		root, err := parseCertPEM(rootPEM)
		if err != nil {
			return nil, fmt.Errorf("EK root %d: %w", i, err)
		}
		ekRoots.AddCert(root)
		ekRootCerts = append(ekRootCerts, root)
		ekPathCerts[string(root.RawSubject)] = root
		if !bytes.Equal(root.RawSubject, root.RawIssuer) {
			ekIntermediates.AddCert(root)
		}
	}
	for i, interPEM := range cfg.EKIntermediatePEMs {
		inter, err := parseCertPEM(interPEM)
		if err != nil {
			return nil, fmt.Errorf("EK intermediate %d: %w", i, err)
		}
		ekIntermediates.AddCert(inter)
		ekPathCerts[string(inter.RawSubject)] = inter
		// a CRL may be signed by an intermediate
		ekRootCerts = append(ekRootCerts, inter)
	}

	ttl := cfg.AIKCertTTL
	if ttl <= 0 {
		ttl = DefaultAIKCertTTL
	}

	is := &Issuer{
		caCert:          caCert,
		caKey:           caKey,
		ekRoots:         ekRoots,
		ekIntermediates: ekIntermediates,
		ekPathCerts:     ekPathCerts,
		certTTL:         ttl,
		ekRootCerts:     ekRootCerts,
		ekCRLPaths:      append([]string(nil), cfg.EKCRLPaths...),
	}
	set, err := crl.BuildSet(is.ekCRLPaths, is.ekRootCerts)
	if err != nil {
		return nil, fmt.Errorf("EK CRL feed: %w", err)
	}
	is.ekCRLs.Store(set)

	return is, nil
}

// ReloadEKCRLs rebuilds the CRL set from the files NewIssuer was given;
// on error the previous set stays in use.
func (is *Issuer) ReloadEKCRLs() error {
	set, err := crl.BuildSet(is.ekCRLPaths, is.ekRootCerts)
	if err != nil {
		return err
	}
	is.ekCRLs.Store(set)
	return nil
}

// EKCRLCount returns the number of loaded CRLs.
func (is *Issuer) EKCRLCount() int { return is.ekCRLs.Load().Size() }

// a supplied chain may describe a cycle
const maxEKPathHops = 16

// pathMaterial returns ekIntermediates plus the supplied certificates that
// parse; the rest are dropped.
func (is *Issuer) pathMaterial(chainDER [][]byte) *x509.CertPool {
	if len(chainDER) == 0 {
		return is.ekIntermediates
	}
	pool := is.ekIntermediates.Clone()
	for _, der := range chainDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		pool.AddCert(cert)
	}
	return pool
}

// missingLink follows issuers up from leaf through the pinned and supplied
// certificates and returns the first issuer name it cannot find, or "" on
// reaching a self-signed certificate or maxEKPathHops. It only words the
// error of a failed verification.
func (is *Issuer) missingLink(leaf *x509.Certificate, chainDER [][]byte) string {
	bySubject := make(map[string]*x509.Certificate, len(is.ekPathCerts)+len(chainDER))
	for k, v := range is.ekPathCerts {
		bySubject[k] = v
	}
	for _, der := range chainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}

		if _, pinned := bySubject[string(c.RawSubject)]; !pinned {
			bySubject[string(c.RawSubject)] = c
		}
	}

	cur := leaf
	for hop := 0; hop < maxEKPathHops; hop++ {
		if bytes.Equal(cur.RawSubject, cur.RawIssuer) {
			return ""
		}
		next, ok := bySubject[string(cur.RawIssuer)]
		if !ok {
			return cur.Issuer.String()
		}
		cur = next
	}
	return ""
}

// VerifyEKCertificate returns the parsed EK certificate once it is within
// its validity, chains to an EK root, passes the CRL check, carries the TCG
// EK OID and holds an RSA key of at least MinEKKeyBits that is not ROCA-weak.
// chainDER is path material only: a root it carries is not an anchor.
func (is *Issuer) VerifyEKCertificate(der []byte, chainDER [][]byte, now time.Time) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEKParse, err)
	}

	if now.Before(cert.NotBefore) {
		return nil, ErrEKNotYet
	}
	if now.After(cert.NotAfter) {
		return nil, ErrEKExpired
	}

	// Verify refuses any unhandled critical extension
	cert.UnhandledCriticalExtensions = dropTPMCriticalExtensions(cert.UnhandledCriticalExtensions)

	// with no KeyUsages Verify demands ServerAuth
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         is.ekRoots,
		Intermediates: is.pathMaterial(chainDER),
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		if missing := is.missingLink(cert, chainDER); missing != "" {
			return nil, fmt.Errorf("%w: %v: nothing pinned or supplied issues %q, "+
				"so the path stops there", ErrEKChain, err, missing)
		}
		return nil, fmt.Errorf("%w: %v", ErrEKChain, err)
	}

	if err := is.ekCRLs.Load().Check(cert, now); err != nil {
		return nil, fmt.Errorf("EK certificate revocation: %w", err)
	}

	if !hasTCGEKOID(cert) {
		return nil, ErrEKMissingOID
	}

	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		// credential.GenerateChallenge takes an RSA EK only
		return nil, fmt.Errorf("%w: certificate carries a %s key", ErrEKKeyType, cert.PublicKeyAlgorithm)
	}
	if rsaPub.N.BitLen() < MinEKKeyBits {
		return nil, fmt.Errorf("%w: %d bits", ErrEKKeySize, rsaPub.N.BitLen())
	}

	// refused whether or not a CRL lists it
	if IsROCAWeak(rsaPub.N) {
		return nil, ErrEKWeakKey
	}

	return cert, nil
}

// IssueAIKCertificate signs a certificate for aikPub with CN subjectCN and,
// unless tenant is empty or the default, OU tenant, valid from a minute
// before now until now plus the issuer's TTL. It carries nothing of the
// EK. An AIK below MinEKKeyBits is refused.
func (is *Issuer) IssueAIKCertificate(aikPub *rsa.PublicKey, subjectCN, tenant string, now time.Time) ([]byte, error) {
	if aikPub == nil {
		return nil, errors.New("nil AIK public key")
	}
	if aikPub.N.BitLen() < MinEKKeyBits {
		return nil, fmt.Errorf("AIK RSA key too small: %d bits", aikPub.N.BitLen())
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial number: %w", err)
	}

	subject := pkix.Name{CommonName: subjectCN}
	if tenant != "" && tenant != defaultTenant {
		subject.OrganizationalUnit = []string{tenant}
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(is.certTTL),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, is.caCert, aikPub, is.caKey)
	if err != nil {
		return nil, fmt.Errorf("signing AIK certificate: %w", err)
	}
	return der, nil
}

func hasTCGEKOID(cert *x509.Certificate) bool {
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(oidTCGEKCertificate) {
			return true
		}
	}

	for _, oid := range cert.PolicyIdentifiers {
		if oid.Equal(oidTCGEKCertificate) {
			return true
		}
	}

	want := oidTCGEKCertificate.String()
	for _, oid := range cert.Policies {
		if oid.String() == want {
			return true
		}
	}
	return false
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseSignerPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	case *rsa.PrivateKey:
		return k, nil
	default:
		return nil, ErrUnsupportedCAKey
	}
}

func publicKeysMatch(a, b crypto.PublicKey) bool {
	type equalable interface{ Equal(x crypto.PublicKey) bool }
	if ak, ok := a.(equalable); ok {
		return ak.Equal(b)
	}
	return false
}
