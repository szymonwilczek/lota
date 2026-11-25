// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Load Generator - Synthetic fleet identities

package synth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// aikKeyBits matches the agent's RSA-2048 AIK.
const aikKeyBits = 2048

// CA is the rig's attestation CA, which issues every agent certificate.
type CA struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
}

// NewCA generates a self-signed CA with an RSA-2048 key, valid for 30 days.
func NewCA() (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, aikKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "lota-loadgen-attest-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return &CA{Key: key, Cert: cert}, nil
}

// CertPEM returns the CA certificate for the verifier's --aik-ca-cert.
func (ca *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

// KeyPEM returns the CA private key as PKCS#8 PEM, so a reloaded rig can
// issue certificates under the same CA.
func (ca *CA) KeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustMarshalPKCS8(ca.Key),
	})
}

func mustMarshalPKCS8(key *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic("marshal CA key: " + err.Error())
	}
	return der
}

// LoadCA rebuilds a CA from the output of CertPEM and KeyPEM.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM block in CA certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block in CA key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key is not RSA")
	}
	return &CA{Key: key, Cert: cert}, nil
}

// IssueAIKCert returns a DER AIK certificate with the pseudonym as subject CN,
// valid for 30 days. A non-empty tenant goes into the one OU the verifier reads
// the tenant from; with no OU the device is in the default tenant.
func (ca *CA) IssueAIKCert(pseudonym, tenant string, pub *rsa.PublicKey) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("certificate serial: %w", err)
	}
	subject := pkix.Name{CommonName: pseudonym}
	if tenant != "" {
		subject.OrganizationalUnit = []string{tenant}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("issue AIK certificate: %w", err)
	}
	if len(der) > types.MaxAIKCertSize {
		return nil, fmt.Errorf("AIK certificate %d bytes exceeds wire max %d",
			len(der), types.MaxAIKCertSize)
	}
	return der, nil
}

// Agent is one synthetic fleet member.
type Agent struct {
	Name       string
	HardwareID [types.HashSize]byte
	Pseudonym  string // AIK certificate CN, the verifier's client ID
	Key        *rsa.PrivateKey
	CertDER    []byte
}

// Fleet is a set of agents with one shared measurement profile.
type Fleet struct {
	Tenant string
	CA     *CA
	Agents []*Agent

	// Policy pins both hashes and PCR 0 and 1
	AgentHash  [types.HashSize]byte
	KernelHash [types.HashSize]byte
	PCRs       [types.PCRCount][types.HashSize]byte
}

// profileDigest gives every rig the same profile, so runs compare.
func profileDigest(label string) [types.HashSize]byte {
	return sha256.Sum256([]byte("lota-loadgen-profile-v1:" + label))
}

// AgentName returns the name of fleet member i.
func AgentName(i int) string {
	return fmt.Sprintf("loadgen-%06d", i)
}

// RigID returns the first 8 bytes of the CA certificate's SHA-256 as hex.
// It salts the agent identities, so they differ between rigs and repeat when
// a rig is reloaded.
func (ca *CA) RigID() string {
	h := sha256.Sum256(ca.Cert.Raw)
	return hex.EncodeToString(h[:8])
}

// Pseudonym derives the 64 hex character CN the verifier decodes as the
// device identity.
func Pseudonym(rigID, name string) string {
	h := sha256.Sum256([]byte("lota-loadgen-pseudonym:" + rigID + ":" + name))
	return hex.EncodeToString(h[:])
}

// DefaultKeyPool is the AIK key pool size when the caller does not choose one.
const DefaultKeyPool = 256

// NewFleet builds n agents that take the keys round-robin and issues
// each a fresh certificate.
func NewFleet(ca *CA, n int, keys []*rsa.PrivateKey, tenant string) (*Fleet, error) {
	if n <= 0 {
		return nil, fmt.Errorf("fleet size must be positive, got %d", n)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("empty AIK key pool")
	}
	if tenant != "" && !verify.ValidTenantName(tenant) {
		return nil, fmt.Errorf("invalid tenant name %q", tenant)
	}

	f := &Fleet{
		Tenant:     tenant,
		CA:         ca,
		Agents:     make([]*Agent, n),
		AgentHash:  profileDigest("agent-hash"),
		KernelHash: profileDigest("kernel-hash"),
	}
	for i := range f.PCRs {
		f.PCRs[i] = profileDigest(fmt.Sprintf("pcr-%d", i))
	}

	rigID := ca.RigID()
	if err := parallelFor(n, func(i int) error {
		name := AgentName(i)
		a := &Agent{
			Name:       name,
			HardwareID: sha256.Sum256([]byte("lota-loadgen-hwid:" + rigID + ":" + name)),
			Pseudonym:  Pseudonym(rigID, name),
			Key:        keys[i%len(keys)],
		}
		der, err := ca.IssueAIKCert(a.Pseudonym, tenant, &a.Key.PublicKey)
		if err != nil {
			return fmt.Errorf("agent %s: %w", name, err)
		}
		a.CertDER = der
		f.Agents[i] = a
		return nil
	}); err != nil {
		return nil, err
	}
	return f, nil
}

// parallelFor runs fn(0..n-1) on GOMAXPROCS workers. A worker stops
// at its first error, and the first error recorded is returned.
func parallelFor(n int, fn func(i int) error) error {
	workers := min(runtime.GOMAXPROCS(0), n)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	next := make(chan int, n)
	for i := range n {
		next <- i
	}
	close(next)
	for range workers {
		wg.Go(func() {
			for i := range next {
				if err := fn(i); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}
			}
		})
	}
	wg.Wait()
	return firstErr
}
