// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Load Generator - Synthetic fleet identities
//
// Builds fleet of software-only agent identities whose attestation reports pass
// the verifier's full production verification path:
// AIK certificate chain, quote signature, binding nonce, PCR digest, event log,
// and the PCR14 boot-commitment derivation.
//
// No TPM involved:
// AIK is plain RSA key and the quote is signed in software, which is exactly what
// makes thousands of agents per host possible.
//
// Fleet shares one deterministic PCR bank and one agent/kernel hash, so single
// generated policy (PolicyYAML) covers every agent.
//
// Identities differ per agent:
// hardware_id, pseudonym and the CA-issued AIK certificate.
// RSA keys come from shared pool because key generation, not signing, dominates
// setup time; the verifier binds trust to the certificate subject, not key uniqueness.

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
)

// aikKeyBits matches the RSA-2048 AIK the real agent certifies
const aikKeyBits = 2048

// CA is throwaway attestation CA for load-test rig
// Its certificate is handed to the verifier as --aik-ca-cert;
// every agent certificate chains to it
type CA struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
}

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

// CertPEM returns the CA certificate for the verifier's --aik-ca-cert
func (ca *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

// KeyPEM returns the CA private key so rig directory can be reused across runs
// without re-issuing agent certificates
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

// LoadCA rebuilds CA from the PEM pair CertPEM/KeyPEM produced
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

// IssueAIKCert mints DER AIK certificate whose subject carries the device
// pseudonym, mirroring what the attestation CA issues
func (ca *CA) IssueAIKCert(pseudonym string, pub *rsa.PublicKey) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("certificate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: pseudonym},
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

// Agent is one synthetic fleet member
type Agent struct {
	Name       string
	HardwareID [types.HashSize]byte
	Pseudonym  string // hex, AIK certificate subject CN = verifier client ID
	Key        *rsa.PrivateKey
	CertDER    []byte
}

// Fleet is set of agents sharing one measurement profile,
// plus the CA that vouches for them
type Fleet struct {
	CA     *CA
	Agents []*Agent

	// shared measurement profile; PolicyYAML pins these
	AgentHash  [types.HashSize]byte
	KernelHash [types.HashSize]byte
	PCRs       [types.PCRCount][types.HashSize]byte
}

// deterministic measurement profile:
// any two rigs built from the same version agree,
// so results are comparable across runs and hosts
func profileDigest(label string) [types.HashSize]byte {
	return sha256.Sum256([]byte("lota-loadgen-profile-v1:" + label))
}

// AgentName returns the canonical name of fleet member i
func AgentName(i int) string {
	return fmt.Sprintf("loadgen-%06d", i)
}

// Pseudonym maps an agent name to its 64-hex device pseudonym,
// the same shape the attestation CA derives for real devices
func Pseudonym(name string) string {
	h := sha256.Sum256([]byte("lota-loadgen-pseudonym:" + name))
	return hex.EncodeToString(h[:])
}

// DefaultKeyPool is the AIK key pool size when the caller does not choose one
const DefaultKeyPool = 256

// NewFleet builds n agents backed by freshly generated pool of keyPool RSA keys
// (keyPool <= 0 collapses to DefaultKeyPool, and the pool never exceeds the fleet size)
// Key generation and certificate issuance run across all CPUs
func NewFleet(ca *CA, n, keyPool int) (*Fleet, error) {
	if n <= 0 {
		return nil, fmt.Errorf("fleet size must be positive, got %d", n)
	}
	if keyPool <= 0 {
		keyPool = DefaultKeyPool
	}
	keyPool = min(keyPool, n)
	keys, err := GenerateKeyPool(keyPool)
	if err != nil {
		return nil, err
	}
	return NewFleetWithKeys(ca, n, keys)
}

// NewFleetWithKeys builds n agents over an existing key pool,
// e.g. one reloaded from rig directory
func NewFleetWithKeys(ca *CA, n int, keys []*rsa.PrivateKey) (*Fleet, error) {
	if n <= 0 {
		return nil, fmt.Errorf("fleet size must be positive, got %d", n)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("empty AIK key pool")
	}

	f := &Fleet{
		CA:         ca,
		Agents:     make([]*Agent, n),
		AgentHash:  profileDigest("agent-hash"),
		KernelHash: profileDigest("kernel-hash"),
	}
	for i := range f.PCRs {
		f.PCRs[i] = profileDigest(fmt.Sprintf("pcr-%d", i))
	}

	if err := parallelFor(n, func(i int) error {
		name := AgentName(i)
		a := &Agent{
			Name:       name,
			HardwareID: sha256.Sum256([]byte("lota-loadgen-hwid:" + name)),
			Pseudonym:  Pseudonym(name),
			Key:        keys[i%len(keys)],
		}
		der, err := ca.IssueAIKCert(a.Pseudonym, &a.Key.PublicKey)
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

// parallelFor runs fn(0..n-1) across GOMAXPROCS workers, returning the first error
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
