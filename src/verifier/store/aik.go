// SPDX-License-Identifier: MIT
// LOTA Verifier - AIK key store
//
// Manages Attestation Identity Keys using TOFU (Trust On First Use).
// Designed for now to be replaceable with certificate-based trust in the future.

package store

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type AIKStore interface {
	// retrieves AIK public key for client
	GetAIK(clientID string) (*rsa.PublicKey, error)

	// stores AIK public key for client (TOFU)
	RegisterAIK(clientID string, pubKey *rsa.PublicKey) error

	// removes trust for client's AIK
	RevokeAIK(clientID string) error

	// returns all registered client IDs
	ListClients() []string
}

// keys are stored as PEM files: {storePath}/{clientID}.pem
type FileStore struct {
	mu        sync.RWMutex
	storePath string
	cache     map[string]*rsa.PublicKey
}

// creates a new file-based AIK store
func NewFileStore(storePath string) (*FileStore, error) {
	if err := os.MkdirAll(storePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %w", err)
	}

	fs := &FileStore{
		storePath: storePath,
		cache:     make(map[string]*rsa.PublicKey),
	}

	// load existing keys into cache
	if err := fs.loadAll(); err != nil {
		return nil, err
	}

	return fs, nil
}

func (fs *FileStore) loadAll() error {
	entries, err := os.ReadDir(fs.storePath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pem" {
			continue
		}

		clientID := entry.Name()[:len(entry.Name())-4] // remove .pem
		pubKey, err := fs.loadKey(clientID)
		if err != nil {
			fmt.Printf("Warning: failed to load key for %s: %v\n", clientID, err)
			continue
		}

		fs.cache[clientID] = pubKey
	}

	return nil
}

func (fs *FileStore) loadKey(clientID string) (*rsa.PublicKey, error) {
	path := filepath.Join(fs.storePath, clientID+".pem")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPub, nil
}

func (fs *FileStore) GetAIK(clientID string) (*rsa.PublicKey, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	pubKey, exists := fs.cache[clientID]
	if !exists {
		return nil, errors.New("AIK not found")
	}

	return pubKey, nil
}

func (fs *FileStore) RegisterAIK(clientID string, pubKey *rsa.PublicKey) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if existing, exists := fs.cache[clientID]; exists {
		if !publicKeysEqual(existing, pubKey) {
			return errors.New("client already registered with different key")
		}
		return nil // same key, no-op
	}

	keyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}

	path := filepath.Join(fs.storePath, clientID+".pem")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		os.Remove(path)
		return fmt.Errorf("failed to write key: %w", err)
	}

	// add to cache
	fs.cache[clientID] = pubKey

	return nil
}

func (fs *FileStore) RevokeAIK(clientID string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	path := filepath.Join(fs.storePath, clientID+".pem")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove key file: %w", err)
	}

	delete(fs.cache, clientID)
	return nil
}

func (fs *FileStore) ListClients() []string {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	clients := make([]string, 0, len(fs.cache))
	for clientID := range fs.cache {
		clients = append(clients, clientID)
	}
	return clients
}

// compares two RSA public keys
func publicKeysEqual(a, b *rsa.PublicKey) bool {
	if a.N.Cmp(b.N) != 0 {
		return false
	}
	return a.E == b.E
}

// returns SHA-256 fingerprint of public key
func Fingerprint(pubKey *rsa.PublicKey) string {
	keyBytes := x509.MarshalPKCS1PublicKey(pubKey)
	hash := sha256.Sum256(keyBytes)
	return hex.EncodeToString(hash[:])
}

// implements AIKStore in-memory (for testing only right now).
type MemoryStore struct {
	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		keys: make(map[string]*rsa.PublicKey),
	}
}

func (ms *MemoryStore) GetAIK(clientID string) (*rsa.PublicKey, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	pubKey, exists := ms.keys[clientID]
	if !exists {
		return nil, errors.New("AIK not found")
	}
	return pubKey, nil
}

func (ms *MemoryStore) RegisterAIK(clientID string, pubKey *rsa.PublicKey) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if existing, exists := ms.keys[clientID]; exists {
		if !publicKeysEqual(existing, pubKey) {
			return errors.New("client already registered with different key")
		}
		return nil
	}

	ms.keys[clientID] = pubKey
	return nil
}

func (ms *MemoryStore) RevokeAIK(clientID string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	delete(ms.keys, clientID)
	return nil
}

func (ms *MemoryStore) ListClients() []string {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	clients := make([]string, 0, len(ms.keys))
	for clientID := range ms.keys {
		clients = append(clients, clientID)
	}
	return clients
}

// currently a placeholder
type CertificateStore struct {
	fileStore  *FileStore
	trustedCAs []*x509.Certificate
}

// creates a certificate-based store
// caCertPaths: paths to trusted CA certificates (TPM manufacturers, Privacy CAs)
func NewCertificateStore(storePath string, caCertPaths []string) (*CertificateStore, error) {
	fs, err := NewFileStore(storePath)
	if err != nil {
		return nil, err
	}

	cs := &CertificateStore{
		fileStore:  fs,
		trustedCAs: make([]*x509.Certificate, 0),
	}

	// load ca certificates
	for _, path := range caCertPaths {
		cert, err := loadCertificate(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA cert %s: %w", path, err)
		}
		cs.trustedCAs = append(cs.trustedCAs, cert)
	}

	return cs, nil
}

func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}

func (cs *CertificateStore) GetAIK(clientID string) (*rsa.PublicKey, error) {
	return cs.fileStore.GetAIK(clientID)
}

func (cs *CertificateStore) RegisterAIK(clientID string, pubKey *rsa.PublicKey) error {
	// TODO: verify AIK certificate chain before registering
	return cs.fileStore.RegisterAIK(clientID, pubKey)
}

func (cs *CertificateStore) RevokeAIK(clientID string) error {
	return cs.fileStore.RevokeAIK(clientID)
}

func (cs *CertificateStore) ListClients() []string {
	return cs.fileStore.ListClients()
}
