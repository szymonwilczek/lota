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
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AIKStore interface {
	// retrieves AIK public key for client
	GetAIK(clientID string) (*rsa.PublicKey, error)

	// stores AIK public key for client (TOFU)
	RegisterAIK(clientID string, pubKey *rsa.PublicKey) error

	// stores AIK with certificate verification
	RegisterAIKWithCert(clientID string, pubKey *rsa.PublicKey, aikCert, ekCert []byte) error

	// registers or validates hardware ID for client
	RegisterHardwareID(clientID string, hardwareID [32]byte) error

	// retrieves stored hardware ID for client
	GetHardwareID(clientID string) ([32]byte, error)

	// removes trust for client's AIK
	RevokeAIK(clientID string) error

	// returns all registered client IDs
	ListClients() []string

	// returns when the AIK was first registered for the client
	// falls back to file modification time for legacy entries without metadata
	GetRegisteredAt(clientID string) (time.Time, error)

	// replaces the AIK for an existing client (key rotation)
	// preserves hardware ID binding. updates registration timestamp
	RotateAIK(clientID string, newKey *rsa.PublicKey) error
}

// metadata persisted alongside AIK public keys for lifecycle management
// used by FileStore to track registration time in a sidecar JSON file
type aikMeta struct {
	RegisteredAt time.Time `json:"registered_at"`
}

// keys are stored as PEM files: {storePath}/{clientID}.pem
// registration metadata: {storePath}/{clientID}.meta (JSON)
// hardware IDs are stored as: {storePath}/{clientID}.hwid
type FileStore struct {
	mu           sync.RWMutex
	storePath    string
	cache        map[string]*rsa.PublicKey
	hardwareIDs  map[string][32]byte
	registeredAt map[string]time.Time
}

// creates a new file-based AIK store
func NewFileStore(storePath string) (*FileStore, error) {
	if err := os.MkdirAll(storePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %w", err)
	}

	fs := &FileStore{
		storePath:    storePath,
		cache:        make(map[string]*rsa.PublicKey),
		hardwareIDs:  make(map[string][32]byte),
		registeredAt: make(map[string]time.Time),
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
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		ext := filepath.Ext(name)
		clientID := name[:len(name)-len(ext)]

		switch ext {
		case ".pem":
			pubKey, err := fs.loadKey(clientID)
			if err != nil {
				fmt.Printf("Warning: failed to load key for %s: %v\n", clientID, err)
				continue
			}
			fs.cache[clientID] = pubKey

		case ".hwid":
			hwid, err := fs.loadHardwareID(clientID)
			if err != nil {
				fmt.Printf("Warning: failed to load hardware ID for %s: %v\n", clientID, err)
				continue
			}
			fs.hardwareIDs[clientID] = hwid

		case ".meta":
			meta, err := fs.loadMeta(clientID)
			if err != nil {
				fmt.Printf("Warning: failed to load metadata for %s: %v\n", clientID, err)
				continue
			}
			fs.registeredAt[clientID] = meta.RegisteredAt
		}
	}

	// backfill registration time from PEM file mtime for legacy entries
	for clientID := range fs.cache {
		if _, hasMeta := fs.registeredAt[clientID]; !hasMeta {
			if info, err := os.Stat(filepath.Join(fs.storePath, clientID+".pem")); err == nil {
				fs.registeredAt[clientID] = info.ModTime()
			}
		}
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

func (fs *FileStore) loadHardwareID(clientID string) ([32]byte, error) {
	var hwid [32]byte
	path := filepath.Join(fs.storePath, clientID+".hwid")

	data, err := os.ReadFile(path)
	if err != nil {
		return hwid, err
	}

	if len(data) != 32 {
		return hwid, fmt.Errorf("invalid hardware ID size: %d", len(data))
	}

	copy(hwid[:], data)
	return hwid, nil
}

func (fs *FileStore) loadMeta(clientID string) (*aikMeta, error) {
	path := filepath.Join(fs.storePath, clientID+".meta")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var meta aikMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return &meta, nil
}

func (fs *FileStore) saveMeta(clientID string, regTime time.Time) error {
	meta := aikMeta{RegisteredAt: regTime}
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	path := filepath.Join(fs.storePath, clientID+".meta")
	return os.WriteFile(path, data, 0600)
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

	// persist registration timestamp
	now := time.Now()
	if err := fs.saveMeta(clientID, now); err != nil {
		fmt.Printf("Warning: failed to save metadata for %s: %v\n", clientID, err)
	}
	fs.registeredAt[clientID] = now

	return nil
}

func (fs *FileStore) RevokeAIK(clientID string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	path := filepath.Join(fs.storePath, clientID+".pem")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove key file: %w", err)
	}

	metaPath := filepath.Join(fs.storePath, clientID+".meta")
	os.Remove(metaPath)

	delete(fs.cache, clientID)
	delete(fs.registeredAt, clientID)
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

func (fs *FileStore) GetRegisteredAt(clientID string) (time.Time, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if t, ok := fs.registeredAt[clientID]; ok {
		return t, nil
	}
	return time.Time{}, errors.New("registration time not found")
}

// replaces expired AIK with a new key, preserving hardware ID binding
func (fs *FileStore) RotateAIK(clientID string, newKey *rsa.PublicKey) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if _, exists := fs.cache[clientID]; !exists {
		return errors.New("client not registered")
	}

	keyBytes, err := x509.MarshalPKIXPublicKey(newKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}

	// overwrite existing PEM file
	path := filepath.Join(fs.storePath, clientID+".pem")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("failed to encode key: %w", err)
	}

	// update metadata with new registration time
	now := time.Now()
	if err := fs.saveMeta(clientID, now); err != nil {
		fmt.Printf("Warning: failed to save metadata for %s: %v\n", clientID, err)
	}

	fs.cache[clientID] = newKey
	fs.registeredAt[clientID] = now

	return nil
}

// falls back to TOFU (no cert verification)
func (fs *FileStore) RegisterAIKWithCert(clientID string, pubKey *rsa.PublicKey, aikCert, ekCert []byte) error {
	return fs.RegisterAIK(clientID, pubKey)
}

// registers hardware ID for client or validates against existing
// implements TOFU: first registration stores the ID, subsequent calls verify match
func (fs *FileStore) RegisterHardwareID(clientID string, hardwareID [32]byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// check if hardware ID already registered
	if existing, exists := fs.hardwareIDs[clientID]; exists {
		if existing != hardwareID {
			return ErrHardwareIDMismatch
		}
		return nil // same hardware ID, all good
	}

	// store new hardware ID to file
	path := filepath.Join(fs.storePath, clientID+".hwid")
	if err := os.WriteFile(path, hardwareID[:], 0600); err != nil {
		return fmt.Errorf("failed to store hardware ID: %w", err)
	}

	fs.hardwareIDs[clientID] = hardwareID
	return nil
}

// retrieves stored hardware ID for client
func (fs *FileStore) GetHardwareID(clientID string) ([32]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	hwid, exists := fs.hardwareIDs[clientID]
	if !exists {
		return [32]byte{}, ErrHardwareIDNotFound
	}
	return hwid, nil
}

// compares two RSA public keys
func publicKeysEqual(a, b *rsa.PublicKey) bool {
	if a.N.Cmp(b.N) != 0 {
		return false
	}
	return a.E == b.E
}

// returns SHA-256 fingerprint of public key (PKIX/SPKI encoding)
func Fingerprint(pubKey *rsa.PublicKey) string {
	keyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(keyBytes)
	return hex.EncodeToString(hash[:])
}

// implements AIKStore in-memory (for testing only right now).
type MemoryStore struct {
	mu           sync.RWMutex
	keys         map[string]*rsa.PublicKey
	hardwareIDs  map[string][32]byte
	registeredAt map[string]time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		keys:         make(map[string]*rsa.PublicKey),
		hardwareIDs:  make(map[string][32]byte),
		registeredAt: make(map[string]time.Time),
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
	ms.registeredAt[clientID] = time.Now()
	return nil
}

func (ms *MemoryStore) RevokeAIK(clientID string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	delete(ms.keys, clientID)
	delete(ms.registeredAt, clientID)
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

// for MemoryStore falls back to TOFU (no cert verification)
func (ms *MemoryStore) RegisterAIKWithCert(clientID string, pubKey *rsa.PublicKey, aikCert, ekCert []byte) error {
	return ms.RegisterAIK(clientID, pubKey)
}

func (ms *MemoryStore) GetRegisteredAt(clientID string) (time.Time, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if t, ok := ms.registeredAt[clientID]; ok {
		return t, nil
	}
	return time.Time{}, errors.New("registration time not found")
}

// replaces expired AIK with a new key, preserving hardware ID binding
func (ms *MemoryStore) RotateAIK(clientID string, newKey *rsa.PublicKey) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if _, exists := ms.keys[clientID]; !exists {
		return errors.New("client not registered")
	}

	ms.keys[clientID] = newKey
	ms.registeredAt[clientID] = time.Now()
	return nil
}

// registers hardware ID for client or validates against existing
func (ms *MemoryStore) RegisterHardwareID(clientID string, hardwareID [32]byte) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if existing, exists := ms.hardwareIDs[clientID]; exists {
		if existing != hardwareID {
			return ErrHardwareIDMismatch
		}
		return nil
	}

	ms.hardwareIDs[clientID] = hardwareID
	return nil
}

// retrieves stored hardware ID for client
func (ms *MemoryStore) GetHardwareID(clientID string) ([32]byte, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	hwid, exists := ms.hardwareIDs[clientID]
	if !exists {
		return [32]byte{}, ErrHardwareIDNotFound
	}
	return hwid, nil
}

// currently a placeholder
type CertificateStore struct {
	fileStore    *FileStore
	trustedCAs   []*x509.Certificate
	caPool       *x509.CertPool
	requireCerts bool
}

// TCG EK Credential Profile OID for TPM 2.0
var oidTCGEKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 1}

// certificate verification errors
var (
	ErrNoCertificate       = errors.New("certificate required but not provided")
	ErrInvalidCertificate  = errors.New("failed to parse certificate")
	ErrCertificateChain    = errors.New("certificate chain verification failed")
	ErrCertificateKeyMatch = errors.New("certificate public key does not match AIK")
	ErrCertificateExpired  = errors.New("certificate has expired")
	ErrCertificateNotYet   = errors.New("certificate not yet valid")
	ErrNoTrustedCAs        = errors.New("no trusted CAs configured")
	ErrCertificateEKOID    = errors.New("EK certificate missing TCG TPM 2.0 OID (2.23.133.8.1)")
)

// hardware identity errors
var (
	ErrHardwareIDMismatch = errors.New("hardware identity mismatch - possible cloning or hardware change")
	ErrHardwareIDNotFound = errors.New("hardware identity not registered")
)

// creates a certificate-based store
// caCertPaths: paths to trusted CA certificates (TPM manufacturers, Privacy CAs)
// requireCerts: if true, reject registrations without valid certificates
func NewCertificateStore(storePath string, caCertPaths []string, requireCerts bool) (*CertificateStore, error) {
	fs, err := NewFileStore(storePath)
	if err != nil {
		return nil, err
	}

	cs := &CertificateStore{
		fileStore:    fs,
		trustedCAs:   make([]*x509.Certificate, 0),
		caPool:       x509.NewCertPool(),
		requireCerts: requireCerts,
	}

	// load ca certificates
	for _, path := range caCertPaths {
		cert, err := loadCertificate(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA cert %s: %w", path, err)
		}
		cs.trustedCAs = append(cs.trustedCAs, cert)
		cs.caPool.AddCert(cert)
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
	// TOFU fallback when no certificates provided
	if cs.requireCerts {
		return ErrNoCertificate
	}
	return cs.fileStore.RegisterAIK(clientID, pubKey)
}

// verifies AIK certificate chain before registering
func (cs *CertificateStore) RegisterAIKWithCert(clientID string, pubKey *rsa.PublicKey, aikCertDER, ekCertDER []byte) error {
	// if no certificates provided, fall back to TOFU (if allowed)
	if len(aikCertDER) == 0 && len(ekCertDER) == 0 {
		return cs.RegisterAIK(clientID, pubKey)
	}

	// parse and verify AIK certificate if provided
	if len(aikCertDER) > 0 {
		if err := cs.verifyAIKCertificate(aikCertDER, pubKey); err != nil {
			return fmt.Errorf("AIK certificate verification failed: %w", err)
		}
	}

	// parse and verify EK certificate if provided (validates TPM authenticity)
	if len(ekCertDER) > 0 {
		if err := cs.verifyEKCertificate(ekCertDER); err != nil {
			return fmt.Errorf("EK certificate verification failed: %w", err)
		}
	}

	return cs.fileStore.RegisterAIK(clientID, pubKey)
}

// validates AIK certificate against trusted CAs
func (cs *CertificateStore) verifyAIKCertificate(certDER []byte, expectedPubKey *rsa.PublicKey) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	// verify certificate time validity
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return ErrCertificateNotYet
	}
	if now.After(cert.NotAfter) {
		return ErrCertificateExpired
	}

	// verify certificate chain against trusted CAs
	if len(cs.trustedCAs) > 0 {
		opts := x509.VerifyOptions{
			Roots:       cs.caPool,
			CurrentTime: now,
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}

		if _, err := cert.Verify(opts); err != nil {
			return fmt.Errorf("%w: %v", ErrCertificateChain, err)
		}
	} else if cs.requireCerts {
		return ErrNoTrustedCAs
	}

	// verify that certificate public key matches the AIK from attestation
	certRSAPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: certificate does not contain RSA key", ErrCertificateKeyMatch)
	}

	if !publicKeysEqual(certRSAPubKey, expectedPubKey) {
		return fmt.Errorf("%w: public key mismatch", ErrCertificateKeyMatch)
	}

	return nil
}

// validates EK certificate (proves TPM authenticity)
func (cs *CertificateStore) verifyEKCertificate(certDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	// verify certificate time validity
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return ErrCertificateNotYet
	}
	if now.After(cert.NotAfter) {
		return ErrCertificateExpired
	}

	// verify certificate chain against trusted CAs (TPM manufacturer CAs)
	if len(cs.trustedCAs) > 0 {
		opts := x509.VerifyOptions{
			Roots:       cs.caPool,
			CurrentTime: now,
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}

		if _, err := cert.Verify(opts); err != nil {
			return fmt.Errorf("%w: %v", ErrCertificateChain, err)
		}
	}

	// EK certificate must contain the TCG EK Credential Profile OID
	// (2.23.133.8.1) in Extended Key Usage to prove TPM 2.0 origin!!
	found := false
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(oidTCGEKCertificate) {
			found = true
			break
		}
	}
	if !found {
		return ErrCertificateEKOID
	}

	return nil
}

func (cs *CertificateStore) RevokeAIK(clientID string) error {
	return cs.fileStore.RevokeAIK(clientID)
}

func (cs *CertificateStore) ListClients() []string {
	return cs.fileStore.ListClients()
}

func (cs *CertificateStore) RegisterHardwareID(clientID string, hardwareID [32]byte) error {
	return cs.fileStore.RegisterHardwareID(clientID, hardwareID)
}

func (cs *CertificateStore) GetHardwareID(clientID string) ([32]byte, error) {
	return cs.fileStore.GetHardwareID(clientID)
}

func (cs *CertificateStore) GetRegisteredAt(clientID string) (time.Time, error) {
	return cs.fileStore.GetRegisteredAt(clientID)
}

func (cs *CertificateStore) RotateAIK(clientID string, newKey *rsa.PublicKey) error {
	return cs.fileStore.RotateAIK(clientID, newKey)
}
