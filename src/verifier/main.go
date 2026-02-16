// SPDX-License-Identifier: MIT
// LOTA Verifier - Remote attestation verification service
//
// Usage:
//   lota-verifier [options]
//
// Options:
//   --addr ADDR        Listen address for TLS attestation protocol (default: :8443)
//   --http-addr ADDR   Listen address for HTTP monitoring API (default: disabled)
//   --cert FILE        TLS certificate file
//   --key FILE         TLS private key file
//   --aik-store PATH   AIK key store directory (default: /var/lib/lota/aiks)
//   --db PATH          SQLite database for persistent storage (default: disabled)
//   --policy FILE      PCR policy file (YAML)
//   --policy-pubkey FILE Ed25519 public key for policy signature verification
//   --admin-api-key KEY Admin API key for mutating HTTP endpoints (required for revoke/ban)
//   --reader-api-key KEY Reader API key for sensitive read-only endpoints (optional)
//
// Environment variables (fallback when flag is empty):
//   LOTA_ADMIN_API_KEY  Equivalent to --admin-api-key
//   LOTA_READER_API_KEY Equivalent to --reader-api-key
//   --aik-max-age DUR  Maximum AIK registration age before forced rotation (default: 720h)
//   --generate-cert    Generate self-signed certificate for testing
//   --log-format FMT   Log output format: text or json (default: text)
//   --log-level LVL    Minimum log level: debug, info, warn, error, security (default: info)

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/server"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

var (
	addr            = flag.String("addr", ":8443", "Listen address for TLS attestation protocol")
	httpAddr        = flag.String("http-addr", "", "Listen address for HTTP monitoring API (e.g. :8080)")
	certFile        = flag.String("cert", "", "TLS certificate file")
	keyFile         = flag.String("key", "", "TLS private key file")
	aikStorePath    = flag.String("aik-store", "/var/lib/lota/aiks", "AIK key store directory")
	dbPath          = flag.String("db", "", "SQLite database path for persistent storage (empty = file/memory stores)")
	policyFile      = flag.String("policy", "", "PCR policy file (YAML)")
	policyPubKey    = flag.String("policy-pubkey", "", "Ed25519 public key for policy signature verification (PEM)")
	adminAPIKey     = flag.String("admin-api-key", "", "API key for admin endpoints (revoke, ban); if empty, admin endpoints are disabled")
	readerAPIKey    = flag.String("reader-api-key", "", "API key for sensitive read-only endpoints (clients, audit, attestations); if empty, those endpoints are public")
	generateCert    = flag.Bool("generate-cert", false, "Generate self-signed certificate")
	aikMaxAge       = flag.Duration("aik-max-age", 30*24*time.Hour, "Maximum AIK registration age before key rotation is required (0 = no expiry)")
	logFormat       = flag.String("log-format", "text", "Log output format: text or json")
	logLevel        = flag.String("log-level", "info", "Minimum log level: debug, info, warn, error, security")
	requireEventLog = flag.Bool("require-event-log", false, "Reject attestation reports without an event log")
)

// resolveAPIKey returns the flag value if set, otherwise falls back to the environment variable
func resolveAPIKey(flagVal *string, envVar string) string {
	if *flagVal != "" {
		return *flagVal
	}
	return os.Getenv(envVar)
}

func main() {
	flag.Parse()

	// initialize structured logger
	logger := logging.New(logging.Options{
		Level:  *logLevel,
		Format: *logFormat,
		Output: os.Stderr,
	})

	// shared metrics registry
	m := metrics.New()

	logger.Info("LOTA Verifier starting",
		"log_format", *logFormat, "log_level", *logLevel)

	if *generateCert {
		if err := generateTestCert(); err != nil {
			logger.Error("failed to generate certificate", "error", err)
			os.Exit(1)
		}
		logger.Info("generated test certificates",
			"cert", "lota-verifier.crt", "key", "lota-verifier.key")
		if *certFile == "" {
			*certFile = "lota-verifier.crt"
			*keyFile = "lota-verifier.key"
		}
	}

	// validate tls config
	if *certFile == "" || *keyFile == "" {
		logger.Error("TLS certificate and key required (use --generate-cert for testing)")
		os.Exit(1)
	}

	// initialize stores
	var aikStore store.AIKStore
	var auditLog store.AuditLog
	var attestLog store.AttestationLog
	verifierCfg := verify.DefaultConfig()
	verifierCfg.Logger = logger
	verifierCfg.Metrics = m
	verifierCfg.AIKMaxAge = *aikMaxAge
	verifierCfg.RequireEventLog = *requireEventLog

	if *aikMaxAge == 0 {
		logger.Warn("AIK expiry disabled (--aik-max-age=0): registered keys will never expire")
	} else {
		logger.Info("AIK key rotation enabled", "max_age", *aikMaxAge)
	}

	if *dbPath != "" {
		db, err := store.OpenDB(*dbPath)
		if err != nil {
			logger.Error("failed to open database", "path", *dbPath, "error", err)
			os.Exit(1)
		}
		defer db.Close()

		aikStore = store.NewSQLiteAIKStore(db)
		verifierCfg.BaselineStore = verify.NewSQLiteBaselineStore(db)
		verifierCfg.UsedNonceBackend = verify.NewSQLiteUsedNonceBackend(db)

		// enforcement stores - revocation, bans, audit log
		auditLog = store.NewSQLiteAuditLog(db)
		verifierCfg.RevocationStore = store.NewSQLiteRevocationStore(db, auditLog)
		verifierCfg.BanStore = store.NewSQLiteBanStore(db, auditLog)

		// attestation decision log
		attestLog = store.NewSQLiteAttestationLog(db)
		verifierCfg.AttestationLog = attestLog

		ver, _ := store.SchemaVersion(db)
		logger.Info("SQLite store initialized", "path", *dbPath, "schema_version", ver)
	} else {
		// file-based AIK store + in-memory baseline/nonce stores
		fileStore, err := store.NewFileStore(*aikStorePath)
		if err != nil {
			logger.Error("failed to initialize AIK store", "path", *aikStorePath, "error", err)
			os.Exit(1)
		}
		aikStore = fileStore

		// in-memory enforcement stores
		auditLog = store.NewMemoryAuditLog()
		verifierCfg.RevocationStore = store.NewMemoryRevocationStore(auditLog)
		verifierCfg.BanStore = store.NewMemoryBanStore(auditLog)

		// in-memory attestation decision log
		attestLog = store.NewMemoryAttestationLog()
		verifierCfg.AttestationLog = attestLog

		logger.Info("file-based AIK store initialized",
			"path", *aikStorePath, "registered_clients", len(fileStore.ListClients()))
	}

	verifier := verify.NewVerifier(verifierCfg, aikStore)

	verifier.AddPolicy(verify.DefaultPolicy())
	logger.Info("loaded default PCR policy")

	// policy signature verification key
	if *policyPubKey != "" {
		pubKey, err := verify.LoadPolicyPublicKey(*policyPubKey)
		if err != nil {
			logger.Error("failed to load policy public key", "path", *policyPubKey, "error", err)
			os.Exit(1)
		}
		verifier.SetPolicyPublicKey(pubKey)
		logger.Info("policy signature verification enabled", "pubkey", *policyPubKey)
	}

	// custom policy if specified
	if *policyFile != "" {
		if err := verifier.LoadPolicy(*policyFile); err != nil {
			logger.Error("failed to load policy", "path", *policyFile, "error", err)
			os.Exit(1)
		}
		logger.Info("loaded custom policy", "path", *policyFile)
	}

	// resolve API keys (flag -> env var fallback)
	adminKey := resolveAPIKey(adminAPIKey, "LOTA_ADMIN_API_KEY")
	readerKey := resolveAPIKey(readerAPIKey, "LOTA_READER_API_KEY")

	if adminKey != *adminAPIKey && adminKey != "" {
		logger.Info("admin API key loaded from LOTA_ADMIN_API_KEY environment variable")
	}
	if readerKey != *readerAPIKey && readerKey != "" {
		logger.Info("reader API key loaded from LOTA_READER_API_KEY environment variable")
	}

	// initialize tls server
	serverCfg := server.ServerConfig{
		Address:        *addr,
		HTTPAddress:    *httpAddr,
		CertFile:       *certFile,
		KeyFile:        *keyFile,
		AuditLog:       auditLog,
		Logger:         logger,
		Metrics:        m,
		AttestationLog: attestLog,
		AdminAPIKey:    adminKey,
		ReaderAPIKey:   readerKey,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   10 * time.Second,
	}

	if *httpAddr != "" && adminKey == "" {
		logger.Warn("HTTP API enabled without admin API key: admin endpoints (revoke, ban) will be disabled")
	}
	if *httpAddr != "" && readerKey == "" {
		logger.Warn("HTTP API enabled without reader API key: sensitive read-only endpoints will be public")
	}

	srv, err := server.NewServer(serverCfg, verifier)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	if err := srv.Start(); err != nil {
		logger.Error("failed to start server", "error", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	logger.Info("shutting down", "signal", sig.String())

	srv.Stop()
	logger.Info("LOTA Verifier stopped")
}

// creates a self-signed certificate for testing
func generateTestCert() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"LOTA Verifier"},
			CommonName:   "lota-verifier",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "lota-verifier"},
	}

	// self-sign
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// write certificate
	certFile, err := os.Create("lota-verifier.crt")
	if err != nil {
		return err
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	// write private key
	keyFile, err := os.OpenFile("lota-verifier.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}

	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return err
	}

	return nil
}
