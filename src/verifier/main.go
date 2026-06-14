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
//   --pg-dsn DSN       PostgreSQL DSN for shared multi-instance storage
//                      (or LOTA_PG_DSN); mutually exclusive with --db
//   --policy FILE      PCR policy file (YAML)
//   --policy-pubkey FILE Ed25519 public key for policy signature verification

// Environment variables:
//   LOTA_ADMIN_API_KEY  API key for admin endpoints (revoke, ban); required for mutation
//   LOTA_READER_API_KEY API key for sensitive read-only endpoints; if empty, the
//                       read tier is public on a loopback bind and the server
//                       refuses a non-loopback bind unless LOTA_ADMIN_API_KEY is set
//   LOTA_PG_DSN         PostgreSQL DSN for the shared storage backend; keeps
//                       connection credentials out of the process argument list
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
	"math"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/server"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("%v", []string(*s))
}

func (s *stringSliceFlag) Set(v string) error {
	if v == "" {
		return fmt.Errorf("empty value")
	}
	*s = append(*s, v)
	return nil
}

var (
	addr         = flag.String("addr", ":8443", "Listen address for TLS attestation protocol")
	httpAddr     = flag.String("http-addr", "", "Listen address for HTTP monitoring API (e.g. :8080)")
	certFile     = flag.String("cert", "", "TLS certificate file")
	keyFile      = flag.String("key", "", "TLS private key file")
	aikStorePath = flag.String("aik-store", "/var/lib/lota/aiks", "AIK key store directory")
	dbPath       = flag.String("db", "", "SQLite database path for persistent storage (empty = file/memory stores)")
	policyFile   = flag.String("policy", "", "PCR policy file (YAML)")
	policyPubKey = flag.String("policy-pubkey", "", "Ed25519 public key for policy signature verification (PEM)")

	generateCert         = flag.Bool("generate-cert", false, "Generate self-signed certificate")
	logFormat            = flag.String("log-format", "text", "Log output format: text or json")
	logLevel             = flag.String("log-level", "info", "Minimum log level: debug, info, warn, error, security")
	requireEventLog      = flag.Bool("require-event-log", true, "Require attestation reports to include a TPM event log (mandatory)")
	requireCert          = flag.Bool("require-cert", true, "Require a Privacy CA-issued AIK certificate; reject reports without one (production default)")
	allowLegacyPCRMask   = flag.Bool("allow-legacy-pcr-mask", false, "INSECURE: accept attestation reports whose pcr_mask omits PCR 0/1/7 (firmware/Secure Boot); allows pre-PCR0/1/7 fleets to attest without firmware baseline pinning")
	allowNoInitramfsLock = flag.Bool("allow-no-initramfs-lock", false, "INSECURE: accept attestation reports that do not advertise FlagInitramfsLockV1 (initramfs PCR14 lock). Use only for legacy hosts without the 90lota dracut module installed; the kernel-handoff -> lota-agent PCR14 window is no longer covered for those hosts.")
	allowTOFUBoot        = flag.Bool("allow-tofu-boot-baseline", false, "INSECURE: allow TOFU first-use of the per-client PCR0/PCR1/PCR7 boot baseline regardless of policy or event-log state. With the default (false), a first-attestation client must be covered by a signed policy that pins PCR0/PCR1/PCR7, be pre-enrolled in the baseline store, or pass the event-log Secure Boot gate of a policy with require_secureboot (the diverse-fleet path); otherwise the report is refused so a host that boots on already-compromised firmware cannot self-pin its tampered baseline.")
	maxRestartSkew       = flag.Uint("max-restart-count-skew", 64, "Maximum restart_count drift (TPM2_Startup STATE cycles, i.e. suspend/resume) tolerated when matching the PCR14 boot-commitment digest against the quote ClockInfo. 0 = exact match required. The default of 64 covers laptop suspend/resume cadences past any realistic operator interval; raising it grows the matcher's brute-force surface linearly without buying additional uptime.")
	rejectLegacyBase     = flag.Bool("reject-legacy-baselines", false, "Reject attestations whose stored baseline row pre-dates FlagBootCommitment and would be silently backfilled with the current agent_hash. Enable once the agent rollout grace period has closed.")
	selfServiceReanchor  = flag.Bool("enable-self-service-reanchor", false, "Diverse-fleet only: on a firmware/Secure Boot PCR drift, let the verifier re-pin the per-device boot baseline itself when the drift preserves the Secure Boot root of trust (PK/KEK/db unchanged, dbx append-only, Secure Boot on, firmware version not rolled back), instead of rejecting until an operator clears the row. Only takes effect under a policy with require_secureboot; leave off for the enterprise profile.")
	allowPermissive      = flag.Bool("allow-permissive-policy", false, "INSECURE: allow starting with a permissive PCR policy (no PCR values and no kernel/agent hash allowlists)")
	allowUnpinnedAgent   = flag.Bool("allow-unpinned-agent", false, "INSECURE: allow a diverse-fleet policy (require_secureboot, no raw PCR pins) with empty agent_hashes. The agent self-hash is then TOFU, so a modified non-enforcing agent can pin its own hash and attest while doing no enforcement. Pin the official agent hash (from the signed release) in agent_hashes instead.")
	aikCACerts           stringSliceFlag
	aikCRLs              stringSliceFlag
	ekCRLsDeprecated     stringSliceFlag
	pgDSN                = flag.String("pg-dsn", "", "PostgreSQL DSN for shared multi-instance storage (or LOTA_PG_DSN env); selects the Postgres backend for baseline, nonce, revocation, ban, audit and attestation state. Mutually exclusive with --db.")
	nonceDBPath          = flag.String("nonce-db", "", "SQLite database path for used nonce history (defaults to <aik-store>/used_nonces.sqlite); set --allow-insecure-memory-nonces to disable persistence")
	allowMemNonces       = flag.Bool("allow-insecure-memory-nonces", false, "INSECURE: allow memory-only used nonce history (replay window after verifier restart)")
)

func main() {
	flag.Var(&aikCACerts, "aik-ca-cert", "Trusted attestation-CA root (PEM) the AIK certificate must chain to; may be repeated")
	flag.Var(&aikCRLs, "aik-crl", "CRL file (PEM or DER) used to revoke compromised AIK certificates; may be repeated. Each CRL must be signed by one of the --aik-ca-cert roots.")
	flag.Var(&ekCRLsDeprecated, "ek-crl", "DEPRECATED alias for --aik-crl. The CRLs loaded here revoke AIK certificates issued by the deployment's attestation CA, not endorsement keys; the TPM-manufacturer EK revocation feed is the attestation CA's -ek-crl flag.")
	flag.Parse()

	// initialize structured logger
	logger := logging.New(logging.Options{
		Level:  *logLevel,
		Format: *logFormat,
		Output: os.Stderr,
	})

	if len(ekCRLsDeprecated) > 0 {
		logger.Warn("--ek-crl is deprecated and will be removed; use --aik-crl",
			"reason", "the flag revokes AIK certificates, not endorsement keys; the EK-manufacturer CRL feed lives on lota-attest-ca (-ek-crl)")
		aikCRLs = append(aikCRLs, ekCRLsDeprecated...)
	}

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
	if !*requireEventLog {
		logger.Error("event log verification is mandatory and cannot be disabled",
			"hint", "remove --require-event-log=false and provide event logs from agents")
		os.Exit(1)
	}
	verifierCfg.RequireEventLog = *requireEventLog
	verifierCfg.RequireCert = *requireCert
	verifierCfg.RequireBootPCRs = !*allowLegacyPCRMask
	if *allowLegacyPCRMask {
		logger.Warn("INSECURE: --allow-legacy-pcr-mask is set; agents may attest without PCR 0/1/7 and bypass the firmware/Secure Boot baseline pin")
	}
	verifierCfg.RequireInitramfsLock = !*allowNoInitramfsLock
	if *allowNoInitramfsLock {
		logger.Warn("INSECURE: --allow-no-initramfs-lock is set; agents may attest without the initramfs PCR14 lock, leaving the kernel-handoff -> lota-agent window uncovered")
	}
	verifierCfg.RequireBootEnrollment = !*allowTOFUBoot
	if *allowTOFUBoot {
		logger.Warn("INSECURE: --allow-tofu-boot-baseline is set; a first-attestation client will TOFU-pin whatever PCR0/PCR1/PCR7 values it reports, including firmware/Secure Boot state that may already be compromised")
	}
	verifierCfg.EnableSelfServiceReanchor = *selfServiceReanchor
	if *selfServiceReanchor {
		logger.Info("self-service re-anchor enabled (diverse-fleet); a firmware/Secure Boot drift that preserves the Secure Boot root of trust will re-pin the per-device baseline automatically")
	}
	if *maxRestartSkew > math.MaxUint32 {
		logger.Error("--max-restart-count-skew exceeds uint32 range",
			"value", *maxRestartSkew, "max", uint64(math.MaxUint32))
		os.Exit(1)
	}
	verifierCfg.MaxRestartCountSkew = uint32(*maxRestartSkew)
	verifierCfg.RejectLegacyBaselines = *rejectLegacyBase
	if *rejectLegacyBase {
		logger.Info("rejecting legacy baseline agent_hash backfills")
	}
	verifierCfg.AllowPermissivePolicy = *allowPermissive
	verifierCfg.AllowUnpinnedAgent = *allowUnpinnedAgent
	if *allowUnpinnedAgent {
		logger.Warn("INSECURE: --allow-unpinned-agent is set; a diverse-fleet policy may run with the agent self-hash on TOFU, so a modified non-enforcing agent could pin its own hash and attest without enforcing")
	}

	// resolve the Postgres DSN from flag or environment
	// the env form keeps connection credentials out of the process argument list
	dsn := *pgDSN
	if dsn == "" {
		dsn = os.Getenv("LOTA_PG_DSN")
	}
	if dsn != "" && *dbPath != "" {
		logger.Error("choose one storage backend: --pg-dsn (Postgres) or --db (SQLite), not both")
		os.Exit(1)
	}

	if dsn != "" {
		// Postgres backend: shared, multi-instance state for deployments
		// behind a load balancer.
		// Mutable enforcement, baseline and nonce state lives in Postgres
		// so any instance sees writes made by any peer.
		//
		// Unlike the SQLite --db block, this path supports the
		// certificate-backed AIK store, so a production --require-cert fleet
		// can run several verifier instances against one database
		db, err := store.OpenPostgresDB(dsn)
		if err != nil {
			logger.Error("failed to open Postgres database", "error", err)
			os.Exit(1)
		}
		defer db.Close()

		verifierCfg.BaselineStore = verify.NewPostgresBaselineStore(db)
		verifierCfg.UsedNonceBackend = verify.NewPostgresUsedNonceBackend(db)
		verifierCfg.SessionTokenStore = verify.NewPostgresSessionTokenStore(db)

		auditLog = store.NewPostgresAuditLog(db)
		verifierCfg.RevocationStore = store.NewPostgresRevocationStore(db, auditLog)
		verifierCfg.BanStore = store.NewPostgresBanStore(db, auditLog)

		attestLog = store.NewPostgresAttestationLog(db)
		verifierCfg.AttestationLog = attestLog

		// AIK store: certificate-backed when the deployment verifies chains
		// (the production default), otherwise a shared TOFU store in Postgres
		if *requireCert || len(aikCACerts) > 0 {
			if *requireCert && len(aikCACerts) == 0 {
				logger.Error("--require-cert requires a trusted attestation-CA root for AIK verification",
					"hint", "provide one or more --aik-ca-cert PEM paths (the Privacy CA root), or disable --require-cert (INSECURE)")
				//nolint:gocritic // startup abort before any DB write; the OS reclaims the handle
				os.Exit(1)
			}
			if len(aikCRLs) > 0 && len(aikCACerts) == 0 {
				logger.Error("--aik-crl requires at least one --aik-ca-cert to verify CRL signatures")
				os.Exit(1)
			}
			cs, err := store.NewCertificateStoreWithCRL(*aikStorePath, []string(aikCACerts), []string(aikCRLs), *requireCert)
			if err != nil {
				logger.Error("failed to initialize certificate-backed AIK store", "path", *aikStorePath, "error", err)
				os.Exit(1)
			}
			aikStore = cs
			logger.Info("certificate-backed AIK store initialized",
				"path", *aikStorePath,
				"trusted_cas", len(aikCACerts),
				"loaded_crls", cs.CRLCount(),
				"require_cert", *requireCert,
				"registered_clients", len(cs.ListClients()))
		} else {
			aikStore = store.NewPostgresAIKStore(db)
			logger.Warn("INSECURE: Postgres TOFU AIK store initialized without certificate verification",
				"hint", "set --require-cert and --aik-ca-cert to verify AIK certificate chains")
		}

		ver, err := store.SchemaVersion(db)
		if err != nil {
			logger.Warn("failed to read Postgres schema version", "error", err)
		} else {
			logger.Info("Postgres store initialized", "schema_version", ver)
		}
	} else if *dbPath != "" {
		if *requireCert {
			logger.Error("--require-cert is enabled but SQLite AIK store does not support certificate chain verification",
				"hint", "run without --db and configure --aik-ca-cert to use CertificateStore, or disable --require-cert (INSECURE)")
			os.Exit(1)
		}
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

		ver, err := store.SchemaVersion(db)
		if err != nil {
			logger.Warn("failed to read SQLite schema version", "path", *dbPath, "error", err)
		} else {
			logger.Info("SQLite store initialized", "path", *dbPath, "schema_version", ver)
		}
	} else {
		// persist used nonce history even without --db
		// otherwise, a verifier restart re-opens a replay window within nonce TTL
		if !*allowMemNonces {
			path := *nonceDBPath
			if path == "" {
				path = filepath.Join(*aikStorePath, "used_nonces.sqlite")
			}
			db, err := store.OpenDB(path)
			if err != nil {
				logger.Error("failed to open nonce DB (required for anti-replay persistence)",
					"path", path,
					"error", err,
					"hint", "use --nonce-db to set a writable path, or (INSECURE) pass --allow-insecure-memory-nonces")
				os.Exit(1)
			}
			defer db.Close()
			verifierCfg.UsedNonceBackend = verify.NewSQLiteUsedNonceBackend(db)
			logger.Info("persistent used nonce backend enabled",
				"path", path)
		} else {
			logger.Warn("INSECURE: using memory-only used nonce backend; verifier restart re-opens replay window",
				"nonce_lifetime", verifierCfg.NonceLifetime)
		}

		// file-based AIK store (optionally certificate-backed)
		if *requireCert && len(aikCACerts) == 0 {
			logger.Error("--require-cert requires a trusted attestation-CA root for AIK verification",
				"hint", "provide one or more --aik-ca-cert PEM paths (the Privacy CA root), or disable --require-cert (INSECURE)")
			os.Exit(1)
		}

		if len(aikCACerts) > 0 || *requireCert {
			if len(aikCRLs) > 0 && len(aikCACerts) == 0 {
				logger.Error("--aik-crl requires at least one --aik-ca-cert to verify CRL signatures")
				os.Exit(1)
			}
			cs, err := store.NewCertificateStoreWithCRL(*aikStorePath, []string(aikCACerts), []string(aikCRLs), *requireCert)
			if err != nil {
				logger.Error("failed to initialize certificate-backed AIK store", "path", *aikStorePath, "error", err)
				os.Exit(1)
			}
			aikStore = cs
			logger.Info("certificate-backed AIK store initialized",
				"path", *aikStorePath,
				"trusted_cas", len(aikCACerts),
				"loaded_crls", cs.CRLCount(),
				"require_cert", *requireCert,
				"registered_clients", len(cs.ListClients()))
		} else {
			fileStore, err := store.NewFileStore(*aikStorePath)
			if err != nil {
				logger.Error("failed to initialize AIK store", "path", *aikStorePath, "error", err)
				os.Exit(1)
			}
			aikStore = fileStore
			logger.Info("file-based AIK store initialized",
				"path", *aikStorePath, "registered_clients", len(fileStore.ListClients()))
		}

		// in-memory enforcement stores
		auditLog = store.NewMemoryAuditLog()
		verifierCfg.RevocationStore = store.NewMemoryRevocationStore(auditLog)
		verifierCfg.BanStore = store.NewMemoryBanStore(auditLog)

		// in-memory attestation decision log
		attestLog = store.NewMemoryAttestationLog()
		verifierCfg.AttestationLog = attestLog

	}

	verifier := verify.NewVerifier(verifierCfg, aikStore)

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
	} else if *allowPermissive {
		if err := verifier.AddPolicy(verify.DefaultPolicy()); err != nil {
			logger.Error("failed to add permissive default PCR policy", "error", err)
			os.Exit(1)
		}
		logger.Warn("INSECURE: loaded permissive built-in PCR policy",
			"hint", "configure --policy with explicit pcrs and/or kernel_hashes/agent_hashes for production")
	} else {
		logger.Error("no PCR policy configured",
			"hint", "provide --policy with explicit measurements, or pass --allow-permissive-policy (INSECURE)")
		os.Exit(1)
	}

	// fail closed on a policy with no measurement allowlists unless explicitly allowed
	if policy, ok := verifier.ActivePolicyConfig(); ok {
		if verify.IsMeasurementEmptyPolicy(policy) && !*allowPermissive {
			logger.Error("refusing to start with measurement-empty PCR policy",
				"policy", policy.Name,
				"hint", "define pcrs and/or kernel_hashes/agent_hashes in a policy file via --policy, or pass --allow-permissive-policy (INSECURE)")
			os.Exit(1)
		}
	}

	// resolve API keys (environment variable only for security)
	adminKey := os.Getenv("LOTA_ADMIN_API_KEY")
	readerKey := os.Getenv("LOTA_READER_API_KEY")

	if adminKey != "" {
		logger.Info("admin API key loaded from LOTA_ADMIN_API_KEY")
	}
	if readerKey != "" {
		logger.Info("reader API key loaded from LOTA_READER_API_KEY")
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
	if *httpAddr != "" && readerKey == "" && adminKey == "" {
		logger.Warn("HTTP API enabled without reader or admin API key: sensitive read-only endpoints are public on a loopback bind; a non-loopback bind will be refused")
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
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// crlReloader is non-nil only when the operator booted with a
	// certificate-backed AIK store; that is also the only path that
	// loaded any CRLs. SIGHUP re-runs the same load+verify gates as
	// startup and atomically swaps the active set on success, leaving
	// the existing set in place when the refresh fails.
	type crlReloader interface{ ReloadCRLs() error }
	var reloader crlReloader
	if r, ok := aikStore.(crlReloader); ok {
		reloader = r
	}

	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			if reloader == nil {
				logger.Warn("SIGHUP: no certificate-backed CRL store configured; nothing to reload")
				continue
			}
			if err := reloader.ReloadCRLs(); err != nil {
				logger.Error("SIGHUP: CRL reload failed; keeping previous set", "error", err)
				continue
			}
			if cs, ok := aikStore.(interface{ CRLCount() int }); ok {
				logger.Info("SIGHUP: CRL feed reloaded", "loaded_crls", cs.CRLCount())
			} else {
				logger.Info("SIGHUP: CRL feed reloaded")
			}
		default:
			logger.Info("shutting down", "signal", sig.String())
			srv.Stop()
			logger.Info("LOTA Verifier stopped")
			return
		}
	}
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
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost", "lota-verifier"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// self-sign
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// write certificate (world-readable) and private key (owner-only)
	if err := writePEMFile("lota-verifier.crt", 0o644,
		&pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	if err := writePEMFile("lota-verifier.key", 0o600,
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// writePEMFile writes block to path with perm. The file's Close error is
// reported even when the PEM encoding itself succeeds, so a flush failure
// is not lost.
func writePEMFile(path string, perm os.FileMode, block *pem.Block) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	return pem.Encode(f, block)
}
