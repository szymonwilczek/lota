// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Remote attestation verification service

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
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
	addr           = flag.String("addr", ":8443", "Listen address for TLS attestation protocol")
	maxConnections = flag.Int("max-connections", server.DefaultMaxConnections,
		"Maximum concurrent attestation connections. Each one costs a TLS handshake and a full report verification, so this bounds what a client stampede can spend; connections past the cap are refused at accept. -1 disables the cap (load rigs only).")
	httpAddr      = flag.String("http-addr", "", "Listen address for HTTP monitoring API (e.g. :8080)")
	shutdownDrain = flag.Duration("shutdown-drain", 0,
		"How long the monitoring API keeps answering after the attestation listener has closed on shutdown. /health answers 503 degraded for that window, which is what a load balancer reads to stop routing here before the process goes; set it to at least one health-check interval behind one. Zero shuts the API down as soon as it is idle.")
	certFile     = flag.String("cert", "", "TLS certificate file")
	keyFile      = flag.String("key", "", "TLS private key file")
	dbPath       = flag.String("db", "", "SQLite database path for all verifier state (empty = --state-db, which keeps no boot baselines)")
	policyFiles  stringSliceFlag
	policyPubKey = flag.String("policy-pubkey", "", "Ed25519 public key for policy signature verification (PEM)")

	generateCert        = flag.Bool("generate-cert", false, "Generate self-signed certificate")
	logFormat           = flag.String("log-format", "text", "Log output format: text or json")
	logLevel            = flag.String("log-level", "info", "Minimum log level: debug, info, warn, error, security")
	requireCert         = flag.Bool("require-cert", true, "Require Privacy CA trust anchors at startup: refuses to start without --aik-ca-cert. Reports without a CA-issued AIK certificate are always rejected at verification; disabling this only skips the startup validation (INSECURE: a deployment without a CA root cannot attest any client)")
	allowTOFUBoot       = flag.Bool("allow-tofu-boot-baseline", false, "INSECURE: allow TOFU first-use of the per-client PCR0/PCR1/PCR7 boot baseline regardless of policy or event-log state. With the default (false), a first-attestation client must be covered by a signed policy that pins PCR0/PCR1/PCR7, be pre-enrolled in the baseline store, or pass the event-log Secure Boot gate of a policy with require_secureboot (the diverse-fleet path); otherwise the report is refused so a host that boots on already-compromised firmware cannot self-pin its tampered baseline.")
	selfServiceReanchor bool
	allowPermissive     = flag.Bool("allow-permissive-policy", false, "INSECURE: allow starting with a permissive PCR policy (no PCR values and no kernel/agent hash allowlists)")
	allowUnpinnedAgent  bool
	aikCACerts          stringSliceFlag
	aikCRLs             stringSliceFlag
	pgShardDSNs         stringSliceFlag
	pgDSN               = flag.String("pg-dsn", "", "PostgreSQL DSN for shared multi-instance storage (or LOTA_PG_DSN env); selects the Postgres backend for baseline, nonce, revocation, ban, audit and attestation state. The database must be writable: the verifier applies its schema at startup, so a hot standby is refused. Mutually exclusive with --db.")
	pgMaxOpenConns      = flag.Int("pg-max-open-conns", store.DefaultPGMaxOpenConns, "Maximum open Postgres connections per instance (per shard when sharded). Postgres group-commits concurrent transactions, so a wider pool raises enrollment/attestation burst throughput; keep the value times the instance count under the database's max_connections.")
	stateDBPath         = flag.String("state-db", "/var/lib/lota/verifier-state.sqlite", "SQLite database an instance without --db or --pg-dsn keeps its durable state in: used nonce history, revocations, hardware bans, the audit log and the attestation decision log; set --allow-insecure-memory-state to keep none of it")
	scopedKeysFile      = flag.String("api-keys-file", "", "YAML file of scoped monitoring-API keys (entries of key_sha256, role: reader|admin, tenants list or * for all); reloaded on SIGHUP. Environment keys keep working with global scope.")
	allowMemState       = flag.Bool("allow-insecure-memory-state", false, "INSECURE: keep no durable state without a database. The used nonce history lives in memory, so a restart re-opens a replay window, and this instance holds no revocations, bans, audit log or decision log at all -- those endpoints answer 503.")
	reportOnly          = flag.Bool("report-only", false, "Serve the monitoring API from a database this instance never writes -- a Postgres hot standby or the primary -- with no attestation listener bound and every state-changing endpoint refused. Requires --http-addr and a Postgres DSN; the schema is verified but never applied, so the reporting load that is not the verifier's can be taken off the primary.")
	printVersions       = flag.Bool("print-versions", false, "Print the attestation report wire version this binary implements, the schema version it builds each backend up to, and its TLS floor, then exit. The report wire must match the agent fleet's exactly.")
)

var attestLogWindow = flag.Duration("attestation-log-window",
	store.DefaultCollapseWindow,
	"How long one decision-log row may stand for. A trusted "+
		"round that repeats what the row standing for that host "+
		"already says updates that row (last seen, rounds) without "+
		"writing a new one. Refusals, verdict changes and first "+
		"sightings always get their own row whatever this is set "+
		"to. Zero writes every round as its own row, which is what "+
		"a deployment whose retention rule counts rows asks for.")

var errCRLWithoutCARoot = errors.New("--aik-crl requires at least one --aik-ca-cert to verify CRL signatures")

type aikVerifierParams struct {
	CACerts     []string
	CRLs        []string
	RequireCert bool
}

// selectAIKVerifier returns nil when no CA root is given, unless CRLs are
// given or RequireCert is set, which is an error.
func selectAIKVerifier(p aikVerifierParams) (*store.CertificateVerifier, error) {
	if len(p.CACerts) == 0 {
		if len(p.CRLs) > 0 {
			return nil, errCRLWithoutCARoot
		}
		if p.RequireCert {
			return nil, fmt.Errorf("%w: provide one or more --aik-ca-cert PEM paths (the Privacy CA root), or disable --require-cert (INSECURE)",
				store.ErrNoTrustedCAs)
		}
		return nil, nil
	}
	return store.NewCertificateVerifier(p.CACerts, p.CRLs)
}

type enforcementStores struct {
	audit        store.AuditLog
	revocations  store.RevocationStore
	bans         store.BanStore
	attestations store.AttestationLog
}

// sqliteEnforcementStores keeps the group in a SQLite database.
func sqliteEnforcementStores(db *sql.DB, logger *slog.Logger, m *metrics.Metrics) enforcementStores {
	audit := store.NewSQLiteAuditLog(db)
	return enforcementStores{
		audit:       audit,
		revocations: store.NewSQLiteRevocationStore(db, audit),
		bans:        store.NewSQLiteBanStore(db, audit),
		attestations: store.NewBatchedAttestationLog(
			store.NewSQLiteAttestationLog(db, *attestLogWindow),
			store.BatchedAttestationLogConfig{Logger: logger, Loss: m}),
	}
}

// postgresEnforcementStores keeps the group in Postgres.
func postgresEnforcementStores(db *sql.DB, logger *slog.Logger, m *metrics.Metrics) enforcementStores {
	audit := store.NewPostgresAuditLog(db)
	return enforcementStores{
		audit:       audit,
		revocations: store.NewPostgresRevocationStore(db, audit),
		bans:        store.NewPostgresBanStore(db, audit),
		attestations: store.NewBatchedAttestationLog(
			store.NewPostgresAttestationLog(db, *attestLogWindow),
			store.BatchedAttestationLogConfig{Logger: logger, Loss: m}),
	}
}

func (e enforcementStores) install(cfg *verify.VerifierConfig) {
	cfg.RevocationStore = e.revocations
	cfg.BanStore = e.bans
	cfg.AttestationLog = e.attestations
}

// loadPolicies loads paths in order; the first becomes the active policy.
// A reused name is refused, and a policy neither active nor bound to a tenant
// is logged.
func loadPolicies(logger *slog.Logger, verifier *verify.Verifier, paths []string) error {
	for i, path := range paths {
		if err := verifier.LoadPolicy(path); err != nil {
			logger.Error("failed to load policy", "path", path, "error", err)
			return err
		}
		if len(verifier.ListPolicies()) != i+1 {
			logger.Error("policy file reuses the name of one already loaded, which would replace it",
				"path", path,
				"hint", "give each policy document its own name:")
			return errors.New("duplicate policy name")
		}
		logger.Info("loaded custom policy", "path", path)
	}

	active := ""
	if policy, ok := verifier.ActivePolicyConfig(); ok {
		active = policy.Name
		logger.Info("active policy", "policy", active,
			"hint", "clients whose tenant binds no policy of its own verify against this one")
	}

	bound := make(map[string]bool)
	for tenant, name := range verifier.TenantBindings() {
		bound[name] = true
		logger.Info("tenant bound to policy", "tenant", tenant, "policy", name)
	}

	for _, name := range verifier.ListPolicies() {
		if name == active || bound[name] {
			continue
		}
		logger.Warn("policy is loaded but no client can reach it: it is neither the active policy nor bound to a tenant",
			"policy", name,
			"hint", "give it a tenant: key, or pass it as the first --policy so it becomes the active one")
	}

	return nil
}

func main() {
	flag.Var(&pgShardDSNs, "pg-shard-dsn", "PostgreSQL shard DSN (or LOTA_PG_SHARD_DSNS as a comma-separated list); may be repeated. Partitions per-client baseline, nonce and session state across the given databases by a stable hash of the key, so the durable write tier scales past one database host. Mutually exclusive with --pg-dsn and --db. Every instance must be given the same shard list in the same order. Enforcement, audit and attestation-log state lives on the first shard.")
	flag.Var(&policyFiles, "policy",
		"PCR policy file (YAML); may be repeated. The first one "+
			"given is the active policy, which every client whose "+
			"tenant binds no policy of its own is verified "+
			"against; each further file must bind itself to a "+
			"tenant with a tenant: key, and clients in that "+
			"tenant are verified against it.")
	flag.Var(&aikCACerts, "aik-ca-cert", "Trusted attestation-CA root (PEM) the AIK certificate must chain to; may be repeated")
	flag.Var(&aikCRLs, "aik-crl", "CRL file (PEM or DER) used to revoke compromised AIK certificates; may be repeated. Each CRL must be signed by one of the --aik-ca-cert roots.")
	flag.BoolVar(&selfServiceReanchor, "enable-self-service-reanchor",
		false, "Override every policy's profile and force "+
			"self-service re-anchor on or off. Left unset, each "+
			"policy decides: profile: consumer enables it, "+
			"enterprise (and unset) leaves it off. When on, a "+
			"firmware/Secure Boot PCR drift re-pins the "+
			"per-device boot baseline automatically if it "+
			"preserves the Secure Boot root of trust (PK/KEK/db "+
			"unchanged, dbx append-only, Secure Boot on, "+
			"firmware version not rolled back). When off, such "+
			"a drift is rejected until an operator clears the "+
			"row. Only ever takes effect under a policy with "+
			"require_secureboot.")
	flag.BoolVar(&allowUnpinnedAgent, "allow-unpinned-agent", false,
		"INSECURE: allow a diverse-fleet policy "+
			"(require_secureboot, no raw PCR pins) with empty "+
			"agent_hashes. The agent self-hash is then TOFU, so "+
			"a modified non-enforcing agent can pin its own "+
			"hash and attest while doing no enforcement. Pin "+
			"the official agent hash (from the signed release) "+
			"in agent_hashes.")
	flag.Parse()

	if *printVersions {
		writeVersions(os.Stdout)
		return
	}

	logger := logging.New(logging.Options{
		Level:  *logLevel,
		Format: *logFormat,
		Output: os.Stderr,
	})

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

	if (*certFile == "" || *keyFile == "") && !*reportOnly {
		logger.Error("TLS certificate and key required (use --generate-cert for testing)")
		os.Exit(1)
	}

	var auditLog store.AuditLog
	var attestLog store.AttestationLog
	verifierCfg := verify.DefaultConfig()
	verifierCfg.Logger = logger
	verifierCfg.Metrics = m
	verifierCfg.RequireBootEnrollment = !*allowTOFUBoot
	if *allowTOFUBoot {
		logger.Warn("INSECURE: --allow-tofu-boot-baseline is set; a first-attestation client will TOFU-pin whatever PCR0/PCR1/PCR7 values it reports, including firmware/Secure Boot state that may already be compromised")
	}

	// only a flag given on the command line overrides the policy profile
	flag.Visit(func(f *flag.Flag) {
		if f.Name != "enable-self-service-reanchor" {
			return
		}
		override := selfServiceReanchor
		verifierCfg.EnableSelfServiceReanchor = &override
		logger.Info("self-service re-anchor forced from the command line, overriding every policy profile",
			"enabled", override)
	})
	if verifierCfg.EnableSelfServiceReanchor == nil {
		logger.Info("self-service re-anchor follows each policy's profile: consumer enables it, enterprise and unset leave it off")
	}
	verifierCfg.AllowPermissivePolicy = *allowPermissive
	verifierCfg.AllowUnpinnedAgent = allowUnpinnedAgent
	if allowUnpinnedAgent {
		logger.Warn("INSECURE: --allow-unpinned-agent is set; a diverse-fleet policy may run with the agent self-hash on TOFU, so a modified non-enforcing agent could pin its own hash and attest without enforcing")
	}

	// the environment keeps credentials out of the argument list
	dsn := *pgDSN
	if dsn == "" {
		dsn = os.Getenv("LOTA_PG_DSN")
	}
	shardDSNs := []string(pgShardDSNs)
	if len(shardDSNs) == 0 {
		if env := os.Getenv("LOTA_PG_SHARD_DSNS"); env != "" {
			for _, d := range strings.Split(env, ",") {
				if d = strings.TrimSpace(d); d != "" {
					shardDSNs = append(shardDSNs, d)
				}
			}
		}
	}
	if len(shardDSNs) > 0 && dsn != "" {
		logger.Error("choose one Postgres form: --pg-dsn (single database) or --pg-shard-dsn (sharded), not both")
		os.Exit(1)
	}
	usePostgres := dsn != "" || len(shardDSNs) > 0
	if usePostgres && *dbPath != "" {
		logger.Error("choose one storage backend: Postgres or --db (SQLite), not both")
		os.Exit(1)
	}

	if *reportOnly {
		if !usePostgres {
			logger.Error("--report-only reads a Postgres database",
				"hint", "give --pg-dsn (or --pg-shard-dsn) pointing at a standby or the primary")
			os.Exit(1)
		}
		if *httpAddr == "" {
			logger.Error("--report-only serves only the monitoring API",
				"hint", "give --http-addr the address to serve it on")
			os.Exit(1)
		}
		logger.Info("reporting mode: no attestation listener, no writes",
			"note", "the schema is verified but never applied, and every state-changing endpoint answers 503")
	}

	// OpenPostgresDB would replace a value below 1 with the default
	if usePostgres && *pgMaxOpenConns < 1 {
		logger.Error("--pg-max-open-conns must be at least 1",
			"value", *pgMaxOpenConns,
			"hint", fmt.Sprintf("omit the flag for the default of %d", store.DefaultPGMaxOpenConns))
		os.Exit(1)
	}

	certs, err := selectAIKVerifier(aikVerifierParams{
		CACerts:     []string(aikCACerts),
		CRLs:        []string(aikCRLs),
		RequireCert: *requireCert && !*reportOnly,
	})
	if err != nil {
		logger.Error("failed to initialize AIK certificate verification", "error", err)
		os.Exit(1)
	}
	var aikVerifier store.AIKCertVerifier
	if certs != nil {
		aikVerifier = certs
		logger.Info("AIK certificate verification initialized",
			"trusted_cas", len(aikCACerts),
			"loaded_crls", certs.CRLCount())
	} else if !*reportOnly {
		logger.Warn("INSECURE: no attestation-CA root configured; every report will be refused",
			"hint", "set --aik-ca-cert to verify AIK certificate chains")
	}

	if usePostgres {
		if len(shardDSNs) == 0 {
			shardDSNs = []string{dsn}
		}
		dbs := make([]*sql.DB, 0, len(shardDSNs))
		for i, d := range shardDSNs {
			open := store.OpenPostgresDB
			if *reportOnly {
				open = store.OpenPostgresDBReadOnly
			}
			sdb, err := open(d, *pgMaxOpenConns)
			if err != nil {
				logger.Error("failed to open Postgres database", "shard", i, "error", err)
				os.Exit(1)
			}

			if serverMax, err := store.ServerMaxConnections(sdb); err != nil {
				logger.Debug("could not read the database's max_connections",
					"shard", i, "error", err)
			} else if *pgMaxOpenConns > serverMax {
				logger.Warn("connection pool exceeds the database's max_connections",
					"shard", i, "pool", *pgMaxOpenConns, "max_connections", serverMax,
					"hint", "this instance alone cannot open its pool; lower --pg-max-open-conns or raise max_connections")
			} else if *pgMaxOpenConns > serverMax/2 {
				logger.Warn("connection pool leaves no room for a second instance",
					"shard", i, "pool", *pgMaxOpenConns, "max_connections", serverMax,
					"hint", "instances times pool must stay under max_connections")
			}
			dbs = append(dbs, sdb)
		}
		closeShards := func() {
			for _, sdb := range dbs {
				_ = sdb.Close()
			}
		}

		shardIDs := make([]string, len(dbs))
		identity := store.ShardIdentity
		assertShards := store.AssertShardSet
		if *reportOnly {
			// ShardIdentity writes the identity on first use
			identity = store.ReadShardIdentity
			assertShards = store.CheckShardSet
		}
		for i, sdb := range dbs {
			id, err := identity(context.Background(), sdb)
			if err != nil {
				logger.Error("failed to read shard identity", "shard", i, "error", err)
				closeShards()
				os.Exit(1)
			}
			shardIDs[i] = id
		}
		if err := assertShards(context.Background(), dbs, shardIDs); err != nil {
			logger.Error("shard set check failed", "error", err,
				"hint", "give every instance the same databases in the same order; "+
					"to change the set deliberately, migrate or re-enrol the fleet and "+
					"clear the pin with DELETE FROM shard_set on every shard")
			closeShards()
			os.Exit(1)
		}

		defer closeShards()
		db := dbs[0]

		if len(dbs) == 1 {
			verifierCfg.BaselineStore = verify.NewPostgresBaselineStore(db)
			verifierCfg.UsedNonceBackend = verify.NewPostgresUsedNonceBackend(db)
		} else {
			baselines := make([]verify.BaselineStorer, len(dbs))
			nonces := make([]verify.UsedNonceBackend, len(dbs))
			for i, sdb := range dbs {
				baselines[i] = verify.NewPostgresBaselineStore(sdb)
				nonces[i] = verify.NewPostgresUsedNonceBackend(sdb)
			}
			verifierCfg.BaselineStore = verify.NewShardedBaselineStore(baselines)
			verifierCfg.UsedNonceBackend = verify.NewShardedUsedNonceBackend(nonces)
			logger.Info("Postgres sharded storage enabled",
				"shards", len(dbs),
				"note", "per-client baseline/nonce partitioned; enforcement and audit on shard 0")
		}

		enforcement := postgresEnforcementStores(db, logger, m)
		enforcement.install(&verifierCfg)
		auditLog = enforcement.audit
		attestLog = enforcement.attestations

		ver, err := store.SchemaVersion(db)
		if err != nil {
			logger.Warn("failed to read Postgres schema version", "error", err)
		} else {
			logger.Info("Postgres store initialized", "schema_version", ver)
		}
	} else if *dbPath != "" {
		db, err := store.OpenDB(*dbPath)
		if err != nil {
			logger.Error("failed to open database", "path", *dbPath, "error", err)
			os.Exit(1)
		}
		defer db.Close()

		verifierCfg.BaselineStore = verify.NewSQLiteBaselineStore(db)
		verifierCfg.UsedNonceBackend = verify.NewSQLiteUsedNonceBackend(db)

		enforcement := sqliteEnforcementStores(db, logger, m)
		enforcement.install(&verifierCfg)
		auditLog = enforcement.audit
		attestLog = enforcement.attestations

		ver, err := store.SchemaVersion(db)
		if err != nil {
			logger.Warn("failed to read SQLite schema version", "path", *dbPath, "error", err)
		} else {
			logger.Info("SQLite store initialized", "path", *dbPath, "schema_version", ver)
		}
	} else {
		if !*allowMemState {
			path := *stateDBPath
			db, err := store.OpenDB(path)
			if err != nil {
				logger.Error("failed to open the state database (required for anti-replay and enforcement persistence)",
					"path", path,
					"error", err,
					"hint", "use --state-db to set a writable path, or (INSECURE) pass --allow-insecure-memory-state")
				os.Exit(1)
			}
			defer db.Close()
			verifierCfg.UsedNonceBackend = verify.NewSQLiteUsedNonceBackend(db)

			enforcement := sqliteEnforcementStores(db, logger, m)
			enforcement.install(&verifierCfg)
			auditLog = enforcement.audit
			attestLog = enforcement.attestations

			logger.Info("state database opened", "path", path,
				"holds", "used nonces, revocations, hardware bans, audit log, attestation log")
		} else {
			logger.Warn("INSECURE: no durable state; verifier restart re-opens a replay window and this instance holds no revocations, bans, audit log or decision log",
				"nonce_lifetime", verifierCfg.NonceLifetime,
				"api", "revocation, ban, audit and attestation endpoints answer 503")
		}
	}

	verifier := verify.NewVerifier(verifierCfg, aikVerifier)

	if *policyPubKey != "" {
		pubKey, err := verify.LoadPolicyPublicKey(*policyPubKey)
		if err != nil {
			logger.Error("failed to load policy public key", "path", *policyPubKey, "error", err)
			//nolint:gocritic // startup abort before any attestation is served; the OS reclaims the handle
			os.Exit(1)
		}
		verifier.SetPolicyPublicKey(pubKey)
		logger.Info("policy signature verification enabled", "pubkey", *policyPubKey)
	}

	switch {
	case *reportOnly:
		if len(policyFiles) > 0 {
			logger.Warn("policy files are not read in reporting mode",
				"files", len(policyFiles),
				"note", "this instance verifies nothing; the policy belongs on the instances that attest")
		}
	case len(policyFiles) > 0:
		if err := loadPolicies(logger, verifier, policyFiles); err != nil {
			os.Exit(1)
		}
	case *allowPermissive:
		if err := verifier.AddPolicy(verify.DefaultPolicy()); err != nil {
			logger.Error("failed to add permissive default PCR policy", "error", err)
			os.Exit(1)
		}
		logger.Warn("INSECURE: loaded permissive built-in PCR policy",
			"hint", "configure --policy with explicit pcrs and/or kernel_hashes/agent_hashes for production")
	default:
		logger.Error("no PCR policy configured",
			"hint", "provide --policy with explicit measurements, or pass --allow-permissive-policy (INSECURE)")
		os.Exit(1)
	}

	if policy, ok := verifier.ActivePolicyConfig(); ok {
		if verify.IsMeasurementEmptyPolicy(policy) && !*allowPermissive {
			logger.Error("refusing to start with measurement-empty PCR policy",
				"policy", policy.Name,
				"hint", "define pcrs and/or kernel_hashes/agent_hashes in a policy file via --policy, or pass --allow-permissive-policy (INSECURE)")
			os.Exit(1)
		}
	}

	adminKey := os.Getenv("LOTA_ADMIN_API_KEY")
	readerKey := os.Getenv("LOTA_READER_API_KEY")

	if adminKey != "" {
		logger.Info("admin API key loaded from LOTA_ADMIN_API_KEY")
	}
	if readerKey != "" {
		logger.Info("reader API key loaded from LOTA_READER_API_KEY")
	}

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
		ScopedKeysFile: *scopedKeysFile,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxConnections: *maxConnections,
		ShutdownDrain:  *shutdownDrain,
		ReportOnly:     *reportOnly,
	}

	if *httpAddr != "" && adminKey == "" && *scopedKeysFile == "" {
		logger.Warn("HTTP API enabled without admin API key: admin endpoints (revoke, ban) will be disabled")
	}
	if *httpAddr != "" && readerKey == "" && adminKey == "" && *scopedKeysFile == "" {
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

	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			if *scopedKeysFile != "" {
				if err := srv.ReloadAPIKeys(); err != nil {
					logger.Error("SIGHUP: API key reload failed; keeping previous set", "error", err)
				}
			}
			if certs == nil {
				if *scopedKeysFile == "" {
					logger.Warn("SIGHUP: no CRL feed configured; nothing to reload")
				}
				continue
			}
			if err := certs.ReloadCRLs(); err != nil {
				logger.Error("SIGHUP: CRL reload failed; keeping previous set", "error", err)
				continue
			}
			logger.Info("SIGHUP: CRL feed reloaded", "loaded_crls", certs.CRLCount())
		default:
			logger.Info("shutting down", "signal", sig.String())
			srv.Stop()
			if c, ok := attestLog.(interface{ Close() error }); ok {
				if err := c.Close(); err != nil {
					logger.Warn("attestation-log flush on shutdown failed", "error", err)
				}
			}

			if l, ok := attestLog.(interface {
				DroppedCount() int64
				FailedCount() int64
			}); ok {
				if dropped, failed := l.DroppedCount(), l.FailedCount(); dropped > 0 || failed > 0 {
					logger.Warn("decision log incomplete for this run",
						"dropped_buffer_full", dropped, "failed_writes", failed)
				}
			}
			logger.Info("LOTA Verifier stopped")
			return
		}
	}
}

// generateTestCert writes a self-signed certificate and key to the working
// directory.
func generateTestCert() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

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
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost", "lota-verifier"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

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

// writePEMFile writes block to path with perm, also on a file that exists.
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
	// before the write, so a key never sits under looser bits
	if err := f.Chmod(perm); err != nil {
		return err
	}
	return pem.Encode(f, block)
}
