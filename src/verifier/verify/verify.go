// SPDX-License-Identifier: MIT
// LOTA Verifier - Main verification orchestrator
//
// Coordinates all verification steps:
//   1. Parse and validate report structure
//   2. Verify nonce (freshness/anti-replay)
//   3. Verify TPM quote signature
//   4. Verify PCR values against policy
//   5. Generate verification result

package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

const sessionTokenDomain = "lota-session-token:v1"

func wipeBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func cloneSensitive(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func wipeReportSensitive(report *types.AttestationReport) {
	if report == nil {
		return
	}
	wipeBytes(report.TPM.QuoteSignature[:])
	wipeBytes(report.TPM.AttestData[:])
	wipeBytes(report.TPM.AIKPublic[:])
	wipeBytes(report.TPM.AIKCertificate[:])
	wipeBytes(report.TPM.EKCertificate[:])
	wipeBytes(report.TPM.Nonce[:])
	wipeBytes(report.TPM.PrevAIKPublic[:])
	wipeBytes(report.EventLog)
}

func sameRSAPublicKey(a, b *rsa.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	if a.N.Cmp(b.N) != 0 {
		return false
	}
	return a.E == b.E
}

func deriveHardwareIDFromEKCert(ekCertDER []byte) ([types.HardwareIDSize]byte, error) {
	var out [types.HardwareIDSize]byte
	cert, err := x509.ParseCertificate(ekCertDER)
	if err != nil {
		return out, fmt.Errorf("failed to parse EK certificate: %w", err)
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		// match agent: SHA-256(modulus bytes)
		sum := sha256.Sum256(pub.N.Bytes())
		copy(out[:], sum[:])
		return out, nil
	default:
		return out, fmt.Errorf("unsupported EK public key type: %T", cert.PublicKey)
	}
}

func unixTimestamp(t time.Time) uint64 {
	ts := t.Unix()
	if ts < 0 {
		return 0
	}
	return uint64(ts)
}

func verifyHardwareIDMatchesEKCert(report *types.AttestationReport, ekCertDER []byte) error {
	if report == nil {
		return errors.New("nil attestation report")
	}
	derivedHWID, err := deriveHardwareIDFromEKCert(ekCertDER)
	if err != nil {
		return err
	}
	if !bytes.Equal(derivedHWID[:], report.TPM.HardwareID[:]) {
		return errors.New("hardware_id/EK mismatch")
	}
	return nil
}

// main verification engine
type Verifier struct {
	nonceStore    *NonceStore
	pcrVerifier   *PCRVerifier
	aikStore      store.AIKStore
	baselineStore BaselineStorer

	// enforcement stores (nil = no enforcement)
	revocationStore store.RevocationStore
	banStore        store.BanStore

	// structured logging and telemetry
	log            *slog.Logger
	metrics        *metrics.Metrics
	attestationLog store.AttestationLog

	// configuration
	nonceLifetime    time.Duration
	sessionTokenLife time.Duration
	aikMaxAge        time.Duration

	// stateless session-token signer key (process-local secret)
	sessionTokenKey      [32]byte
	sessionTokenKeyReady bool

	// issued session tokens (ephemeral in-memory index for validation API)
	tokenMu    sync.Mutex
	tokenIndex map[[32]byte]sessionTokenRecord

	// monitoring
	startTime      time.Time
	totalAttests   atomic.Int64
	successAttests atomic.Int64
	failedAttests  atomic.Int64
	revokedAttests atomic.Int64
	bannedAttests  atomic.Int64

	// policy enforcement
	requireEventLog       bool
	requireCert           bool
	requireBootPCRs       bool
	requireInitramfsLock  bool
	requireBootEnrollment bool
	rejectLegacyBaselines bool
	maxRestartCountSkew   uint32
}

type sessionTokenRecord struct {
	ClientID   string
	HardwareID [types.HardwareIDSize]byte
	ValidUntil uint64
	ResultCode uint32
	Flags      uint32
	PCRMask    uint32
	Consumed   bool
}

type SessionTokenStatus struct {
	ClientID   string
	HardwareID [types.HardwareIDSize]byte
	ValidUntil uint64
	ResultCode uint32
	Flags      uint32
	PCRMask    uint32
	Consumed   bool
	Exists     bool
	Expired    bool
}

func validateTPMFieldSizes(report *types.AttestationReport) error {
	if int(report.TPM.AIKPublicSize) > len(report.TPM.AIKPublic) {
		return fmt.Errorf("invalid aik_public_size: %d > %d", report.TPM.AIKPublicSize, len(report.TPM.AIKPublic))
	}
	if int(report.TPM.AIKCertSize) > len(report.TPM.AIKCertificate) {
		return fmt.Errorf("invalid aik_cert_size: %d > %d", report.TPM.AIKCertSize, len(report.TPM.AIKCertificate))
	}
	if int(report.TPM.EKCertSize) > len(report.TPM.EKCertificate) {
		return fmt.Errorf("invalid ek_cert_size: %d > %d", report.TPM.EKCertSize, len(report.TPM.EKCertificate))
	}
	if int(report.TPM.AttestSize) > len(report.TPM.AttestData) {
		return fmt.Errorf("invalid attest_size: %d > %d", report.TPM.AttestSize, len(report.TPM.AttestData))
	}
	if int(report.TPM.QuoteSigSize) > len(report.TPM.QuoteSignature) {
		return fmt.Errorf("invalid quote_sig_size: %d > %d", report.TPM.QuoteSigSize, len(report.TPM.QuoteSignature))
	}
	if int(report.TPM.PrevAIKSize) > len(report.TPM.PrevAIKPublic) {
		return fmt.Errorf("invalid prev_aik_public_size: %d > %d", report.TPM.PrevAIKSize, len(report.TPM.PrevAIKPublic))
	}
	return nil
}

// holds verifier configuration
type VerifierConfig struct {
	// how long a challenge nonce is valid
	NonceLifetime time.Duration

	// how long issued tokens are valid
	SessionTokenLife time.Duration

	// maximum age of a registered AIK before key rotation is required
	// zero disables AIK expiry (not recommended)
	AIKMaxAge time.Duration

	// optional: persistent baseline store (nil = in-memory)
	BaselineStore BaselineStorer

	// optional: persistent used nonce backend (nil = in-memory)
	UsedNonceBackend UsedNonceBackend

	// optional: revocation enforcement (nil = no revocation checks)
	RevocationStore store.RevocationStore

	// optional: hardware ban enforcement (nil = no ban checks)
	BanStore store.BanStore

	// optional: structured logger (nil = default stderr text logger)
	Logger *slog.Logger

	// optional: Prometheus metrics (nil = no metrics)
	Metrics *metrics.Metrics

	// optional: attestation decision log (nil = no attestation audit)
	AttestationLog store.AttestationLog

	// if true, reject attestation reports that do not include an event log
	RequireEventLog bool

	// if true, reject new AIK registrations that do not provide
	// AIK or EK certificates (disables pure TOFU)
	RequireCert bool

	// if true, reject attestation reports whose pcr_mask does not
	// include PCR 0, 1, and 7 (firmware, platform configuration,
	// Secure Boot policy). An agent that omits these bits would
	// bypass the BootBaselineStorer pin even when one is configured.
	RequireBootPCRs bool

	// if true, reject attestation reports that do not advertise the
	// initramfs PCR14 lock (FlagInitramfsLockV1). The lock is extended
	// by the 90lota dracut helper before pivot_root, so it closes the
	// kernel-handoff -> lota-agent window in which PCR14 is still
	// OS-writable from locality 0. A fleet that opts out (legacy host
	// without the dracut module) can keep attesting under the bare
	// FlagBootCommitmentV1 derivation, but the verifier no longer
	// authenticates the initramfs-stage pin for that report.
	RequireInitramfsLock bool

	// if true, refuse to TOFU-establish a per-client boot baseline
	// (PCR0/PCR1/PCR7) the first time a client reports. The baseline
	// must be authenticated through one of two enrollment paths:
	//   - the active (signed) policy explicitly pins PCR0/PCR1/PCR7,
	//     so the operator-approved firmware/Secure Boot values are
	//     compared against the report by the existing PCRVerifier;
	//   - the baseline store already holds a row for the client,
	//     i.e. the host has been enrolled out-of-band.
	// Without one of those, a first-attestation host that boots on
	// already-compromised firmware would silently pin the attacker's
	// PCR0/1/7 as the canonical baseline. The default (true) closes
	// that branch; legacy fleets that depend on pure TOFU first use
	// must set this to false explicitly.
	RequireBootEnrollment bool

	// RejectLegacyBaselines refuses any attestation whose
	// CheckAndUpdateAgentHash result is TOFULegacyBackfill. The
	// backfill branch fires once per client - when a baseline row
	// was pinned before FlagBootCommitment existed and the current
	// quote is the first to carry an agent_hash. An attacker that
	// swapped the agent binary on a legacy host across two
	// attestations would otherwise pin arbitrary bytes as the
	// canonical hash. Default false keeps existing pre-v1.0
	// fleets attestable; production deployments past their rollout
	// grace period should set it to true.
	RejectLegacyBaselines bool

	// MaxRestartCountSkew bounds how many TPM2_Startup(STATE) cycles
	// the verifier tolerates when matching the PCR14 boot-commitment
	// digest. The agent extends PCR14 once at startup with the
	// restartCount in effect at that moment; the quote's ClockInfo
	// reports the current restartCount, which advances on every
	// suspend/resume. Without a window any laptop that suspends
	// between attestations drops offline with integrity_mismatch.
	// 0 = exact match only.
	MaxRestartCountSkew uint32

	// if true, allow policies that define no measurement allowlists
	// (no PCR values and no kernel/agent hash allowlists)
	// This is insecure and should be enabled only explicitly!
	AllowPermissivePolicy bool
}

// returns sensible defaults for verifier
func DefaultConfig() VerifierConfig {
	return VerifierConfig{
		NonceLifetime:         5 * time.Minute,
		SessionTokenLife:      1 * time.Hour,
		AIKMaxAge:             30 * 24 * time.Hour, // 30 days
		RequireEventLog:       true,
		RequireCert:           true,
		RequireBootPCRs:       true,
		RequireInitramfsLock:  true,
		RequireBootEnrollment: true,
		MaxRestartCountSkew:   1024,
		AllowPermissivePolicy: false,
	}
}

// creates a new verification engine
func NewVerifier(cfg VerifierConfig, aikStore store.AIKStore) *Verifier {
	nonceCfg := DefaultNonceStoreConfig()
	nonceCfg.Lifetime = cfg.NonceLifetime
	nonceCfg.UsedBackend = cfg.UsedNonceBackend

	baselineStore := cfg.BaselineStore
	if baselineStore == nil {
		baselineStore = NewBaselineStore()
	}

	logger := cfg.Logger
	if logger == nil {
		logger = logging.Nop()
	}

	effectiveAIKMaxAge := cfg.AIKMaxAge
	if effectiveAIKMaxAge > 0 && !aikStoreSupportsCertVerification(aikStore) {
		logger.Warn("AIK rotation disabled: configured AIKMaxAge requires a certificate-verifying AIK store",
			"max_age", cfg.AIKMaxAge,
			"store_type", fmt.Sprintf("%T", aikStore),
			"hint", "set AIKMaxAge=0 (disable expiry), or use CertificateStore with trusted CA roots")
		effectiveAIKMaxAge = 0
	}

	m := cfg.Metrics
	if m == nil {
		m = metrics.New()
	}

	pcrVerifier := NewPCRVerifier()
	pcrVerifier.SetAllowPermissivePolicy(cfg.AllowPermissivePolicy)

	v := &Verifier{
		nonceStore:            NewNonceStoreFromConfig(nonceCfg),
		pcrVerifier:           pcrVerifier,
		aikStore:              aikStore,
		baselineStore:         baselineStore,
		revocationStore:       cfg.RevocationStore,
		banStore:              cfg.BanStore,
		log:                   logger,
		metrics:               m,
		attestationLog:        cfg.AttestationLog,
		nonceLifetime:         cfg.NonceLifetime,
		sessionTokenLife:      cfg.SessionTokenLife,
		aikMaxAge:             effectiveAIKMaxAge,
		requireEventLog:       cfg.RequireEventLog,
		requireCert:           cfg.RequireCert,
		requireBootPCRs:       cfg.RequireBootPCRs,
		requireInitramfsLock:  cfg.RequireInitramfsLock,
		requireBootEnrollment: cfg.RequireBootEnrollment,
		rejectLegacyBaselines: cfg.RejectLegacyBaselines,
		maxRestartCountSkew:   cfg.MaxRestartCountSkew,
		startTime:             time.Now(),
		tokenIndex:            make(map[[32]byte]sessionTokenRecord),
	}

	if _, err := rand.Read(v.sessionTokenKey[:]); err != nil {
		logger.Error("failed to initialize session token signing key", "error", err)
		v.sessionTokenKeyReady = false
	} else {
		v.sessionTokenKeyReady = true
	}

	return v
}

func (v *Verifier) rememberSessionToken(token [32]byte, report *types.AttestationReport, clientID string,
	validUntil uint64, resultCode uint32,
) {
	if v == nil || report == nil {
		return
	}

	now := unixTimestamp(time.Now())
	v.tokenMu.Lock()
	defer v.tokenMu.Unlock()

	for k, rec := range v.tokenIndex {
		if rec.ValidUntil > 0 && rec.ValidUntil <= now {
			delete(v.tokenIndex, k)
		}
	}

	v.tokenIndex[token] = sessionTokenRecord{
		ClientID:   clientID,
		HardwareID: report.TPM.HardwareID,
		ValidUntil: validUntil,
		ResultCode: resultCode,
		Flags:      report.Header.Flags,
		PCRMask:    report.TPM.PCRMask,
		Consumed:   false,
	}
}

func (v *Verifier) ValidateSessionToken(token [32]byte, consume bool) SessionTokenStatus {
	st := SessionTokenStatus{}
	if v == nil {
		return st
	}

	now := unixTimestamp(time.Now())

	v.tokenMu.Lock()
	defer v.tokenMu.Unlock()

	for k, rec := range v.tokenIndex {
		if rec.ValidUntil > 0 && rec.ValidUntil <= now {
			delete(v.tokenIndex, k)
		}
	}

	rec, ok := v.tokenIndex[token]
	if !ok {
		return st
	}

	st.Exists = true
	st.ClientID = rec.ClientID
	st.HardwareID = rec.HardwareID
	st.ValidUntil = rec.ValidUntil
	st.ResultCode = rec.ResultCode
	st.Flags = rec.Flags
	st.PCRMask = rec.PCRMask
	st.Consumed = rec.Consumed
	st.Expired = rec.ValidUntil > 0 && rec.ValidUntil <= now

	if st.Expired {
		delete(v.tokenIndex, token)
		st.Exists = false
		return st
	}

	if consume && !rec.Consumed {
		rec.Consumed = true
		v.tokenIndex[token] = rec
		st.Consumed = true
	}

	return st
}

func (v *Verifier) deriveSessionToken(report *types.AttestationReport, clientID string,
	validUntil uint64, resultCode uint32,
) ([32]byte, error) {
	var out [32]byte
	if v == nil || report == nil {
		return out, errors.New("nil verifier/report")
	}
	if !v.sessionTokenKeyReady {
		return out, errors.New("session token signing key unavailable")
	}

	mac := hmac.New(sha256.New, v.sessionTokenKey[:])
	writeU32 := func(x uint32) {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], x)
		_, _ = mac.Write(b[:])
	}
	writeU64 := func(x uint64) {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], x)
		_, _ = mac.Write(b[:])
	}

	_, _ = mac.Write([]byte(sessionTokenDomain))
	_, _ = mac.Write(report.TPM.HardwareID[:])
	_, _ = mac.Write(report.TPM.Nonce[:])
	_, _ = mac.Write([]byte(clientID))

	writeU64(validUntil)
	writeU32(resultCode)
	writeU32(report.Header.Flags)
	writeU32(report.TPM.PCRMask)
	writeU16 := func(x uint16) {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], x)
		_, _ = mac.Write(b[:])
	}
	writeU16(report.TPM.AttestSize)

	if report.TPM.AttestSize > 0 {
		att := report.TPM.AttestData[:report.TPM.AttestSize]
		sum := sha256.Sum256(att)
		_, _ = mac.Write(sum[:])
	}

	copy(out[:], mac.Sum(nil))
	return out, nil
}

func aikStoreSupportsCertVerification(aikStore store.AIKStore) bool {
	_, ok := aikStore.(store.AIKCertificateVerifier)
	return ok
}

// releases resources held by the Verifier, including the
// background cleanup goroutine in the nonce store
func (v *Verifier) Close() {
	v.nonceStore.Close()
}

// creates a challenge for client attestation
func (v *Verifier) GenerateChallenge(clientID string) (*types.Challenge, error) {
	pcrMask := v.pcrVerifier.GetActivePolicyMask()
	return v.nonceStore.GenerateChallenge(clientID, pcrMask)
}

// performs full verification of attestation report
// returns verification result ready to send back to client
//
// challengeID identifies the transport-level endpoint used when the
// challenge was generated. It is used exclusively for nonce binding
// verification. All persistent identity operations (AIK registration,
// baseline, revocation, bans) require a non-zero hardware-derived
// clientID (hex-encoded HardwareID from the TPM report) so that
// transport identity (e.g. NATed IP) is never used as durable identity.
func (v *Verifier) VerifyReport(challengeID string, reportData []byte) (_ *types.VerifyResult, retErr error) {
	reportBuf := cloneSensitive(reportData)
	defer wipeBytes(reportBuf)

	startTime := time.Now()
	v.totalAttests.Add(1)
	v.metrics.AttestationTotal.Inc()

	// clientID will be derived from HardwareID after parse; until then
	// use challengeID as provisional identity for early logging
	clientID := challengeID
	clog := logging.WithClient(v.log, clientID)
	var pcr14Hex string
	var hwID string

	result := &types.VerifyResult{
		Magic:   types.ReportMagic,
		Version: types.ReportVersion,
		Result:  types.VerifyInternalError,
	}

	defer func() {
		duration := time.Since(startTime)
		v.metrics.VerifyDuration.Observe(duration.Seconds())
		if retErr != nil {
			v.failedAttests.Add(1)
			v.metrics.AttestationFail.Inc()
		} else {
			v.successAttests.Add(1)
			v.metrics.AttestationOK.Inc()
		}
		if v.attestationLog != nil {
			resultStr := types.VerifyResultString(result.Result)
			if err := v.attestationLog.Record(store.AttestationRecord{
				Timestamp:  time.Now(),
				ClientID:   clientID,
				HardwareID: hwID,
				Result:     resultStr,
				DurationMs: float64(duration.Milliseconds()),
				PCR14:      pcr14Hex,
			}); err != nil {
				clog.Warn("failed to record attestation decision", "error", err)
			}
		}
	}()

	report, err := types.ParseReport(reportBuf)
	if err != nil {
		clog.Error("report parse failed", "error", err)
		result.Result = types.VerifyOldVersion
		return result, err
	}
	defer wipeReportSensitive(report)

	if err := validateTPMFieldSizes(report); err != nil {
		clog.Error("invalid TPM field sizes in report", "error", err)
		v.metrics.Rejections.Inc("sig_fail")
		result.Result = types.VerifySigFail
		return result, err
	}

	hwID = fmt.Sprintf("%x", report.TPM.HardwareID[:8])

	var zeroHWID [types.HardwareIDSize]byte
	if report.TPM.HardwareID == zeroHWID {
		logging.Security(clog, "attestation rejected: missing hardware identity",
			"detail", "zero hardware_id is not allowed", "challenge_id", challengeID)
		v.metrics.Rejections.Inc("sig_fail")
		result.Result = types.VerifySigFail
		return result, errors.New("hardware ID missing or zero")
	}

	clientID = hex.EncodeToString(report.TPM.HardwareID[:])
	clog = logging.WithClient(v.log, clientID)
	clog.Debug("client identity derived from hardware ID", "challenge_id", challengeID)

	// check revocation BEFORE consuming nonce
	// Why? This prevents wasting nonces on known-revoked clients
	// and avoids any crypto operations for identities that should be rejected.
	if v.revocationStore != nil {
		if entry, revoked := v.revocationStore.IsRevoked(clientID); revoked {
			v.revokedAttests.Add(1)
			v.metrics.Rejections.Inc("revoked")
			logging.Security(clog, "attestation rejected: AIK revoked",
				"reason", entry.Reason, "revoked_by", entry.RevokedBy, "note", entry.Note)
			result.Result = types.VerifyRevoked
			return result, fmt.Errorf("client AIK revoked: %s", entry.Reason)
		}
	}

	// check hardware ban BEFORE consuming nonce
	if v.banStore != nil {
		if entry, banned := v.banStore.IsBanned(report.TPM.HardwareID); banned {
			v.bannedAttests.Add(1)
			v.metrics.Rejections.Inc("banned")
			logging.Security(clog, "attestation rejected: hardware banned",
				"hardware_id", hwID, "reason", entry.Reason, "banned_by", entry.BannedBy)
			result.Result = types.VerifyBanned
			return result, fmt.Errorf("hardware banned: %s", entry.Reason)
		}
	}

	if err := v.nonceStore.VerifyNonce(report, challengeID); err != nil {
		clog.Error("nonce verification failed", "error", err)
		v.metrics.Rejections.Inc("nonce_fail")
		result.Result = types.VerifyNonceFail
		return result, err
	}
	clog.Debug("nonce verified", "method", "challenge-response+TPMS_ATTEST")

	storedAIK, err := v.aikStore.GetAIK(clientID)
	newClient := false
	if err != nil {
		if errors.Is(err, store.ErrAIKNotFound) {
			newClient = true
		} else {
			clog.Error("failed to query AIK store", "error", err)
			v.metrics.Rejections.Inc("sig_fail")
			result.Result = types.VerifySigFail
			return result, fmt.Errorf("AIK store query failed: %w", err)
		}
	}

	// check if registered AIK has exceeded its maximum age.
	// IMPORTANT: expiry is a policy hint; rotation MUST NOT be performed via TOFU
	// on an existing identity, otherwise an attacker can hijack the client
	aikExpired := false
	if !newClient && v.aikMaxAge > 0 {
		regTime, rerr := v.aikStore.GetRegisteredAt(clientID)
		if rerr != nil || regTime.IsZero() {
			aikExpired = true
			clog.Warn("AIK registration time unavailable; key rotation required",
				"error", rerr,
				"max_age", v.aikMaxAge)
		} else if time.Since(regTime) > v.aikMaxAge {
			aikExpired = true
			clog.Warn("AIK registration expired, key rotation required",
				"registered_at", regTime.UTC().Format(time.RFC3339),
				"max_age", v.aikMaxAge,
				"age", time.Since(regTime).Truncate(time.Second))
		}
	}

	// extract the AIK from the report (untrusted input)
	var reportAIK *rsa.PublicKey
	if report.TPM.AIKPublicSize > 0 {
		aikData := cloneSensitive(report.TPM.AIKPublic[:report.TPM.AIKPublicSize])
		defer wipeBytes(aikData)
		reportAIK, err = ParseRSAPublicKey(aikData)
		if err != nil {
			clog.Error("failed to parse AIK public key", "error", err)
			v.metrics.Rejections.Inc("sig_fail")
			result.Result = types.VerifySigFail
			return result, fmt.Errorf("failed to parse AIK: %w", err)
		}
	}

	if newClient {
		// first connection: TOFU registration (optionally certificate-backed).
		// signature that verifies against a key from the same report is NOT an identity proof,
		// but LOTA still require it to be internally consistent to reject corrupted reports.
		if reportAIK == nil {
			clog.Error("no AIK public key in report")
			v.metrics.Rejections.Inc("sig_fail")
			result.Result = types.VerifySigFail
			return result, errors.New("no AIK public key in report")
		}
		if err := VerifyReportSignature(report, reportAIK); err != nil {
			clog.Error("signature verification failed", "error", err)
			v.metrics.Rejections.Inc("sig_fail")
			result.Result = types.VerifySigFail
			return result, err
		}

		var aikCert, ekCert []byte
		if report.TPM.AIKCertSize > 0 {
			aikCert = cloneSensitive(report.TPM.AIKCertificate[:report.TPM.AIKCertSize])
			defer wipeBytes(aikCert)
			clog.Info("AIK certificate provided", "size", report.TPM.AIKCertSize)
		}
		if report.TPM.EKCertSize > 0 {
			ekCert = cloneSensitive(report.TPM.EKCertificate[:report.TPM.EKCertSize])
			defer wipeBytes(ekCert)
			clog.Info("EK certificate provided", "size", report.TPM.EKCertSize)
		}

		// enforce certificate-backed registration before touching persistent state
		if v.requireCert {
			if len(aikCert) == 0 || len(ekCert) == 0 {
				fingerprint := AIKFingerprint(reportAIK)
				logging.Security(clog, "TOFU rejected: certificate required by policy",
					"fingerprint", fingerprint,
					"has_aik_cert", len(aikCert) > 0,
					"has_ek_cert", len(ekCert) > 0)
				v.metrics.Rejections.Inc("sig_fail")
				result.Result = types.VerifySigFail
				return result, errors.New("AIK and EK certificates required by policy")
			}

			certVerifier, ok := v.aikStore.(store.AIKCertificateVerifier)
			if !ok {
				logging.Security(clog, "require-cert enabled but AIK store does not verify certificates",
					"store_type", fmt.Sprintf("%T", v.aikStore))
				v.metrics.Rejections.Inc("sig_fail")
				result.Result = types.VerifySigFail
				return result, errors.New("AIK certificate verification required but configured AIK store does not support certificate validation")
			}
			if err := certVerifier.VerifyCertificatesForAIK(reportAIK, aikCert, ekCert); err != nil {
				logging.Security(clog, "TOFU rejected: certificate verification failed", "error", err)
				v.metrics.Rejections.Inc("sig_fail")
				result.Result = types.VerifySigFail
				return result, err
			}
		}

		if len(ekCert) > 0 {
			if err := verifyHardwareIDMatchesEKCert(report, ekCert); err != nil {
				logging.Security(clog, "TOFU rejected: hardware_id does not match EK certificate", "error", err)
				v.metrics.Rejections.Inc("sig_fail")
				result.Result = types.VerifySigFail
				return result, err
			}
		}

		if err := v.aikStore.RegisterAIKWithCert(clientID, reportAIK, aikCert, ekCert); err != nil {
			if existing, gerr := v.aikStore.GetAIK(clientID); gerr == nil {
				fpExisting := store.Fingerprint(existing)
				fpReport := store.Fingerprint(reportAIK)
				if fpExisting != "" && fpExisting == fpReport {
					clog.Warn("TOFU registration raced; identical AIK already present")
				} else {
					clog.Error("failed to register AIK", "error", err)
					v.metrics.Rejections.Inc("sig_fail")
					result.Result = types.VerifySigFail
					return result, fmt.Errorf("AIK registration failed: %w", err)
				}
			} else {
				clog.Error("failed to register AIK", "error", err)
				v.metrics.Rejections.Inc("sig_fail")
				result.Result = types.VerifySigFail
				return result, fmt.Errorf("AIK registration failed: %w", err)
			}
		}

		fingerprint := AIKFingerprint(reportAIK)
		if len(aikCert) == 0 && len(ekCert) == 0 {
			clog.Warn("TOFU: AIK registered without certificate", "fingerprint", fingerprint)
		} else if aikStoreSupportsCertVerification(v.aikStore) {
			clog.Info("AIK registered with certificate verification", "fingerprint", fingerprint)
		} else {
			clog.Warn("AIK certificates provided but store does not verify certificates; TOFU fallback applied",
				"fingerprint", fingerprint, "store_type", fmt.Sprintf("%T", v.aikStore))
		}

		if err := v.aikStore.RegisterHardwareID(clientID, report.TPM.HardwareID); err != nil {
			if errors.Is(err, store.ErrHardwareIDMismatch) {
				logging.Security(clog, "hardware identity mismatch",
					"detail", "possible cloning or hardware change")
				v.metrics.Rejections.Inc("integrity_mismatch")
				result.Result = types.VerifySigFail
				return result, fmt.Errorf("hardware identity verification failed: %w", err)
			}
			clog.Error("failed to register hardware ID", "error", err)
			v.metrics.Rejections.Inc("sig_fail")
			result.Result = types.VerifySigFail
			return result, fmt.Errorf("hardware ID registration failed: %w", err)
		}
		clog.Info("hardware ID registered", "hwid", hwID)
	} else {
		// existing client: NEVER authenticate using a key extracted from the same untrusted report.
		if err := VerifyReportSignature(report, storedAIK); err != nil {
			if aikExpired {
				clog.Warn("signature failed with registered AIK on expired registration; attempting certificate-backed rotation", "error", err)

				if reportAIK == nil {
					v.metrics.Rejections.Inc("sig_fail")
					result.Result = types.VerifySigFail
					return result, errors.New("rotation attempt missing new AIK public key")
				}

				// continuity hint: agent should include the previous AIK public key during grace period
				if report.TPM.PrevAIKSize == 0 {
					v.metrics.Rejections.Inc("sig_fail")
					result.Result = types.VerifySigFail
					return result, errors.New("rotation attempt missing prev_aik_public")
				}
				prevAIKData := cloneSensitive(report.TPM.PrevAIKPublic[:report.TPM.PrevAIKSize])
				defer wipeBytes(prevAIKData)
				prevKey, perr := ParseRSAPublicKey(prevAIKData)
				if perr != nil {
					v.metrics.Rejections.Inc("sig_fail")
					result.Result = types.VerifySigFail
					return result, fmt.Errorf("failed to parse prev_aik_public: %w", perr)
				}
				if !sameRSAPublicKey(prevKey, storedAIK) {
					logging.Security(clog, "rotation continuity check failed",
						"detail", "prev_aik_public does not match registered AIK")
					v.metrics.Rejections.Inc("sig_fail")
					result.Result = types.VerifySigFail
					return result, errors.New("rotation continuity check failed")
				}

				// rotation is always certificate-backed (regardless of TOFU policy)
				certVerifier, ok := v.aikStore.(store.AIKCertificateVerifier)
				if !ok {
					logging.Security(clog, "rotation rejected: AIK store cannot verify certificates",
						"store_type", fmt.Sprintf("%T", v.aikStore))
					v.metrics.Rejections.Inc("sig_fail")
					result.Result = types.VerifySigFail
					return result, errors.New("AIK store does not support certificate-backed rotation")
				}

				if report.TPM.AIKCertSize == 0 || report.TPM.EKCertSize == 0 {
					v.metrics.Rejections.Inc("sig_fail")
					result.Result = types.VerifySigFail
					return result, errors.New("AIK rotation requires both AIK and EK certificates")
				}
				aikCert := cloneSensitive(report.TPM.AIKCertificate[:report.TPM.AIKCertSize])
				ekCert := cloneSensitive(report.TPM.EKCertificate[:report.TPM.EKCertSize])
				defer wipeBytes(aikCert)
				defer wipeBytes(ekCert)

				// reported hardware_id must be consistent with EK certificate
				if err := verifyHardwareIDMatchesEKCert(report, ekCert); err != nil {
					v.metrics.Rejections.Inc("sig_fail")
					result.Result = types.VerifySigFail
					logging.Security(clog, "rotation rejected: hardware_id does not match EK certificate", "error", err)
					return result, err
				}

				// verify cert chain and key match
				if verr := certVerifier.VerifyCertificatesForAIK(reportAIK, aikCert, ekCert); verr != nil {
					logging.Security(clog, "rotation rejected: certificate verification failed", "error", verr)
					v.metrics.Rejections.Inc("sig_fail")
					result.Result = types.VerifySigFail
					return result, verr
				}

				// verify the report signature with the NEW AIK (quote is signed by it)
				if serr := VerifyReportSignature(report, reportAIK); serr != nil {
					clog.Error("signature verification failed with new AIK", "error", serr)
					v.metrics.Rejections.Inc("sig_fail")
					result.Result = types.VerifySigFail
					return result, serr
				}

				if rerr := v.aikStore.RotateAIK(clientID, reportAIK); rerr != nil {
					clog.Error("failed to rotate AIK", "error", rerr)
					v.metrics.Rejections.Inc("sig_fail")
					result.Result = types.VerifySigFail
					return result, fmt.Errorf("AIK rotation failed: %w", rerr)
				}

				fingerprint := AIKFingerprint(reportAIK)
				logging.Security(clog, "AIK rotated after expiry (certificate-backed)",
					"fingerprint", fingerprint, "max_age", v.aikMaxAge, "generation", report.TPM.AIKGeneration)

				storedAIK = reportAIK
			} else {
				clog.Error("signature verification failed", "error", err)
				v.metrics.Rejections.Inc("sig_fail")
				result.Result = types.VerifySigFail
				return result, err
			}
		}
		clog.Debug("signature verified with registered AIK")

		if err := v.aikStore.RegisterHardwareID(clientID, report.TPM.HardwareID); err != nil {
			if errors.Is(err, store.ErrHardwareIDMismatch) {
				logging.Security(clog, "hardware identity mismatch",
					"detail", "possible cloning or hardware change")
				v.metrics.Rejections.Inc("integrity_mismatch")
				result.Result = types.VerifySigFail
				return result, fmt.Errorf("hardware identity verification failed: %w", err)
			}
			clog.Error("hardware ID verification failed", "error", err)
			v.metrics.Rejections.Inc("sig_fail")
			result.Result = types.VerifySigFail
			return result, fmt.Errorf("hardware ID verification failed: %w", err)
		}
	}

	// verify PCR digest binding: ensure reported PCR values match the
	// TPM-signed digest. The parsed TPMS_ATTEST is reused below by the
	// FlagBootCommitment branch so attestData walks the parser exactly
	// once per attestation; a malformed payload therefore cannot cost
	// two allocation passes and the DoS surface from twice-running the
	// parser collapses to one.
	var parsedAttest *TPMSAttest
	if report.TPM.AttestSize > 0 {
		attestData := cloneSensitive(report.TPM.AttestData[:report.TPM.AttestSize])
		defer wipeBytes(attestData)
		var err error
		parsedAttest, err = ParseTPMSAttest(attestData)
		if err != nil {
			clog.Error("PCR digest verification failed", "error", err)
			v.metrics.Rejections.Inc("pcr_fail")
			result.Result = types.VerifyPCRFail
			return result, fmt.Errorf("failed to parse TPMS_ATTEST: %w", err)
		}
		if err := VerifyPCRDigestParsed(parsedAttest, report.TPM.PCRValues, report.TPM.PCRMask); err != nil {
			clog.Error("PCR digest verification failed", "error", err)
			v.metrics.Rejections.Inc("pcr_fail")
			result.Result = types.VerifyPCRFail
			return result, fmt.Errorf("PCR digest binding failed: %w", err)
		}
		clog.Debug("PCR digest verified against TPM-signed attestation")
	}

	if err := v.pcrVerifier.VerifyReport(report); err != nil {
		clog.Error("PCR verification failed", "error", err)
		v.metrics.Rejections.Inc("pcr_fail")
		result.Result = types.VerifyPCRFail
		return result, err
	}

	// verify event log -> independent PCR reconstruction
	if len(report.EventLog) > 0 {
		if err := VerifyEventLog(report); err != nil {
			// present but inconsistent -> boot chain tampered
			clog.Error("event log verification failed", "error", err)
			v.metrics.Rejections.Inc("pcr_fail")
			result.Result = types.VerifyPCRFail
			return result, fmt.Errorf("event log inconsistency: %w", err)
		}
		clog.Debug("event log verified", "size", len(report.EventLog))
	} else {
		clog.Error("event log required but not provided")
		v.metrics.Rejections.Inc("pcr_fail")
		result.Result = types.VerifyPCRFail
		return result, errors.New("event log required but not provided")
	}

	// check agent self-measurement against baseline
	pcr14 := report.TPM.PCRValues[14]
	pcr14Hex = FormatPCR14(pcr14)

	useBootCommitment := report.Header.Flags&types.FlagBootCommitmentV1 != 0
	useInitramfsLock := report.Header.Flags&types.FlagInitramfsLockV1 != 0
	if useInitramfsLock && !useBootCommitment {
		logging.Security(clog, "initramfs-lock flag set without boot-commitment flag")
		v.metrics.Rejections.Inc("pcr_fail")
		result.Result = types.VerifyPCRFail
		return result, errors.New("FAIL_PCR_FAIL: FlagInitramfsLockV1 requires FlagBootCommitmentV1")
	}
	// The initramfs PCR14 lock pins PCR14 to a fixed
	// SHA256("LOTA-PCR14-INITRAMFS-LOCK-v1" || resetCount || restartCount)
	// before pivot_root. Without it, any code path that runs in
	// userspace before the agent's first PCR14 extend can poison the
	// boot-commitment baseline. The default production profile
	// rejects reports that do not advertise FlagInitramfsLockV1; a
	// fleet that explicitly opts out (see RequireInitramfsLock) keeps
	// attesting on the bare FlagBootCommitmentV1 derivation but
	// surfaces the gap to the operator.
	if v.requireInitramfsLock && !useInitramfsLock {
		logging.Security(clog, "report omits FlagInitramfsLockV1; initramfs PCR14 lock required",
			"flags", fmt.Sprintf("0x%08x", report.Header.Flags))
		v.metrics.Rejections.Inc("pcr_fail")
		result.Result = types.VerifyPCRFail
		return result, errors.New("FAIL_PCR_FAIL: report missing FlagInitramfsLockV1 (initramfs PCR14 lock required)")
	}

	// Mask gate: PCR0/PCR1/PCR7 (firmware + Secure Boot) are mandatory in
	// the default production configuration. Move this ahead of any
	// baseline write so a malformed report cannot persist a partial row.
	const bootPCRMask = (uint32(1) << 0) | (uint32(1) << 1) | (uint32(1) << 7)
	haveBootPCRs := report.TPM.PCRMask&bootPCRMask == bootPCRMask
	if v.requireBootPCRs && !haveBootPCRs {
		logging.Security(clog, "report omits firmware/SecureBoot PCRs from pcr_mask",
			"pcr_mask", fmt.Sprintf("0x%08x", report.TPM.PCRMask),
			"required_mask", fmt.Sprintf("0x%08x", bootPCRMask))
		v.metrics.Rejections.Inc("pcr_fail")
		result.Result = types.VerifyPCRFail
		return result, errors.New("FAIL_PCR_FAIL: report does not include firmware/SecureBoot PCRs in pcr_mask")
	}
	bootStore, bootStoreOK := v.baselineStore.(BootBaselineStorer)
	if v.requireBootPCRs && !bootStoreOK {
		clog.Error("baseline store does not support boot PCR pinning; refusing attestation")
		v.metrics.Rejections.Inc("baseline_error")
		result.Result = types.VerifyIntegrityMismatch
		return result, errors.New("FAIL_BASELINE_ERROR: store missing boot PCR support")
	}

	if useBootCommitment {
		// The agent_hash pin and the firmware/SecureBoot PCR pin must
		// commit atomically: splitting them across two store calls
		// opens a multi-process race where a second verifier instance
		// can observe the row mid-flight and TOFU-establish
		// attacker-controlled PCR0/1/7 between the two writes. The
		// AtomicBaselineStorer contract folds both decisions into one
		// SQL transaction (BEGIN IMMEDIATE on SQLite) so any
		// concurrent writer blocks until the first attestation
		// commits or rolls back.
		atomicStore, atomicOK := v.baselineStore.(AtomicBaselineStorer)
		if !atomicOK {
			clog.Error("baseline store does not implement AtomicBaselineStorer; refusing FlagBootCommitment attestation")
			v.metrics.Rejections.Inc("baseline_error")
			result.Result = types.VerifyIntegrityMismatch
			return result, errors.New("FAIL_BASELINE_ERROR: store missing atomic agent_hash/boot pinning")
		}

		// Reuse the TPMS_ATTEST already parsed for the PCR digest
		// binding above; FlagBootCommitment paths cannot run with
		// AttestSize=0, so parsedAttest must be non-nil here.
		if parsedAttest == nil {
			clog.Error("FlagBootCommitment set without a TPM quote payload")
			v.metrics.Rejections.Inc("pcr_fail")
			result.Result = types.VerifyPCRFail
			return result, errors.New("FAIL_PCR_FAIL: FlagBootCommitment requires a TPMS_ATTEST payload")
		}

		// Pick the derivation that matches the flag set on the
		// report. Hosts with the 90lota dracut module run the
		// initramfs lock helper (src/initramfs/lota-pcr14-lock.c)
		// before the agent ever starts, so PCR14 carries the
		// two-hop chain SHA256(lock_value || boot_commit) and the
		// report carries FlagInitramfsLockV1. Hosts without the
		// module emit FlagBootCommitment alone and fall through to
		// the single-hop derivation.
		var (
			expected     [types.HashSize]byte
			restartDrift uint32
			matched      bool
		)
		if useInitramfsLock {
			expected, restartDrift, matched = MatchLockedBootCommitmentPCR14(
				report.System.AgentHash,
				parsedAttest.ClockInfo.ResetCount,
				parsedAttest.ClockInfo.RestartCount,
				pcr14, v.maxRestartCountSkew)
		} else {
			expected, restartDrift, matched = MatchBootCommitmentPCR14(
				report.System.AgentHash,
				parsedAttest.ClockInfo.ResetCount,
				parsedAttest.ClockInfo.RestartCount,
				pcr14, v.maxRestartCountSkew)
		}
		if !matched {
			logging.Security(clog, "PCR14 boot-commitment derivation mismatch",
				"actual_pcr14", pcr14Hex,
				"expected_pcr14", FormatPCR14(expected),
				"reset_count", parsedAttest.ClockInfo.ResetCount,
				"restart_count", parsedAttest.ClockInfo.RestartCount,
				"max_restart_skew", v.maxRestartCountSkew,
				"initramfs_lock", useInitramfsLock)
			v.metrics.Rejections.Inc("integrity_mismatch")
			result.Result = types.VerifyIntegrityMismatch
			return result, errors.New("FAIL_INTEGRITY_MISMATCH: PCR14 does not match boot-commitment derivation")
		}
		if restartDrift > 0 {
			clog.Info("PCR14 boot-commitment matched within restart_count skew window",
				"restart_drift", restartDrift,
				"quote_restart_count", parsedAttest.ClockInfo.RestartCount,
				"max_restart_skew", v.maxRestartCountSkew,
				"initramfs_lock", useInitramfsLock)
		}

		var bootPtr *BootBaseline
		if haveBootPCRs && bootStoreOK {
			boot := BootBaseline{
				PCR0: report.TPM.PCRValues[0],
				PCR1: report.TPM.PCRValues[1],
				PCR7: report.TPM.PCRValues[7],
			}
			bootPtr = &boot
		}

		// Enrollment gate.
		//
		// The atomic transaction below will TOFU-establish the
		// per-client PCR0/PCR1/PCR7 row on first use. With pure
		// TOFU, a brand-new client that boots on already-tampered
		// firmware would silently pin the attacker-controlled
		// values as the canonical baseline; later attestations
		// would then "match" the poisoned baseline. Refuse that
		// branch when the operator has not authenticated the
		// initial PCR0/1/7 values through either:
		//   - the active signed policy (PCR0+PCR1+PCR7 hex
		//     entries that the existing PCRVerifier compares
		//     against the report), or
		//   - an out-of-band baseline row that is already
		//     present in the store for this client.
		// The check runs only when the verifier is about to write
		// boot columns (bootPtr non-nil) so PCR14-only legacy
		// flows are unaffected.
		if v.requireBootEnrollment && bootPtr != nil {
			reader, readerOK := v.baselineStore.(BootBaselineReader)
			enrolled := false
			if readerOK && reader.GetBootBaseline(clientID) != nil {
				enrolled = true
			}
			if !enrolled && !v.pcrVerifier.ActivePolicyDeclaresBootPCRs() {
				logging.Security(clog, "boot baseline not enrolled; refusing TOFU first-use",
					"active_policy", v.pcrVerifier.GetActivePolicy(),
					"hint", "load a signed policy that pins PCR0/PCR1/PCR7 for this fleet, or disable RequireBootEnrollment for legacy hosts")
				v.metrics.Rejections.Inc("baseline_error")
				result.Result = types.VerifyIntegrityMismatch
				return result, errors.New("FAIL_BASELINE_ERROR: boot baseline not enrolled (TOFU first-use refused under RequireBootEnrollment)")
			}
		}

		outcome := atomicStore.CheckAndUpdateAttestation(
			clientID, pcr14, report.System.AgentHash, bootPtr)

		switch outcome.AgentHashResult {
		case TOFUFirstUse:
			clog.Info("TOFU: agent_hash baseline established",
				"agent_hash", hex.EncodeToString(report.System.AgentHash[:]))
		case TOFULegacyBackfill:
			if v.rejectLegacyBaselines {
				logging.Security(clog, "rejected legacy baseline agent_hash backfill",
					"agent_hash", hex.EncodeToString(report.System.AgentHash[:]),
					"hint", "remove --reject-legacy-baselines or clear the stale baseline row to allow this client through")
				v.metrics.Rejections.Inc("integrity_mismatch")
				result.Result = types.VerifyIntegrityMismatch
				return result, errors.New("FAIL_INTEGRITY_MISMATCH: legacy baseline backfill refused by policy")
			}
			attestCount := uint64(0)
			if outcome.AgentHashBaseline != nil {
				attestCount = outcome.AgentHashBaseline.AttestCount
			}
			logging.Security(clog, "legacy baseline agent_hash backfilled",
				"agent_hash", hex.EncodeToString(report.System.AgentHash[:]),
				"attest_count", attestCount,
				"hint", "set RejectLegacyBaselines once the fleet rollout window has closed to refuse this branch")
		case TOFUMatch:
			if outcome.AgentHashBaseline != nil {
				clog.Debug("agent_hash matches baseline",
					"attest_count", outcome.AgentHashBaseline.AttestCount)
			}
		case TOFUMismatch:
			stored := report.System.AgentHash
			if outcome.AgentHashBaseline != nil {
				stored = outcome.AgentHashBaseline.AgentHash
			}
			logging.Security(clog, "agent_hash drift detected",
				"expected_agent_hash", hex.EncodeToString(stored[:]),
				"actual_agent_hash", hex.EncodeToString(report.System.AgentHash[:]))
			v.metrics.Rejections.Inc("integrity_mismatch")
			result.Result = types.VerifyIntegrityMismatch
			return result, errors.New("FAIL_INTEGRITY_MISMATCH: agent_hash changed from baseline")
		case TOFUError:
			clog.Error("agent_hash baseline store error, refusing attestation")
			v.metrics.Rejections.Inc("baseline_error")
			result.Result = types.VerifyIntegrityMismatch
			return result, errors.New("FAIL_BASELINE_ERROR: agent_hash baseline store unavailable")
		}

		if outcome.BootProvided {
			switch outcome.BootResult {
			case TOFUFirstUse:
				clog.Info("TOFU: firmware/SecureBoot PCRs baseline established",
					"pcr0", hex.EncodeToString(bootPtr.PCR0[:]),
					"pcr1", hex.EncodeToString(bootPtr.PCR1[:]),
					"pcr7", hex.EncodeToString(bootPtr.PCR7[:]))
			case TOFUMatch:
				clog.Debug("boot PCRs match baseline")
			case TOFUMismatch:
				exp0, exp1, exp7 := bootPtr.PCR0, bootPtr.PCR1, bootPtr.PCR7
				if outcome.BootBaseline != nil {
					exp0, exp1, exp7 = outcome.BootBaseline.PCR0,
						outcome.BootBaseline.PCR1, outcome.BootBaseline.PCR7
				}
				logging.Security(clog, "firmware/SecureBoot PCR drift detected",
					"actual_pcr0", hex.EncodeToString(bootPtr.PCR0[:]),
					"actual_pcr1", hex.EncodeToString(bootPtr.PCR1[:]),
					"actual_pcr7", hex.EncodeToString(bootPtr.PCR7[:]),
					"expected_pcr0", hex.EncodeToString(exp0[:]),
					"expected_pcr1", hex.EncodeToString(exp1[:]),
					"expected_pcr7", hex.EncodeToString(exp7[:]))
				v.metrics.Rejections.Inc("integrity_mismatch")
				result.Result = types.VerifyIntegrityMismatch
				return result, fmt.Errorf("FAIL_INTEGRITY_MISMATCH: firmware/SecureBoot PCRs changed from baseline")
			case TOFUError:
				clog.Error("boot baseline store error, refusing attestation")
				v.metrics.Rejections.Inc("baseline_error")
				result.Result = types.VerifyIntegrityMismatch
				return result, fmt.Errorf("FAIL_BASELINE_ERROR: boot baseline store unavailable")
			}
		}
	} else {
		// Legacy non-FlagBootCommitment path: PCR14 TOFU plus, when the
		// store supports it, a separate boot baseline pin. The two
		// writes are not atomic across processes here, but legacy
		// clients are being phased out under --reject-legacy-baselines
		// once the rollout window closes; production fleets pass through
		// the atomic branch above.
		tofuResult, baseline := v.baselineStore.CheckAndUpdate(clientID, pcr14)
		switch tofuResult {
		case TOFUFirstUse:
			clog.Info("TOFU: PCR14 baseline established", "pcr14", pcr14Hex)
		case TOFUMatch:
			clog.Debug("PCR14 matches baseline", "attest_count", baseline.AttestCount)
		case TOFUMismatch:
			logging.Security(clog, "potential agent tampering detected",
				"expected_pcr14", FormatPCR14(baseline.PCR14), "actual_pcr14", pcr14Hex)
			v.metrics.Rejections.Inc("integrity_mismatch")
			result.Result = types.VerifyIntegrityMismatch
			return result, fmt.Errorf("FAIL_INTEGRITY_MISMATCH: PCR14 changed from baseline")
		case TOFUError:
			clog.Error("baseline store error, refusing attestation")
			v.metrics.Rejections.Inc("baseline_error")
			result.Result = types.VerifyIntegrityMismatch
			return result, fmt.Errorf("FAIL_BASELINE_ERROR: baseline store unavailable")
		}

		if bootStoreOK && haveBootPCRs {
			boot := BootBaseline{
				PCR0: report.TPM.PCRValues[0],
				PCR1: report.TPM.PCRValues[1],
				PCR7: report.TPM.PCRValues[7],
			}
			bootResult, bootBaseline := bootStore.CheckAndUpdateBootPCRs(clientID, boot)
			switch bootResult {
			case TOFUFirstUse:
				clog.Info("TOFU: firmware/SecureBoot PCRs baseline established",
					"pcr0", hex.EncodeToString(boot.PCR0[:]),
					"pcr1", hex.EncodeToString(boot.PCR1[:]),
					"pcr7", hex.EncodeToString(boot.PCR7[:]))
			case TOFUMatch:
				clog.Debug("boot PCRs match baseline")
			case TOFUMismatch:
				exp0, exp1, exp7 := boot.PCR0, boot.PCR1, boot.PCR7
				if bootBaseline != nil {
					exp0, exp1, exp7 = bootBaseline.PCR0,
						bootBaseline.PCR1, bootBaseline.PCR7
				}
				logging.Security(clog, "firmware/SecureBoot PCR drift detected",
					"actual_pcr0", hex.EncodeToString(boot.PCR0[:]),
					"actual_pcr1", hex.EncodeToString(boot.PCR1[:]),
					"actual_pcr7", hex.EncodeToString(boot.PCR7[:]),
					"expected_pcr0", hex.EncodeToString(exp0[:]),
					"expected_pcr1", hex.EncodeToString(exp1[:]),
					"expected_pcr7", hex.EncodeToString(exp7[:]))
				v.metrics.Rejections.Inc("integrity_mismatch")
				result.Result = types.VerifyIntegrityMismatch
				return result, fmt.Errorf("FAIL_INTEGRITY_MISMATCH: firmware/SecureBoot PCRs changed from baseline")
			case TOFUError:
				clog.Error("boot baseline store error, refusing attestation")
				v.metrics.Rejections.Inc("baseline_error")
				result.Result = types.VerifyIntegrityMismatch
				return result, fmt.Errorf("FAIL_BASELINE_ERROR: boot baseline store unavailable")
			}
		}
	}

	if report.Header.Flags&types.FlagIOMMUOK == 0 {
		clog.Warn("IOMMU not verified")
		// IMPORTANT: policy determines if this is required
	}

	secFlags := []string{}
	if report.Header.Flags&types.FlagModuleSig != 0 {
		secFlags = append(secFlags, "MODULE_SIG")
	}
	if report.Header.Flags&types.FlagLockdown != 0 {
		secFlags = append(secFlags, "LOCKDOWN")
	}
	if report.Header.Flags&types.FlagSecureBoot != 0 {
		secFlags = append(secFlags, "SECUREBOOT")
	}
	if len(secFlags) > 0 {
		clog.Info("security features detected", "flags", secFlags)
	} else {
		clog.Warn("no module security features detected")
	}

	clog.Info("verification successful")

	result.Result = types.VerifyOK
	result.ValidUntil = unixTimestamp(time.Now().Add(v.sessionTokenLife))
	sessionToken, err := v.deriveSessionToken(report, clientID, result.ValidUntil, result.Result)
	if err != nil {
		result.Result = types.VerifyInternalError
		return result, fmt.Errorf("failed to derive session token: %w", err)
	}
	result.SessionToken = sessionToken
	v.rememberSessionToken(sessionToken, report, clientID, result.ValidUntil, result.Result)

	return result, nil
}

// loads a PCR policy file
func (v *Verifier) LoadPolicy(path string) error {
	return v.pcrVerifier.LoadPolicy(path)
}

// adds a policy programmatically
func (v *Verifier) AddPolicy(policy *PCRPolicy) error {
	return v.pcrVerifier.AddPolicy(policy)
}

// sets the Ed25519 public key used to verify policy file signatures
// when set, LoadPolicy rejects any policy without a valid detached .sig file!
func (v *Verifier) SetPolicyPublicKey(pubKey ed25519.PublicKey) {
	v.pcrVerifier.SetPolicyPublicKey(pubKey)
}

// sets which policy to use
func (v *Verifier) SetActivePolicy(name string) error {
	return v.pcrVerifier.SetActivePolicy(name)
}

// returns the currently active PCR policy
// returned pointer must be treated as read-only by callers
func (v *Verifier) ActivePolicyConfig() (*PCRPolicy, bool) {
	return v.pcrVerifier.GetActivePolicyConfig()
}

// returns verifier statistics
type Stats struct {
	PendingChallenges int
	UsedNonces        int
	ActivePolicy      string
	LoadedPolicies    []string
	RegisteredClients int
	TotalAttestations int64
	SuccessAttests    int64
	FailedAttests     int64
	RevokedAttests    int64
	BannedAttests     int64
	ActiveRevocations int
	ActiveBans        int
	Uptime            time.Duration
}

func (v *Verifier) Stats() Stats {
	s := Stats{
		PendingChallenges: v.nonceStore.PendingCount(),
		UsedNonces:        v.nonceStore.UsedCount(),
		ActivePolicy:      v.pcrVerifier.GetActivePolicy(),
		LoadedPolicies:    v.pcrVerifier.ListPolicies(),
		RegisteredClients: len(v.aikStore.ListClients()),
		TotalAttestations: v.totalAttests.Load(),
		SuccessAttests:    v.successAttests.Load(),
		FailedAttests:     v.failedAttests.Load(),
		RevokedAttests:    v.revokedAttests.Load(),
		BannedAttests:     v.bannedAttests.Load(),
		Uptime:            time.Since(v.startTime),
	}

	if v.revocationStore != nil {
		s.ActiveRevocations = len(v.revocationStore.ListRevocations())
	}
	if v.banStore != nil {
		s.ActiveBans = len(v.banStore.ListBans())
	}

	return s
}

// per-client information for monitoring API
type ClientInfo struct {
	ClientID          string
	HasAIK            bool
	HardwareID        string // hex-encoded
	Revoked           bool
	RevocationReason  string
	LastAttestation   time.Time
	AttestCount       uint64
	MonotonicCounter  uint64
	PendingChallenges int
	PCR14Baseline     string // hex-encoded
	FirstSeen         time.Time
}

// returns aggregated information about a specific client
func (v *Verifier) ClientInfo(clientID string) (*ClientInfo, bool) {
	info := &ClientInfo{
		ClientID: clientID,
	}

	// check AIK store
	_, err := v.aikStore.GetAIK(clientID)
	info.HasAIK = err == nil

	// hardware ID
	if hwid, err := v.aikStore.GetHardwareID(clientID); err == nil {
		info.HardwareID = hex.EncodeToString(hwid[:])
	}

	// revocation status
	if v.revocationStore != nil {
		if entry, revoked := v.revocationStore.IsRevoked(clientID); revoked {
			info.Revoked = true
			info.RevocationReason = string(entry.Reason)
		}
	}

	// nonce store data
	info.MonotonicCounter = v.nonceStore.ClientCounter(clientID)
	info.PendingChallenges = v.nonceStore.ClientPendingCount(clientID)
	info.LastAttestation = v.nonceStore.ClientLastAttestation(clientID)

	// baseline store data
	if baseline := v.baselineStore.GetBaseline(clientID); baseline != nil {
		info.PCR14Baseline = hex.EncodeToString(baseline.PCR14[:])
		info.AttestCount = baseline.AttestCount
		info.FirstSeen = baseline.FirstSeen
	}

	// check if client exists in any store
	if !info.HasAIK && info.MonotonicCounter == 0 {
		return nil, false
	}

	return info, true
}

// returns all known client IDs as a union of AIK store and nonce store
func (v *Verifier) ListClients() []string {
	seen := make(map[string]struct{})
	var clients []string

	for _, id := range v.aikStore.ListClients() {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			clients = append(clients, id)
		}
	}

	for _, id := range v.nonceStore.ListActiveClients() {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			clients = append(clients, id)
		}
	}

	return clients
}

// returns the configured revocation store
func (v *Verifier) RevocationStore() store.RevocationStore {
	return v.revocationStore
}

// returns the configured hardware ban store
func (v *Verifier) BanStore() store.BanStore {
	return v.banStore
}

// returns the configured AIK store implementation
func (v *Verifier) AIKStore() store.AIKStore {
	return v.aikStore
}

// returns client IDs currently present in the nonce store
func (v *Verifier) ListActiveClients() []string {
	return v.nonceStore.ListActiveClients()
}
