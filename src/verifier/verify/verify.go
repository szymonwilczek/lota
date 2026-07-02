// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
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
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
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

func unixTimestamp(t time.Time) uint64 {
	ts := t.Unix()
	if ts < 0 {
		return 0
	}
	return uint64(ts)
}

// decodeDevicePseudonym parses the CA-assigned device identifier from an
// AIK certificate subject. The CA encodes it as the hex of a 32-byte
// keyed hash of the EK, so it decodes to a fixed-width identity that the
// ban store and session token reuse in place of the former hardware_id.
func decodeDevicePseudonym(cn string) ([types.HardwareIDSize]byte, error) {
	var out [types.HardwareIDSize]byte
	if len(cn) != hex.EncodedLen(types.HardwareIDSize) {
		return out, fmt.Errorf("expected %d hex chars, got %d",
			hex.EncodedLen(types.HardwareIDSize), len(cn))
	}
	decoded, err := hex.DecodeString(cn)
	if err != nil {
		return out, fmt.Errorf("device identity is not hex: %w", err)
	}
	copy(out[:], decoded)
	return out, nil
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

	// stateless session-token signer key (process-local secret)
	sessionTokenKey      [32]byte
	sessionTokenKeyReady bool

	// store for issued session tokens; in-memory by default (single node),
	// Postgres for multi-instance validation behind a load balancer
	sessionTokenStore SessionTokenStore

	// monitoring
	startTime      time.Time
	totalAttests   atomic.Int64
	successAttests atomic.Int64
	failedAttests  atomic.Int64
	revokedAttests atomic.Int64
	bannedAttests  atomic.Int64

	// policy enforcement
	requireEventLog       bool
	requireBootPCRs       bool
	requireInitramfsLock  bool
	requireBootEnrollment bool
	rejectLegacyBaselines bool
	selfServiceReanchor   bool
	maxRestartCountSkew   uint32
}

type sessionTokenRecord struct {
	ClientID   string
	Tenant     string
	HardwareID [types.HardwareIDSize]byte
	ValidUntil uint64
	ResultCode uint32
	Flags      uint32
	PCRMask    uint32
	Consumed   bool
}

type SessionTokenStatus struct {
	ClientID   string
	Tenant     string
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

	// optional: persistent baseline store (nil = in-memory)
	BaselineStore BaselineStorer

	// optional: persistent used nonce backend (nil = in-memory)
	UsedNonceBackend UsedNonceBackend

	// optional: shared session-token store (nil = in-memory, single node).
	// Postgres-backed store lets several instances behind a load balancer
	// validate each other's tokens.
	SessionTokenStore SessionTokenStore

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

	// EnableSelfServiceReanchor turns on self-service re-anchor:
	// on a firmware/Secure Boot PCR drift the verifier may re-pin the
	// per-device boot baseline itself when the drift preserves the Secure Boot
	// root of trust (see reanchorDecision), instead of rejecting until
	// operator clears the row.
	// Only takes effect for the diverse-fleet profile (a policy with require_secureboot);
	// off by default and intended to stay off for the enterprise profile,
	// which treats drift as a feature.
	EnableSelfServiceReanchor bool

	// MaxRestartCountSkew bounds how many TPM2_Startup(STATE) cycles
	// the verifier tolerates when matching the PCR14 boot-commitment
	// digest. The agent extends PCR14 once at startup with the
	// restartCount in effect at that moment; the quote's ClockInfo
	// reports the current restartCount, which advances on every
	// suspend/resume. Without a window any laptop that suspends
	// between attestations drops offline with integrity_mismatch.
	// 0 = exact match only.
	//
	// The default of 64 covers around sixty suspend/resume cycles
	// between two attestations - well past any realistic operator
	// cadence on a laptop fleet (continuous attestation at a few-
	// minute interval, or operator-driven probes after a workstation
	// returns from sleep). Keeping the window narrow shrinks the
	// brute-force surface the matcher exposes to a caller that
	// controls PCR14 contents but not the agent_hash baseline: every
	// additional unit of skew is one extra SHA-256 candidate the
	// matcher tries before giving up.
	MaxRestartCountSkew uint32

	// if true, allow policies that define no measurement allowlists
	// (no PCR values and no kernel/agent hash allowlists)
	// This is insecure and should be enabled only explicitly!
	AllowPermissivePolicy bool

	// if true, allow a diverse-fleet policy (require_secureboot, no raw PCR
	// pins) that does not pin agent_hashes.
	// INSECURE: agent self-hash is then TOFU, so a modified non-enforcing
	// agent can pin its own hash!
	AllowUnpinnedAgent bool
}

// returns sensible defaults for verifier
func DefaultConfig() VerifierConfig {
	return VerifierConfig{
		NonceLifetime:         5 * time.Minute,
		SessionTokenLife:      1 * time.Hour,
		RequireEventLog:       true,
		RequireBootPCRs:       true,
		RequireInitramfsLock:  true,
		RequireBootEnrollment: true,
		MaxRestartCountSkew:   64,
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

	m := cfg.Metrics
	if m == nil {
		m = metrics.New()
	}

	pcrVerifier := NewPCRVerifier()
	pcrVerifier.SetAllowPermissivePolicy(cfg.AllowPermissivePolicy)
	pcrVerifier.SetAllowUnpinnedAgent(cfg.AllowUnpinnedAgent)

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
		requireEventLog:       cfg.RequireEventLog,
		requireBootPCRs:       cfg.RequireBootPCRs,
		requireInitramfsLock:  cfg.RequireInitramfsLock,
		requireBootEnrollment: cfg.RequireBootEnrollment,
		rejectLegacyBaselines: cfg.RejectLegacyBaselines,
		selfServiceReanchor:   cfg.EnableSelfServiceReanchor,
		maxRestartCountSkew:   cfg.MaxRestartCountSkew,
		startTime:             time.Now(),
		sessionTokenStore:     cfg.SessionTokenStore,
	}

	// default to the in-memory store (single node) when none is configured
	if v.sessionTokenStore == nil {
		v.sessionTokenStore = newMemorySessionTokenStore()
	}

	if _, err := rand.Read(v.sessionTokenKey[:]); err != nil {
		logger.Error("failed to initialize session token signing key", "error", err)
		v.sessionTokenKeyReady = false
	} else {
		v.sessionTokenKeyReady = true
	}

	return v
}

func (v *Verifier) rememberSessionToken(token [32]byte, report *types.AttestationReport, clientID, tenant string,
	identity [types.HardwareIDSize]byte, validUntil uint64, resultCode uint32,
) {
	if v == nil || report == nil {
		return
	}

	v.sessionTokenStore.Remember(token, sessionTokenRecord{
		ClientID:   clientID,
		Tenant:     tenant,
		HardwareID: identity,
		ValidUntil: validUntil,
		ResultCode: resultCode,
		Flags:      report.Header.Flags,
		PCRMask:    report.TPM.PCRMask,
		Consumed:   false,
	})
}

func (v *Verifier) ValidateSessionToken(token [32]byte, consume bool) SessionTokenStatus {
	if v == nil {
		return SessionTokenStatus{}
	}
	return v.sessionTokenStore.Validate(token, consume, unixTimestamp(time.Now()))
}

func (v *Verifier) deriveSessionToken(report *types.AttestationReport, clientID string,
	identity [types.HardwareIDSize]byte, validUntil uint64, resultCode uint32,
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
	_, _ = mac.Write(identity[:])
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

// releases resources held by the Verifier, including the
// background cleanup goroutine in the nonce store
func (v *Verifier) Close() {
	v.nonceStore.Close()
}

// creates a challenge for client attestation
func (v *Verifier) GenerateChallenge(clientID string) (*types.Challenge, error) {
	// challenges precede tenant authentication, so request the union
	// of every selectable policy's PCRs
	pcrMask := v.pcrVerifier.GetChallengePolicyMask()
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
	// tenant stays empty until the AIK certificate authenticates it.
	// attestation record without a tenant is one that never proved
	// tenant-assigned identity
	var tenant string

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
				Tenant:     tenant,
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

	// Authenticate the AIK through its CA-issued certificate. The
	// certificate chain is the only AIK trust anchor: the attestation CA
	// issues it only after credential activation proves the AIK and the
	// endorsement key share one TPM, so a software-only client that never
	// passed activation cannot present a chaining certificate. The durable
	// client identity is the CA-assigned device pseudonym in the subject,
	// not the agent-asserted hardware_id; the verifier never sees the EK.
	if report.TPM.AIKPublicSize == 0 {
		clog.Error("no AIK public key in report")
		v.metrics.Rejections.Inc("sig_fail")
		result.Result = types.VerifySigFail
		return result, errors.New("no AIK public key in report")
	}
	aikData := cloneSensitive(report.TPM.AIKPublic[:report.TPM.AIKPublicSize])
	defer wipeBytes(aikData)
	reportAIK, err := ParseRSAPublicKey(aikData)
	if err != nil {
		clog.Error("failed to parse AIK public key", "error", err)
		v.metrics.Rejections.Inc("sig_fail")
		result.Result = types.VerifySigFail
		return result, fmt.Errorf("failed to parse AIK: %w", err)
	}

	certVerifier, ok := v.aikStore.(store.AIKCertVerifier)
	if !ok {
		logging.Security(clog, "AIK store cannot verify certificates; refusing attestation",
			"store_type", fmt.Sprintf("%T", v.aikStore))
		v.metrics.Rejections.Inc("sig_fail")
		result.Result = types.VerifySigFail
		return result, errors.New("configured AIK store does not support AIK certificate verification")
	}
	if report.TPM.AIKCertSize == 0 {
		logging.Security(clog, "attestation rejected: AIK certificate required",
			"challenge_id", challengeID)
		v.metrics.Rejections.Inc("sig_fail")
		result.Result = types.VerifySigFail
		return result, errors.New("AIK certificate required")
	}
	aikCert := cloneSensitive(report.TPM.AIKCertificate[:report.TPM.AIKCertSize])
	defer wipeBytes(aikCert)
	aikLeaf, err := certVerifier.VerifyAIKCertificate(reportAIK, aikCert)
	if err != nil {
		logging.Security(clog, "AIK certificate verification failed", "error", err)
		v.metrics.Rejections.Inc("sig_fail")
		result.Result = types.VerifySigFail
		return result, fmt.Errorf("AIK certificate verification failed: %w", err)
	}

	identity, err := decodeDevicePseudonym(aikLeaf.Subject.CommonName)
	if err != nil {
		logging.Security(clog, "AIK certificate carries an invalid device identity",
			"subject", aikLeaf.Subject.CommonName, "error", err)
		v.metrics.Rejections.Inc("sig_fail")
		result.Result = types.VerifySigFail
		return result, fmt.Errorf("invalid device identity in AIK certificate: %w", err)
	}
	tenant, err = TenantFromCertificate(aikLeaf)
	if err != nil {
		logging.Security(clog, "AIK certificate carries an invalid tenant",
			"subject", aikLeaf.Subject.CommonName, "error", err)
		v.metrics.Rejections.Inc("sig_fail")
		result.Result = types.VerifySigFail
		return result, fmt.Errorf("invalid tenant in AIK certificate: %w", err)
	}
	clientID = aikLeaf.Subject.CommonName
	hwID = clientID
	if len(hwID) > 16 {
		hwID = hwID[:16]
	}
	clog = logging.WithClient(v.log, clientID).With("tenant", tenant)
	clog.Debug("client identity derived from AIK certificate", "challenge_id", challengeID)

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
	//
	// Bans are strictly per-tenant:
	// Only a ban recorded in the tenant the CA assigned to this client rejects it.
	// The same hardware stays clean in every other tenant.
	if v.banStore != nil {
		if entry, banned := v.banStore.IsBanned(tenant, identity); banned {
			v.bannedAttests.Add(1)
			v.metrics.Rejections.Inc("banned")
			logging.Security(clog, "attestation rejected: hardware banned",
				"hardware_id", hwID, "reason", entry.Reason, "banned_by", entry.BannedBy)
			result.Result = types.VerifyBanned
			return result, fmt.Errorf("hardware banned: %s", entry.Reason)
		}
	}

	if err := v.nonceStore.VerifyNonce(report, challengeID, clientID); err != nil {
		clog.Error("nonce verification failed", "error", err)
		v.metrics.Rejections.Inc("nonce_fail")
		result.Result = types.VerifyNonceFail
		return result, err
	}
	clog.Debug("nonce verified", "method", "challenge-response+TPMS_ATTEST")

	// The AIK certificate authenticated the AIK above; the quote is
	// signed by that key.
	if err := VerifyReportSignature(report, reportAIK); err != nil {
		clog.Error("signature verification failed", "error", err)
		v.metrics.Rejections.Inc("sig_fail")
		result.Result = types.VerifySigFail
		return result, err
	}
	clog.Debug("signature verified with certificate-authenticated AIK")

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
		if err := VerifyPCRDigestParsed(parsedAttest, &report.TPM.PCRValues, report.TPM.PCRMask); err != nil {
			clog.Error("PCR digest verification failed", "error", err)
			v.metrics.Rejections.Inc("pcr_fail")
			result.Result = types.VerifyPCRFail
			return result, fmt.Errorf("PCR digest binding failed: %w", err)
		}
		clog.Debug("PCR digest verified against TPM-signed attestation")
	}

	// verify event log -> independent PCR reconstruction + boot facts.
	// Runs before the policy gates because RequireSecureBoot and the
	// cmdline policy consume the quote-authenticated facts extracted
	// here. PCR 8 consistency is enforced whenever the active policy
	// gates on the measured cmdline; otherwise a forged kernel_cmdline
	// event would go undetected.
	var bootFacts *BootFacts
	if len(report.EventLog) > 0 {
		facts, err := VerifyEventLogWithPolicy(report, v.pcrVerifier.PolicyRequiresCmdlineForTenant(tenant))
		if err != nil {
			// present but inconsistent -> boot chain tampered
			clog.Error("event log verification failed", "error", err)
			v.metrics.Rejections.Inc("pcr_fail")
			result.Result = types.VerifyPCRFail
			return result, fmt.Errorf("event log inconsistency: %w", err)
		}
		bootFacts = facts
		clog.Debug("event log verified", "size", len(report.EventLog))
	} else {
		clog.Error("event log required but not provided")
		v.metrics.Rejections.Inc("pcr_fail")
		result.Result = types.VerifyPCRFail
		return result, errors.New("event log required but not provided")
	}

	if err := v.pcrVerifier.VerifyReportForTenant(report, tenant, bootFacts); err != nil {
		clog.Error("PCR verification failed", "error", err)
		v.metrics.Rejections.Inc("pcr_fail")
		result.Result = types.VerifyPCRFail
		return result, err
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
	// SHA256("LOTA-PCR14-INITRAMFS-LOCK-v1") value before pivot_root.
	// Without it, any code path that runs in userspace before the
	// agent's first PCR14 extend can poison the boot-commitment
	// baseline. The default production profile rejects reports that do
	// not advertise FlagInitramfsLockV1; a fleet that explicitly opts
	// out (see RequireInitramfsLock) keeps attesting on the bare
	// FlagBootCommitmentV1 derivation but surfaces the gap to the
	// operator.
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
		// pcr14Baseline is the PCR14 content present before the
		// initramfs lock / agent extends: 0^32 on a legacy/BIOS host,
		// or the firmware/shim MOK measurement on UEFI Secure Boot,
		// reconstructed by replaying the firmware event log (the LOTA
		// extends are post-ExitBootServices and never enter that log).
		// Forged log diverges from the signed PCR14 and fails the
		// match below, so baseline doesnt need separate pin here
		var pcr14Baseline [types.HashSize]byte
		if bootFacts != nil {
			pcr14Baseline = PCR14BaselineFromEventLog(bootFacts.Parsed)
		}
		if useInitramfsLock {
			expected, restartDrift, matched = MatchLockedBootCommitmentPCR14(
				pcr14Baseline,
				report.System.AgentHash,
				parsedAttest.ClockInfo.ResetCount,
				parsedAttest.ClockInfo.RestartCount,
				pcr14, v.maxRestartCountSkew)
		} else {
			expected, restartDrift, matched = MatchBootCommitmentPCR14(
				pcr14Baseline,
				report.System.AgentHash,
				parsedAttest.ClockInfo.ResetCount,
				parsedAttest.ClockInfo.RestartCount,
				pcr14, v.maxRestartCountSkew)
		}
		if !matched {
			hint := "verify that the quoted agent binary is the one that extended PCR14"
			if useInitramfsLock {
				hint = "rebuild initramfs with the current lota-pcr14-lock helper, cold reboot, and run the same agent binary that extended PCR14"
			}
			logging.Security(clog, "PCR14 boot-commitment derivation mismatch",
				"actual_pcr14", pcr14Hex,
				"expected_pcr14", FormatPCR14(expected),
				"reset_count", parsedAttest.ClockInfo.ResetCount,
				"restart_count", parsedAttest.ClockInfo.RestartCount,
				"max_restart_skew", v.maxRestartCountSkew,
				"initramfs_lock", useInitramfsLock,
				"hint", hint)
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
		// initial PCR0/1/7 values through one of:
		//   - the active signed policy (PCR0+PCR1+PCR7 hex
		//     entries that the existing PCRVerifier compares
		//     against the report),
		//   - an out-of-band baseline row that is already
		//     present in the store for this client, or
		//   - the event-log Secure Boot anchor: the active policy
		//     enforces RequireSecureBoot and this report's
		//     quote-authenticated event log proves Secure Boot
		//     enabled
		//     Policy gate above already rejected the report otherwise;
		//     re-derived from bootFacts so this branch cannot silently
		//     widen if the gates move).
		//     Raw PCR0/1/7 differ per machine, so a diverse fleet
		//     cannot pin them in policy; with the firmware
		//     boot-with-Secure-Boot-off path already rejected
		//     machine-independently, the TOFU row serves as a
		//     per-device rollback/consistency anchor rather than
		//     the firmware trust control itself.
		// Check runs only when the verifier is about to write
		// boot columns (bootPtr non-nil) so PCR14-only legacy
		// flows are unaffected.
		if v.requireBootEnrollment && bootPtr != nil {
			reader, readerOK := v.baselineStore.(BootBaselineReader)
			enrolled := false
			if readerOK && reader.GetBootBaseline(clientID) != nil {
				enrolled = true
			}
			if !enrolled && !v.pcrVerifier.PolicyDeclaresBootPCRsForTenant(tenant) {
				if v.pcrVerifier.PolicyRequiresSecureBootForTenant(tenant) && SecureBootAnchored(bootFacts) {
					logging.Security(clog, "boot baseline TOFU first-use accepted under event-log Secure Boot anchor",
						"policy", v.pcrVerifier.PolicyNameForTenant(tenant),
						"note", "PCR0/1/7 row is a per-device rollback anchor; firmware trust comes from the event-log Secure Boot gate")
				} else {
					logging.Security(clog, "boot baseline not enrolled; refusing TOFU first-use",
						"policy", v.pcrVerifier.PolicyNameForTenant(tenant),
						"hint", "load a signed policy that pins PCR0/PCR1/PCR7 for this fleet, or enable require_secureboot for diverse fleets, or disable RequireBootEnrollment for legacy hosts")
					v.metrics.Rejections.Inc("baseline_error")
					result.Result = types.VerifyIntegrityMismatch
					return result, errors.New("FAIL_BASELINE_ERROR: boot baseline not enrolled (TOFU first-use refused under RequireBootEnrollment)")
				}
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

				// capture the event log + firmware version alongside the boot
				// baseline so a later self-service re-anchor can replay-diff
				// PCR 7 and apply the firmware anti-rollback check
				if rs, ok := v.baselineStore.(ReanchorStorer); ok {
					var esrtVer uint32
					esrtPresent := false
					if report.ESRT != nil && report.ESRT.Present {
						esrtVer = report.ESRT.FWVersion
						esrtPresent = true
					}
					if err := rs.RecordBootEvidence(clientID, report.EventLog,
						esrtVer, esrtPresent); err != nil {
						clog.Warn("failed to record boot evidence for re-anchor",
							"error", err)
					}
				}
			case TOFUMatch:
				clog.Debug("boot PCRs match baseline")
			case TOFUMismatch:
				// self-service re-anchor:
				// if the drift preserves the Secure Boot root of trust,
				// re-pin the baseline instead of rejecting.
				// Returns true only on an actual re-pin.
				if v.tryReanchor(clog, clientID, tenant, bootPtr, report, bootFacts) {
					break
				}
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

	// stamp the CA-assigned tenant on the baseline row so the operator
	// surface can scope this client.
	// Fail closed rather than let tenant-owned device linger unscoped
	// in the default tenant
	if ts, ok := v.baselineStore.(TenantStorer); ok {
		if err := ts.SetClientTenant(clientID, tenant); err != nil {
			clog.Error("failed to persist the client tenant", "error", err)
			result.Result = types.VerifyInternalError
			return result, fmt.Errorf("failed to persist client tenant: %w", err)
		}
	}

	result.Result = types.VerifyOK
	result.ValidUntil = unixTimestamp(time.Now().Add(v.sessionTokenLife))
	sessionToken, err := v.deriveSessionToken(report, clientID, identity, result.ValidUntil, result.Result)
	if err != nil {
		result.Result = types.VerifyInternalError
		return result, fmt.Errorf("failed to derive session token: %w", err)
	}
	result.SessionToken = sessionToken
	v.rememberSessionToken(sessionToken, report, clientID, tenant, identity, result.ValidUntil, result.Result)

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
		RegisteredClients: len(v.ListClients()),
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
	HardwareID        string // hex-encoded
	Revoked           bool
	RevocationReason  string
	LastAttestation   time.Time
	AttestCount       uint64
	MonotonicCounter  uint64
	PendingChallenges int
	PCR14Baseline     string // hex-encoded
	FirstSeen         time.Time
	Tenant            string // CA-assigned; DefaultTenant when never stamped
}

// returns aggregated information about a specific client
func (v *Verifier) ClientInfo(clientID string) (*ClientInfo, bool) {
	info := &ClientInfo{
		ClientID: clientID,
	}

	// AIK store carries registrations only on legacy deployments;
	// under the Privacy CA flow the per-report certificate is
	// the AIK trust anchor and this lookup never hits
	_, err := v.aikStore.GetAIK(clientID)
	hasAIK := err == nil

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
	hasBaseline := false
	if baseline := v.baselineStore.GetBaseline(clientID); baseline != nil {
		hasBaseline = true
		info.PCR14Baseline = hex.EncodeToString(baseline.PCR14[:])
		info.AttestCount = baseline.AttestCount
		info.FirstSeen = baseline.FirstSeen
	}

	// check if client exists in any store
	// baseline row is the durable record under the Privacy CA flow:
	// AIK store carries no registrations there and the nonce history
	// may start empty after a verifier restart
	if !hasAIK && info.MonotonicCounter == 0 && !hasBaseline {
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

// tryReanchor attempts self-service re-anchor on a firmware/Secure Boot PCR drift.
// It returns true only when the per-device boot baseline was actually re-pinned
// (the strong path, or an operator-approved LFA path), in which case the caller
// treats the attestation as a match instead of rejecting.
// Pending or escalated outcome returns false and the caller rejects as before.
// Decision itself lives in reanchorDecision.
func (v *Verifier) tryReanchor(clog *slog.Logger, clientID, tenant string,
	boot *BootBaseline, report *types.AttestationReport,
	bootFacts *BootFacts,
) bool {
	if !v.selfServiceReanchor {
		return false
	}
	// diverse-fleet profile only:
	// client's policy with require_secureboot and the event-log Secure Boot
	// anchor proven for this boot
	if !v.pcrVerifier.PolicyRequiresSecureBootForTenant(tenant) || !SecureBootAnchored(bootFacts) {
		return false
	}
	rs, ok := v.baselineStore.(ReanchorStorer)
	if !ok {
		return false
	}

	st := rs.GetReanchorState(clientID)
	now := time.Now()
	verdict, reason := reanchorDecision(ReanchorInputs{
		BaselineEventLog:    st.EventLogBaseline,
		CurrentParsed:       bootFacts.Parsed, // already parsed + quote-verified upstream
		BaselineESRTVersion: st.ESRTVersion,
		CurrentESRT:         report.ESRT,
		ESRTCapable:         st.ESRTCapable,
		LastReanchorAt:      st.LastReanchorAt,
		Now:                 now,
	})

	esrtPresent := report.ESRT != nil && report.ESRT.Present
	var esrtVer uint32
	if esrtPresent {
		esrtVer = report.ESRT.FWVersion
	}

	switch verdict {
	case ReanchorAllow:
		if err := rs.ArchiveAndReanchor(clientID, *boot, report.EventLog,
			esrtVer, esrtPresent, false, "strong", now); err != nil {
			if errors.Is(err, ErrReanchorRateLimited) {
				// concurrent attestation for this client re-anchored first;
				// in-transaction guard refused this one. Fail closed.
				logging.Security(clog, "boot baseline re-anchor escalated (rate limit raced)", "reason", reason)
				v.metrics.Reanchors.Inc("escalate")
				return false
			}
			clog.Warn("re-anchor archive failed", "error", err)
			return false
		}
		logging.Security(clog, "boot baseline re-anchored (strong path)", "reason", reason)
		v.metrics.Reanchors.Inc("strong")
		return true
	case ReanchorLFA:
		// LFA re-anchor applies automatically (no approval gate):
		// player keeps attesting after a firmware update.
		// ArchiveAndReanchor flags the client for post-fact operator review;
		// the alert below and the review list (GET /api/v1/reanchor/review)
		// surface it so an operator can inspect and, if needed, revoke or ban.
		if err := rs.ArchiveAndReanchor(clientID, *boot, report.EventLog,
			esrtVer, esrtPresent, true, "lfa", now); err != nil {
			if errors.Is(err, ErrReanchorRateLimited) {
				// concurrent attestation for this client re-anchored first;
				// in-transaction guard refused this one. Fail closed.
				logging.Security(clog, "boot baseline re-anchor escalated (rate limit raced)", "reason", reason)
				v.metrics.Reanchors.Inc("escalate")
				return false
			}
			clog.Warn("re-anchor archive failed", "error", err)
			return false
		}
		logging.Security(clog, "ALERT: boot baseline re-anchored on the low-firmware-assurance path (operator review recommended)", "reason", reason)
		v.metrics.Reanchors.Inc("lfa")
		return true
	default:
		logging.Security(clog, "boot baseline re-anchor escalated to operator", "reason", reason)
		v.metrics.Reanchors.Inc("escalate")
		return false
	}
}

// ListReanchorReview returns the clients that re-anchored on the
// Low-Firmware-Assurance path and have not yet been reviewed by an operator.
// List is informational (post-fact); LFA re-anchors are not blocked on it.
func (v *Verifier) ListReanchorReview() ([]string, error) {
	rs, ok := v.baselineStore.(ReanchorStorer)
	if !ok {
		return nil, fmt.Errorf("baseline store does not support self-service re-anchor")
	}
	return rs.ListLFAReviewPending(), nil
}

// AcknowledgeReanchorReview clears a client's pending-review flag once an
// operator has inspected its LFA re-anchor.
// It does not change the baseline.
func (v *Verifier) AcknowledgeReanchorReview(clientID string) error {
	rs, ok := v.baselineStore.(ReanchorStorer)
	if !ok {
		return fmt.Errorf("baseline store does not support self-service re-anchor")
	}
	return rs.AcknowledgeLFAReview(clientID)
}

// ErrUnknownClient is returned by the operator-facing lifecycle helpers
// when the target client has neither an AIK registration nor a baseline.
var ErrUnknownClient = errors.New("unknown client")

// reports whether the store pins a boot baseline for the client;
// stores without boot-PCR support report false
func (v *Verifier) hasBootBaseline(clientID string) bool {
	br, ok := v.baselineStore.(BootBaselineReader)
	return ok && br.GetBootBaseline(clientID) != nil
}

// ForceReanchor drops all stored baseline state for a client
// (PCR14 baseline, PCR0/1/7 boot baseline, re-anchor bookkeeping)
// so the next attestation re-establishes trust per the active TOFU/policy configuration.
// This is the deliberate operator re-baseline for platform changes the self-service
// re-anchor refuses (or that profile is not enabled for).
// AIK registration is untouched, so the host keeps attesting with its enrolled identity.
func (v *Verifier) ForceReanchor(clientID string) error {
	// in-memory store keeps the PCR14 and boot baselines in separate maps,
	// so existence must consult both before falling back to the AIK registration
	if v.baselineStore.GetBaseline(clientID) == nil && !v.hasBootBaseline(clientID) {
		if _, err := v.aikStore.GetAIK(clientID); err != nil {
			return ErrUnknownClient
		}
	}
	if err := v.baselineStore.ClearBaseline(clientID); err != nil {
		return err
	}
	v.metrics.Reanchors.Inc("forced")
	return nil
}

// DeleteClient removes all verifier-side trust state for a client:
// the baseline row and, on deployments whose AIK store carries registrations,
// the AIK registration.
// Under the Privacy CA model the AIK trust anchor is the certificate presented
// per attestation, so the baseline is the state that pins the device.
// Deleted client re-establishes trust from scratch on its next attestation.
// Revocations and hardware bans are keyed separately and intentionally
// survive the delete, so removal cannot be used to shed either.
func (v *Verifier) DeleteClient(clientID string) error {
	known := v.baselineStore.GetBaseline(clientID) != nil || v.hasBootBaseline(clientID)

	if deleter, ok := v.aikStore.(store.ClientDeleter); ok {
		switch err := deleter.DeleteClient(clientID); {
		case err == nil:
			known = true
		case errors.Is(err, store.ErrAIKNotFound):
			// nothing registered
			// baseline decides existence
		default:
			return err
		}
	}

	if !known {
		return ErrUnknownClient
	}
	return v.baselineStore.ClearBaseline(clientID)
}
