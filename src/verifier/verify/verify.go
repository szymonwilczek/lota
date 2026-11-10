// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Main verification orchestrator

package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sort"
	"sync/atomic"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

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
	wipeBytes(report.TPM.Nonce[:])
	wipeBytes(report.EventLog)
}

func unixTimestamp(t time.Time) uint64 {
	ts := t.Unix()
	if ts < 0 {
		return 0
	}
	return uint64(ts)
}

// decodeDevicePseudonym decodes the device identity the attestation CA writes
// as hex in the AIK certificate subject.
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

// Verifier verifies attestation reports.
type Verifier struct {
	nonceStore    *NonceStore
	pcrVerifier   *PCRVerifier
	aikVerifier   store.AIKCertVerifier
	baselineStore BaselineStorer

	// nil = not enforced
	revocationStore store.RevocationStore
	banStore        store.BanStore

	log            *slog.Logger
	metrics        *metrics.Metrics
	attestationLog store.AttestationLog

	resultValidity time.Duration

	startTime      time.Time
	totalAttests   atomic.Int64
	successAttests atomic.Int64
	failedAttests  atomic.Int64
	revokedAttests atomic.Int64
	bannedAttests  atomic.Int64

	requireBootEnrollment bool
	selfServiceReanchor   *bool
}

func validateTPMFieldSizes(report *types.AttestationReport) error {
	if int(report.TPM.AIKPublicSize) > len(report.TPM.AIKPublic) {
		return fmt.Errorf("invalid aik_public_size: %d > %d", report.TPM.AIKPublicSize, len(report.TPM.AIKPublic))
	}
	if int(report.TPM.AIKCertSize) > len(report.TPM.AIKCertificate) {
		return fmt.Errorf("invalid aik_cert_size: %d > %d", report.TPM.AIKCertSize, len(report.TPM.AIKCertificate))
	}
	if int(report.TPM.AttestSize) > len(report.TPM.AttestData) {
		return fmt.Errorf("invalid attest_size: %d > %d", report.TPM.AttestSize, len(report.TPM.AttestData))
	}
	if int(report.TPM.QuoteSigSize) > len(report.TPM.QuoteSignature) {
		return fmt.Errorf("invalid quote_sig_size: %d > %d", report.TPM.QuoteSigSize, len(report.TPM.QuoteSignature))
	}
	return nil
}

// VerifierConfig configures NewVerifier.
type VerifierConfig struct {
	NonceLifetime time.Duration

	// ResultValidity is how long a passing verdict holds; the host gets it
	// as ValidUntil.
	ResultValidity time.Duration

	BaselineStore    BaselineStorer   // nil = in-memory
	UsedNonceBackend UsedNonceBackend // nil = in-memory

	RevocationStore store.RevocationStore // nil = not enforced
	BanStore        store.BanStore        // nil = not enforced

	Logger *slog.Logger // nil = discarded

	Metrics *metrics.Metrics // nil = a private instance

	AttestationLog store.AttestationLog // nil = not recorded

	// RequireBootEnrollment refuses a first-use PCR 0/1/7 baseline unless
	// the policy pins PCR 0/1/7, the store holds an enrolled row, or the
	// policy requires Secure Boot and the event log anchors it.
	RequireBootEnrollment bool

	// EnableSelfServiceReanchor overrides the policy profile; nil lets the
	// policy decide (profile consumer turns it on). Re-anchor also needs
	// require_secureboot and a trusted Secure Boot anchor.
	EnableSelfServiceReanchor *bool

	// AllowPermissivePolicy lets LoadPolicy accept a policy for which
	// IsMeasurementEmptyPolicy holds.
	AllowPermissivePolicy bool

	// AllowUnpinnedAgent lets LoadPolicy accept a policy for which
	// RequiresAgentHashPin holds.
	AllowUnpinnedAgent bool
}

// DefaultConfig returns the default verifier configuration.
func DefaultConfig() VerifierConfig {
	return VerifierConfig{
		NonceLifetime:         5 * time.Minute,
		ResultValidity:        1 * time.Hour,
		RequireBootEnrollment: true,
		AllowPermissivePolicy: false,
	}
}

// NewVerifier returns a verifier; Close stops its nonce store sweep.
func NewVerifier(cfg VerifierConfig, aikVerifier store.AIKCertVerifier) *Verifier {
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
		aikVerifier:           aikVerifier,
		baselineStore:         baselineStore,
		revocationStore:       cfg.RevocationStore,
		banStore:              cfg.BanStore,
		log:                   logger,
		metrics:               m,
		attestationLog:        cfg.AttestationLog,
		resultValidity:        cfg.ResultValidity,
		requireBootEnrollment: cfg.RequireBootEnrollment,
		selfServiceReanchor:   cfg.EnableSelfServiceReanchor,
		startTime:             time.Now(),
	}

	return v
}

// Close stops the nonce store's expiry sweep.
func (v *Verifier) Close() {
	v.nonceStore.Close()
}

// GenerateChallenge issues a challenge bound to clientID, the caller's
// per-connection binding. It asks for the PCRs of every selectable policy:
// the tenant is not known before the report.
func (v *Verifier) GenerateChallenge(clientID string) (*types.Challenge, error) {
	pcrMask := v.pcrVerifier.GetChallengePolicyMask()
	return v.nonceStore.GenerateChallenge(clientID, pcrMask)
}

// DiscardChallenge releases a challenge whose peer left without answering.
func (v *Verifier) DiscardChallenge(challenge *types.Challenge, clientID string) {
	if challenge == nil {
		return
	}
	v.nonceStore.DiscardChallenge(challenge.Nonce, clientID)
}

// certificateVerdict maps an AIK certificate failure to the agent's verdict:
//   - names another key: VerifyIdentityFail;
//   - outside its validity window: VerifyCertificateValidity (expiry, clock);
//   - unparseable, untrusted chain or no anchors: VerifySigFail.
func certificateVerdict(err error) uint32 {
	switch {
	case errors.Is(err, store.ErrCertificateKeyMatch):
		return types.VerifyIdentityFail
	case errors.Is(err, store.ErrCertificateExpired),
		errors.Is(err, store.ErrCertificateNotYet):
		return types.VerifyCertificateValidity
	default:
		return types.VerifySigFail
	}
}

// MaxRecordedDetail caps the refusal reason in an attestation record.
// The reason quotes report data, so it is capped when written.
const MaxRecordedDetail = 2048

// recordedDetail returns err as one sanitized, bounded line for the decision
// log. An accepted round (nil err) records an empty reason.
func recordedDetail(err error) string {
	if err == nil {
		return ""
	}
	detail := logging.SanitizeField(err.Error())
	if len(detail) > MaxRecordedDetail {
		detail = detail[:MaxRecordedDetail]
	}
	return detail
}

// bootBaselineRoad names what authenticated a first-use PCR 0/1/7 baseline.
type bootBaselineRoad struct {
	allowedBy string // logged as allowed_by; empty = not authenticated
	note      string
	consent   bool // the pin spends a forced re-anchor consent
}

// bootBaselineRoad resolves the policy roads; the caller checks the store.
func (v *Verifier) bootBaselineRoad(tenant string, bootFacts *BootFacts) bootBaselineRoad {
	if v.pcrVerifier.PolicyDeclaresBootPCRsForTenant(tenant) {
		return bootBaselineRoad{allowedBy: "policy PCR0/1/7 pins"}
	}
	if v.pcrVerifier.PolicyRequiresSecureBootForTenant(tenant) &&
		SecureBootAnchored(bootFacts) {
		return bootBaselineRoad{
			allowedBy: "event-log Secure Boot anchor",
			note:      "PCR0/1/7 row is a per-device rollback anchor; firmware trust comes from the event-log Secure Boot gate",
		}
	}
	return bootBaselineRoad{}
}

// storeBootRoad resolves the store roads: an enrolled boot baseline, else a
// forced re-anchor consent, which the pin spends.
func (v *Verifier) storeBootRoad(clientID string) (bootBaselineRoad, error) {
	enrolled, err := v.hasBootBaseline(clientID)
	if err != nil {
		return bootBaselineRoad{}, err
	}
	if enrolled {
		road := bootBaselineRoad{allowedBy: "baseline store enrollment"}
		return road, nil
	}
	fr, ok := v.baselineStore.(ForcedReanchorStorer)
	if !ok {
		return bootBaselineRoad{}, nil
	}
	forced, err := fr.HasForcedReanchor(clientID)
	if err != nil || !forced {
		return bootBaselineRoad{}, err
	}
	return bootBaselineRoad{
		allowedBy: "operator force-reanchor",
		note: "the operator consented to pin the firmware state " +
			"this host reported",
		consent: true,
	}, nil
}

// VerifyReportFrom verifies a report and records the address it came from;
// remoteAddr may be empty. challengeID is the binding the challenge was issued
// to; logs and the record name it as the client until the verified AIK
// certificate does.
func (v *Verifier) VerifyReportFrom(challengeID, remoteAddr string, reportData []byte) (_ *types.VerifyResult, retErr error) {
	reportBuf := cloneSensitive(reportData)
	defer wipeBytes(reportBuf)

	startTime := time.Now()
	v.totalAttests.Add(1)
	v.metrics.AttestationTotal.Inc()

	// logged until the AIK certificate names the client
	clientID := challengeID
	clog := logging.WithClient(v.log, clientID)
	var pcr14Hex string
	var kernelHashHex string
	var hwID string
	// empty in the record until the AIK certificate names it
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
				KernelHash: kernelHashHex,
				Details:    recordedDetail(retErr),
				RemoteAddr: logging.SanitizeField(remoteAddr),
			}); err != nil {
				clog.Warn("failed to record attestation decision", "error", err)
			}
		}
	}()

	report, err := types.ParseReport(reportBuf)
	if err != nil {
		clog.Error("report parse failed", "error", err)
		// only a version mismatch means upgrade the agent;
		// any other parse failure is a damaged frame
		verdict := types.VerifyReportMalformed
		if errors.Is(err, types.ErrInvalidVersion) {
			verdict = types.VerifyOldVersion
		}
		v.metrics.Rejections.Inc(types.VerifyResultString(verdict))
		result.Result = verdict
		return result, err
	}
	defer wipeReportSensitive(report)

	if err := validateTPMFieldSizes(report); err != nil {
		clog.Error("invalid TPM field sizes in report", "error", err)
		v.metrics.Rejections.Inc("sig_fail")
		result.Result = types.VerifySigFail
		return result, err
	}

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

	if v.aikVerifier == nil {
		// verifier misconfiguration; nothing the host can change
		logging.Security(clog, "no attestation-CA root configured; refusing attestation")
		v.metrics.Rejections.Inc(types.VerifyResultString(types.VerifyInternalError))
		result.Result = types.VerifyInternalError
		return result, errors.New("no AIK certificate verifier configured")
	}
	if report.TPM.AIKCertSize == 0 {
		// an unfinished enrolment, not a bad signature
		logging.Security(clog, "attestation rejected: AIK certificate required",
			"challenge_id", challengeID)
		v.metrics.Rejections.Inc(types.VerifyResultString(types.VerifyCertificateMissing))
		result.Result = types.VerifyCertificateMissing
		return result, errors.New("AIK certificate required")
	}
	aikCert := cloneSensitive(report.TPM.AIKCertificate[:report.TPM.AIKCertSize])
	defer wipeBytes(aikCert)
	aikLeaf, err := v.aikVerifier.VerifyAIKCertificate(reportAIK, aikCert)
	if err != nil {
		logging.Security(clog, "AIK certificate verification failed", "error", err)
		verdict := certificateVerdict(err)
		v.metrics.Rejections.Inc(types.VerifyResultString(verdict))
		result.Result = verdict
		return result, fmt.Errorf("AIK certificate verification failed: %w", err)
	}

	identity, err := decodeDevicePseudonym(aikLeaf.Subject.CommonName)
	if err != nil {
		// verified cert, unreadable pseudonym: re-enroll, not a TPM fault
		logging.Security(clog, "AIK certificate carries an invalid device identity",
			"subject", aikLeaf.Subject.CommonName, "error", err)
		v.metrics.Rejections.Inc(types.VerifyResultString(types.VerifyIdentityFail))
		result.Result = types.VerifyIdentityFail
		return result, fmt.Errorf("invalid device identity in AIK certificate: %w", err)
	}
	tenant, err = TenantFromCertificate(aikLeaf)
	if err != nil {
		// same for a missing or ambiguous tenant
		logging.Security(clog, "AIK certificate carries an invalid tenant",
			"subject", aikLeaf.Subject.CommonName, "error", err)
		v.metrics.Rejections.Inc(types.VerifyResultString(types.VerifyIdentityFail))
		result.Result = types.VerifyIdentityFail
		return result, fmt.Errorf("invalid tenant in AIK certificate: %w", err)
	}
	clientID = aikLeaf.Subject.CommonName
	hwID = store.FormatHardwareID(identity)
	clog = logging.WithClient(v.log, clientID).With("tenant", tenant)
	clog.Debug("client identity derived from AIK certificate", "challenge_id", challengeID)

	// revocation and bans are checked before the nonce is consumed
	if v.revocationStore != nil {
		entry, revoked, err := v.revocationStore.IsRevoked(clientID)
		if err != nil {
			return v.refuseOnListError(clog, result,
				"revocation", err)
		}
		if revoked {
			v.revokedAttests.Add(1)
			v.metrics.Rejections.Inc("revoked")
			logging.Security(clog, "attestation rejected: AIK revoked",
				"reason", entry.Reason, "revoked_by", entry.RevokedBy, "note", entry.Note)
			result.Result = types.VerifyRevoked
			return result, fmt.Errorf("client AIK revoked: %s", entry.Reason)
		}
	}

	// a ban holds in the tenant it was recorded in alone
	if v.banStore != nil {
		entry, banned, err := v.banStore.IsBanned(tenant, identity)
		if err != nil {
			return v.refuseOnListError(clog, result, "ban", err)
		}
		if banned {
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

	if err := VerifyReportSignature(report, reportAIK); err != nil {
		clog.Error("signature verification failed", "error", err)
		v.metrics.Rejections.Inc("sig_fail")
		result.Result = types.VerifySigFail
		return result, err
	}
	clog.Debug("signature verified with certificate-authenticated AIK")

	if report.TPM.AttestSize > 0 {
		attestData := cloneSensitive(report.TPM.AttestData[:report.TPM.AttestSize])
		defer wipeBytes(attestData)
		parsedAttest, err := ParseTPMSAttest(attestData)
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

	// the policy gates read the boot facts
	var bootFacts *BootFacts
	if len(report.EventLog) > 0 {
		facts, err := VerifyEventLogWithPolicy(report, v.pcrVerifier.PolicyRequiresCmdlineForTenant(tenant))
		if err != nil {
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
		// the host sees only the verdict, so send the refusal's own class
		verdict := policyVerdict(err)
		clog.Error("policy verification failed", "error", err,
			"verdict", types.VerifyResultString(verdict))
		v.metrics.Rejections.Inc(types.VerifyResultString(verdict))
		result.Result = verdict
		return result, err
	}

	if !UEFIAnchored(bootFacts) {
		logging.Security(clog, "event log carries no UEFI firmware evidence",
			"hint", "LOTA requires UEFI; switch the firmware out of legacy BIOS/CSM mode and reinstall")
		v.metrics.Rejections.Inc("pcr_fail")
		result.Result = types.VerifyPCRFail
		return result, errors.New("FAIL_PCR_FAIL: event log proves no UEFI boot (no quote-authenticated SecureBoot variable measurement)")
	}

	pcr14 := report.TPM.PCRValues[14]
	pcr14Hex = FormatPCR14(pcr14)
	recordedKernelHash := RecordedKernelHash(report, bootFacts)
	kernelHashHex = hex.EncodeToString(recordedKernelHash[:])
	if bootFacts != nil && bootFacts.KernelImageTrusted &&
		bootFacts.KernelImage.Found {
		clog.Debug("kernel hash taken from the measured kernel image",
			"path", bootFacts.KernelImage.Path)
	}

	// PCR 14 is derived for the initramfs lock with the boot commitment on
	// top, and for nothing else
	if report.Header.Flags&types.FlagBootCommitmentV1 == 0 {
		logging.Security(clog, "report omits FlagBootCommitmentV1",
			"flags", fmt.Sprintf("0x%08x", report.Header.Flags))
		v.metrics.Rejections.Inc("pcr_fail")
		result.Result = types.VerifyPCRFail
		return result, errors.New("FAIL_PCR_FAIL: report missing FlagBootCommitmentV1 (PCR14 boot commitment required)")
	}
	if report.Header.Flags&types.FlagInitramfsLockV1 == 0 {
		logging.Security(clog, "report omits FlagInitramfsLockV1; initramfs PCR14 lock required",
			"flags", fmt.Sprintf("0x%08x", report.Header.Flags))
		v.metrics.Rejections.Inc("pcr_fail")
		result.Result = types.VerifyPCRFail
		return result, errors.New("FAIL_PCR_FAIL: report missing FlagInitramfsLockV1 (initramfs PCR14 lock required)")
	}

	// PCR 0, 1 and 7 are required before any baseline write
	const bootPCRMask = (uint32(1) << 0) | (uint32(1) << 1) | (uint32(1) << 7)
	haveBootPCRs := report.TPM.PCRMask&bootPCRMask == bootPCRMask
	if !haveBootPCRs {
		logging.Security(clog, "report omits firmware/SecureBoot PCRs from pcr_mask",
			"pcr_mask", fmt.Sprintf("0x%08x", report.TPM.PCRMask),
			"required_mask", fmt.Sprintf("0x%08x", bootPCRMask))
		v.metrics.Rejections.Inc("pcr_fail")
		result.Result = types.VerifyPCRFail
		return result, errors.New("FAIL_PCR_FAIL: report does not include firmware/SecureBoot PCRs in pcr_mask")
	}
	if _, bootStoreOK := v.baselineStore.(BootBaselineStorer); !bootStoreOK {
		clog.Error("baseline store does not support boot PCR pinning; refusing attestation")
		v.metrics.Rejections.Inc("baseline_error")
		result.Result = types.VerifyInternalError
		return result, errors.New("FAIL_BASELINE_ERROR: store missing boot PCR support")
	}

	// the agent_hash and boot PCR pins commit in one transaction
	atomicStore, atomicOK := v.baselineStore.(AtomicBaselineStorer)
	if !atomicOK {
		clog.Error("baseline store does not implement AtomicBaselineStorer; refusing FlagBootCommitment attestation")
		v.metrics.Rejections.Inc("baseline_error")
		result.Result = types.VerifyInternalError
		return result, errors.New("FAIL_BASELINE_ERROR: store missing atomic agent_hash/boot pinning")
	}

	// the pre-lock PCR 14 comes from the event log; a forged log fails the
	// match with the quoted register
	var pcr14Baseline [types.HashSize]byte
	if bootFacts != nil {
		pcr14Baseline = PCR14BaselineFromEventLog(bootFacts.Parsed)
	}
	expected, matched := MatchLockedBootCommitmentPCR14(
		pcr14Baseline, report.System.AgentHash, pcr14)
	if !matched {
		logging.Security(clog, "PCR14 boot-commitment derivation mismatch",
			"actual_pcr14", pcr14Hex,
			"expected_pcr14", FormatPCR14(expected),
			"eventlog_baseline", FormatPCR14(pcr14Baseline),
			"agent_hash", hex.EncodeToString(report.System.AgentHash[:]),
			"hint", "rebuild initramfs with the current lota-pcr14-lock helper, cold reboot, and run the same agent binary that extended PCR14")
		v.metrics.Rejections.Inc("integrity_mismatch")
		result.Result = types.VerifyIntegrityMismatch
		return result, errors.New("FAIL_INTEGRITY_MISMATCH: PCR14 does not match boot-commitment derivation")
	}

	bootPtr := &BootBaseline{
		PCR0: report.TPM.PCRValues[0],
		PCR1: report.TPM.PCRValues[1],
		PCR7: report.TPM.PCRValues[7],
	}

	// Enrollment gate: a first-use PCR 0/1/7 row needs a policy road, an
	// enrolled store row or an operator's forced re-anchor while
	// RequireBootEnrollment holds. The road is resolved with the gate off
	// too: the pin logs it.
	bootPin := v.bootBaselineRoad(tenant, bootFacts)
	if bootPin.allowedBy == "" && v.requireBootEnrollment {
		road, err := v.storeBootRoad(clientID)
		if err != nil {
			clog.Error("boot baseline store error, refusing "+
				"attestation", "error", err)
			v.metrics.Rejections.Inc("baseline_error")
			result.Result = types.VerifyInternalError
			return result, errors.New(
				"FAIL_BASELINE_ERROR: baseline store error")
		}
		bootPin = road
	}
	if bootPin.allowedBy == "" {
		if v.requireBootEnrollment {
			logging.Security(clog, "boot baseline not enrolled; refusing TOFU first-use",
				"policy", v.pcrVerifier.PolicyNameForTenant(tenant),
				"hint", "load a signed policy that pins PCR0/PCR1/PCR7 for this fleet, enable require_secureboot for diverse fleets, or run with --allow-tofu-boot-baseline")
			v.metrics.Rejections.Inc("baseline_error")
			result.Result = types.VerifyPolicyRequirement
			return result, errors.New("FAIL_BASELINE_ERROR: boot baseline not enrolled (TOFU first-use refused under RequireBootEnrollment)")
		}
		bootPin = bootBaselineRoad{
			allowedBy: "--allow-tofu-boot-baseline",
			note:      "nothing authenticated these values; the host pinned the firmware state it reported",
		}
	}

	outcome := atomicStore.CheckAndUpdateAttestation(
		clientID, pcr14, report.System.AgentHash, bootPtr,
		bootPin.consent)

	switch outcome.AgentHashResult {
	case TOFUFirstUse:
		clog.Info("TOFU: agent_hash baseline established",
			"agent_hash", hex.EncodeToString(report.System.AgentHash[:]))
	case TOFUMatch:
		if outcome.AgentHashBaseline != nil {
			clog.Debug("agent_hash matches baseline",
				"attest_count", outcome.AgentHashBaseline.AttestCount)
		}
	case TOFUMismatch:
		if v.tryAgentHashRepin(clog, clientID, tenant, pcr14, report) {
			// the mismatch aborted the transaction; re-run it
			outcome = atomicStore.CheckAndUpdateAttestation(
				clientID, pcr14, report.System.AgentHash, bootPtr,
				bootPin.consent)
			if outcome.AgentHashResult != TOFUMatch {
				logging.Security(clog, "agent_hash re-pin did not settle; refusing",
					"agent_hash", hex.EncodeToString(report.System.AgentHash[:]))
				v.metrics.Rejections.Inc("integrity_mismatch")
				result.Result = types.VerifyIntegrityMismatch
				return result, errors.New("FAIL_INTEGRITY_MISMATCH: agent_hash re-pin did not settle")
			}
			break
		}
		stored := report.System.AgentHash
		if outcome.AgentHashBaseline != nil {
			stored = outcome.AgentHashBaseline.AgentHash
		}
		if stored == ([types.HashSize]byte{}) {
			logging.Security(clog,
				"baseline carries no pinned agent_hash; refusing to adopt the reported one",
				"reported_agent_hash",
				hex.EncodeToString(report.System.AgentHash[:]),
				"note",
				"out-of-band PCR 14 pin; pin this client's agent hash or clear the baseline to re-enroll it")
			v.metrics.Rejections.Inc("integrity_mismatch")
			result.Result = types.VerifyIntegrityMismatch
			return result, errors.New("FAIL_INTEGRITY_MISMATCH: baseline has no pinned agent_hash to compare against")
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
		result.Result = types.VerifyInternalError
		return result, errors.New("FAIL_BASELINE_ERROR: agent_hash baseline store unavailable")
	}

	// The derivation above holds for any pre-lock PCR 14 the log names; the
	// pinned register catches a change of it. tryMOKRepin follows a change
	// confined to the MOK events.
	switch outcome.PCR14Result {
	case TOFUFirstUse:
		clog.Info("TOFU: PCR14 baseline established", "pcr14", pcr14Hex)
	case TOFUMatch:
		clog.Debug("PCR14 matches the pinned register")
	case TOFUMismatch:
		pinned := pcr14
		if outcome.AgentHashBaseline != nil {
			pinned = outcome.AgentHashBaseline.PCR14
		}
		if v.tryMOKRepin(clog, clientID, tenant, pinned, pcr14, report, bootFacts) {
			// the mismatch aborted the transaction; re-run it on the moved pin
			outcome = atomicStore.CheckAndUpdateAttestation(
				clientID, pcr14, report.System.AgentHash, bootPtr,
				bootPin.consent)
			if outcome.PCR14Result == TOFUMatch {
				break
			}
			logging.Security(clog, "PCR14 re-pin did not settle; refusing",
				"pcr14", pcr14Hex)
			v.metrics.Rejections.Inc("integrity_mismatch")
			result.Result = types.VerifyIntegrityMismatch
			return result, errors.New("FAIL_INTEGRITY_MISMATCH: PCR14 re-pin did not settle")
		}
		logging.Security(clog, "PCR14 moved from the pinned register",
			"actual_pcr14", pcr14Hex,
			"pinned_pcr14", FormatPCR14(pinned),
			"agent_hash", hex.EncodeToString(report.System.AgentHash[:]),
			"hint", "the pre-lock PCR14 baseline changed (MOK enrollment, shim/SBAT update, rebuilt initramfs lock); re-anchor the client once the change is accounted for")
		v.metrics.Rejections.Inc("integrity_mismatch")
		result.Result = types.VerifyIntegrityMismatch
		return result, errors.New("FAIL_INTEGRITY_MISMATCH: PCR14 changed from the pinned baseline")
	case TOFUError:
		clog.Error("PCR14 baseline store error, refusing attestation")
		v.metrics.Rejections.Inc("baseline_error")
		result.Result = types.VerifyInternalError
		return result, errors.New("FAIL_BASELINE_ERROR: PCR14 baseline store unavailable")
	}

	if outcome.BootProvided {
		switch outcome.BootResult {
		case TOFUFirstUse:
			pinArgs := []any{
				"pcr0", hex.EncodeToString(bootPtr.PCR0[:]),
				"pcr1", hex.EncodeToString(bootPtr.PCR1[:]),
				"pcr7", hex.EncodeToString(bootPtr.PCR7[:]),
				"policy", v.pcrVerifier.PolicyNameForTenant(tenant),
				"allowed_by", bootPin.allowedBy,
			}
			if bootPin.note != "" {
				pinArgs = append(pinArgs, "note", bootPin.note)
			}
			logging.Security(clog, "boot baseline TOFU first-use accepted", pinArgs...)

			// evidence for a later self-service re-anchor
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
			result.Result = types.VerifyInternalError
			return result, fmt.Errorf("FAIL_BASELINE_ERROR: boot baseline store unavailable")
		}
	}

	if report.Header.Flags&types.FlagIOMMUOK == 0 {
		clog.Warn("IOMMU not verified")
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
	if report.Header.Flags&types.FlagIMAAppraisal != 0 {
		secFlags = append(secFlags, "IMA_APPRAISAL")
	}
	if len(secFlags) > 0 {
		clog.Info("security features detected", "flags", secFlags)
	} else {
		clog.Warn("no module security features detected")
	}

	if report.Header.Flags&types.FlagBench != 0 {
		clog.Info("agent runs with --bench")
	}
	if report.Header.Flags&types.FlagEventsLost != 0 {
		clog.Warn("agent's event log is incomplete: the kernel left events out")
	}
	if report.Header.Flags&types.FlagEnforce != 0 {
		clog.Info("enforce mode", "policy", types.PolicyKeys(report.Header.Flags))
	}

	clog.Info("verification successful")

	// advisory: record the kernel digest and log a change
	if kr, ok := v.baselineStore.(KernelHashRecorder); ok {
		prev, had, err := kr.RecordKernelHash(clientID, recordedKernelHash)
		switch {
		case err != nil:
			clog.Warn("failed to record the reported kernel hash", "error", err)
		case had && prev != recordedKernelHash:
			clog.Info("kernel_hash changed",
				"previous_kernel_hash", hex.EncodeToString(prev[:]),
				"reported_kernel_hash", kernelHashHex,
				"note", "advisory: this device booted a different kernel image than the one it booted before. The digest is the bootloader's own measurement of the image, taken from the quote-authenticated event log, so a rebooted host reports the same value until the kernel it loads changes. Hosts that measure no kernel image under a name the verifier recognises fall back to the register the agent reports, which covers everything the bootloader read and moves on an ordinary reboot")
		}
	}

	// advisory: record the trusted keys and log a change
	if kr, ok := v.baselineStore.(MachineKeysRecorder); ok && bootFacts != nil {
		keys := ExtractMachineKeys(bootFacts.Parsed, report.MokList)
		encoded, err := json.Marshal(keys)
		if err == nil {
			var prev []byte
			prev, err = kr.RecordMachineKeys(clientID, encoded)
			if err == nil && prev != nil && !bytes.Equal(prev, encoded) {
				clog.Info("machine_keys changed", "db", len(keys.DB),
					"mok", len(keys.MOK), "mok_state", keys.MOKState)
			}
		}
		if err != nil {
			clog.Warn("failed to record the machine keys", "error", err)
		}
	}

	// fail closed: an unstamped client reads as the default tenant
	if ts, ok := v.baselineStore.(TenantStorer); ok {
		if err := ts.SetClientTenant(clientID, tenant); err != nil {
			clog.Error("failed to persist the client tenant", "error", err)
			v.metrics.Rejections.Inc(types.VerifyResultString(types.VerifyInternalError))
			result.Result = types.VerifyInternalError
			return result, fmt.Errorf("failed to persist client tenant: %w", err)
		}
	}

	result.Result = types.VerifyOK
	result.ValidUntil = unixTimestamp(time.Now().Add(v.resultValidity))

	return result, nil
}

// LoadPolicy loads a PCR policy file.
func (v *Verifier) LoadPolicy(path string) error {
	return v.pcrVerifier.LoadPolicy(path)
}

// AddPolicy adds a policy without the signature, IsMeasurementEmptyPolicy and
// RequiresAgentHashPin checks of LoadPolicy.
func (v *Verifier) AddPolicy(policy *PCRPolicy) error {
	return v.pcrVerifier.AddPolicy(policy)
}

// SetPolicyPublicKey makes LoadPolicy require a valid detached signature by
// pubKey.
func (v *Verifier) SetPolicyPublicKey(pubKey ed25519.PublicKey) {
	v.pcrVerifier.SetPolicyPublicKey(pubKey)
}

// ActivePolicyConfig returns the active policy; callers must not modify it.
func (v *Verifier) ActivePolicyConfig() (*PCRPolicy, bool) {
	return v.pcrVerifier.GetActivePolicyConfig()
}

// ListPolicies returns the names of the loaded policies.
func (v *Verifier) ListPolicies() []string {
	return v.pcrVerifier.ListPolicies()
}

// TenantBindings returns the policy each tenant binds; a tenant that binds
// none is verified against the active policy.
func (v *Verifier) TenantBindings() map[string]string {
	return v.pcrVerifier.TenantBindings()
}

// Stats is a snapshot of the verifier's counters.
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

// ClientInfo is what the verifier knows about one client.
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
	Tenant            string       // CA-assigned; DefaultTenant when never stamped
	MachineKeys       *MachineKeys // nil until an attestation recorded them
}

// ClientInfo returns the client's record; false when it has no baseline and
// a zero ClientCounter. A baseline store failure is an error.
func (v *Verifier) ClientInfo(clientID string) (*ClientInfo, bool, error) {
	info := &ClientInfo{
		ClientID: clientID,
	}

	if hwid, err := store.ParseHardwareID(clientID); err == nil {
		info.HardwareID = store.FormatHardwareID(hwid)
	}

	if v.revocationStore != nil {
		entry, revoked, err := v.revocationStore.IsRevoked(clientID)
		if err != nil {
			return nil, false, err
		}
		if revoked {
			info.Revoked = true
			info.RevocationReason = string(entry.Reason)
		}
	}

	// per-instance nonce state, not comparable across instances
	info.MonotonicCounter = v.nonceStore.ClientCounter(clientID)
	info.PendingChallenges = v.nonceStore.ClientPendingCount(clientID)

	// the baseline record is shared; the nonce history is this instance's
	baseline, err := v.baselineStore.GetBaseline(clientID)
	if err != nil {
		return nil, false, err
	}
	hasBaseline := false
	if baseline != nil {
		hasBaseline = true
		info.PCR14Baseline = hex.EncodeToString(baseline.PCR14[:])
		info.AttestCount = baseline.AttestCount
		info.FirstSeen = baseline.FirstSeen
		info.LastAttestation = baseline.LastSeen
	}
	if info.LastAttestation.IsZero() {
		info.LastAttestation = v.nonceStore.ClientLastAttestation(clientID)
	}

	if kr, ok := v.baselineStore.(MachineKeysRecorder); ok {
		if stored := kr.GetMachineKeys(clientID); stored != nil {
			keys := &MachineKeys{}
			if err := json.Unmarshal(stored, keys); err == nil {
				info.MachineKeys = keys
			}
		}
	}

	// an unresolved tenant stays empty and matches no scoped key
	info.Tenant = DefaultTenant
	if ts, ok := v.baselineStore.(TenantStorer); ok {
		tenant, err := ts.ClientTenant(clientID)
		if err != nil {
			v.log.Error("failed to resolve the client tenant",
				"client_id", logging.SanitizeField(clientID), "error", err)
			info.Tenant = ""
		} else {
			info.Tenant = tenant
		}
	}

	if info.MonotonicCounter == 0 && !hasBaseline {
		return nil, false, nil
	}

	return info, true, nil
}

// ListClients returns every known client: the durable baseline record first,
// then this process's challenge history.
// Only the baseline record is shared and survives a restart.
func (v *Verifier) ListClients() []string {
	seen := make(map[string]struct{})
	var clients []string

	add := func(ids []string) {
		for _, id := range ids {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			clients = append(clients, id)
		}
	}

	add(v.baselineStore.ListClients())
	add(v.nonceStore.ListActiveClients())

	return clients
}

// DurableClientsPage returns one page of the durable client record,
// ordered by client ID.
func (v *Verifier) DurableClientsPage(limit, offset int) ([]string, error) {
	if pager, ok := v.baselineStore.(PagedClientLister); ok {
		return pager.ListClientsPage(limit, offset)
	}

	all := v.baselineStore.ListClients()
	sort.Strings(all)
	if offset >= len(all) {
		return []string{}, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], nil
}

// CountDurableClients returns the number of clients with a durable record.
func (v *Verifier) CountDurableClients() int {
	return v.baselineStore.Stats().TotalClients
}

// IsDurableClient reports whether the client has a durable record.
func (v *Verifier) IsDurableClient(clientID string) (bool, error) {
	baseline, err := v.baselineStore.GetBaseline(clientID)
	return baseline != nil, err
}

// RevocationStore returns the revocation store, nil when not enforced.
func (v *Verifier) RevocationStore() store.RevocationStore {
	return v.revocationStore
}

// BanStore returns the ban store, nil when not enforced.
func (v *Verifier) BanStore() store.BanStore {
	return v.banStore
}

// selfServiceReanchorForTenant returns EnableSelfServiceReanchor when set,
// the tenant's policy profile otherwise.
func (v *Verifier) selfServiceReanchorForTenant(tenant string) bool {
	if v.selfServiceReanchor != nil {
		return *v.selfServiceReanchor
	}
	return v.pcrVerifier.PolicyEnablesSelfServiceReanchorForTenant(tenant)
}

// tryReanchor re-pins a drifted PCR 0/1/7 baseline when reanchorDecision
// allows it on the strong or the LFA path, and returns true only on a re-pin.
// It needs self-service re-anchor on, require_secureboot and a trusted Secure
// Boot anchor.
func (v *Verifier) tryReanchor(clog *slog.Logger, clientID, tenant string,
	boot *BootBaseline, report *types.AttestationReport,
	bootFacts *BootFacts,
) bool {
	if !v.selfServiceReanchorForTenant(tenant) {
		return false
	}
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
		CurrentParsed:       bootFacts.Parsed,
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
				// a concurrent round re-anchored first
				logging.Security(clog, "boot baseline re-anchor escalated (rate limit raced)", "reason", reason)
				v.metrics.Reanchors.Inc(metrics.OutcomeEscalate)
				return false
			}
			clog.Warn("re-anchor archive failed", "error", err)
			return false
		}
		logging.Security(clog, "boot baseline re-anchored (strong path)", "reason", reason)
		v.metrics.Reanchors.Inc(metrics.OutcomeStrong)
		return true
	case ReanchorLFA:
		// applied at once and flagged, see ListReanchorReview
		if err := rs.ArchiveAndReanchor(clientID, *boot, report.EventLog,
			esrtVer, esrtPresent, true, "lfa", now); err != nil {
			if errors.Is(err, ErrReanchorRateLimited) {
				// a concurrent round re-anchored first
				logging.Security(clog, "boot baseline re-anchor escalated (rate limit raced)", "reason", reason)
				v.metrics.Reanchors.Inc(metrics.OutcomeEscalate)
				return false
			}
			clog.Warn("re-anchor archive failed", "error", err)
			return false
		}
		logging.Security(clog, "ALERT: boot baseline re-anchored on the low-firmware-assurance path (operator review recommended)", "reason", reason)
		v.metrics.Reanchors.Inc(metrics.OutcomeLFA)
		return true
	default:
		logging.Security(clog, "boot baseline re-anchor escalated to operator", "reason", reason)
		v.metrics.Reanchors.Inc(metrics.OutcomeEscalate)
		return false
	}
}

// refuseOnListError refuses an attestation whose revocation or ban lookup
// failed: a store that cannot answer does not clear the client.
func (v *Verifier) refuseOnListError(clog *slog.Logger,
	result *types.VerifyResult, list string, err error,
) (*types.VerifyResult, error) {
	clog.Error(list+" store error, refusing attestation", "error", err)
	v.metrics.Rejections.Inc(
		types.VerifyResultString(types.VerifyInternalError))
	result.Result = types.VerifyInternalError
	return result, fmt.Errorf("%s store error", list)
}

// tryAgentHashRepin moves a mismatched agent_hash pin, with its PCR 14, to the
// reported hash when agentHashDecision allows it, and returns true only on a
// re-pin.
func (v *Verifier) tryAgentHashRepin(clog *slog.Logger, clientID, tenant string,
	pcr14 [types.HashSize]byte, report *types.AttestationReport,
) bool {
	rs, ok := v.baselineStore.(AgentHashRepinStorer)
	if !ok {
		return false
	}
	policy, ok := v.pcrVerifier.policyForTenant(tenant)
	if !ok || policy == nil {
		return false
	}

	st := rs.GetAgentHashRepinState(clientID)
	if !st.Present {
		return false
	}
	if !st.Pinned {
		// a PCR 14 pin without an agent hash is not moved
		logging.Security(clog,
			"agent_hash re-pin refused: the baseline carries no pinned hash to move",
			"reported_agent_hash",
			hex.EncodeToString(report.System.AgentHash[:]),
			"note",
			"the row comes from an out-of-band PCR 14 pin; pin this client's agent hash or clear the baseline to re-enroll it")
		v.metrics.Reanchors.Inc(metrics.OutcomeAgentHashEscalate)
		return false
	}

	now := time.Now()
	verdict, refusal := agentHashDecision(policy.AgentHashes,
		st.LastRepinAt, now)

	if verdict != AgentHashRepin {
		// an unlisted build already failed the policy gate
		if refusal == AgentHashTooSoon {
			logging.Security(clog,
				"agent_hash re-pin refused by the per-client interval, not by the allow-list",
				"reported_agent_hash",
				hex.EncodeToString(report.System.AgentHash[:]),
				"last_repin_at", st.LastRepinAt.UTC().Format(time.RFC3339),
				"interval_elapses_at",
				st.LastRepinAt.Add(AgentHashRepinMinInterval).UTC().Format(time.RFC3339),
				"note",
				"the reported build is on this policy's allow-list; wait for the interval or re-anchor this client")
			v.metrics.Reanchors.Inc(
				metrics.OutcomeAgentHashEscalate)
		}
		return false
	}

	if err := rs.ArchiveAndRepinAgentHash(clientID, report.System.AgentHash,
		pcr14, now); err != nil {
		if errors.Is(err, ErrAgentHashRepinRateLimited) {
			// a concurrent round re-pinned first
			logging.Security(clog, "agent_hash re-pin escalated (rate limit raced)")
			v.metrics.Reanchors.Inc(
				metrics.OutcomeAgentHashEscalate)
			return false
		}
		clog.Warn("agent_hash re-pin archive failed", "error", err)
		return false
	}

	logging.Security(clog, "agent_hash re-pinned to a policy-listed build",
		"new_agent_hash", hex.EncodeToString(report.System.AgentHash[:]),
		"repin_count", st.RepinCount+1,
		"note", "package update; the outgoing hash is archived and PCR 14 moved with it")
	v.metrics.Reanchors.Inc(metrics.OutcomeAgentHash)
	return true
}

// ListReanchorReview returns the clients that re-anchored on the
// Low-Firmware-Assurance path and await operator review.
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
	if err := v.knownClient(clientID); err != nil {
		return err
	}
	return rs.AcknowledgeLFAReview(clientID)
}

// ErrUnknownClient is returned by the operator-facing lifecycle helpers
// when the target client has no baseline.
var ErrUnknownClient = errors.New("unknown client")

func (v *Verifier) hasBootBaseline(clientID string) (bool, error) {
	br, ok := v.baselineStore.(BootBaselineReader)
	if !ok {
		return false, nil
	}
	boot, err := br.GetBootBaseline(clientID)
	return boot != nil, err
}

// knownClient returns ErrUnknownClient for a client with neither baseline,
// the store error when the store cannot say.
func (v *Verifier) knownClient(clientID string) error {
	baseline, err := v.baselineStore.GetBaseline(clientID)
	if err != nil {
		return err
	}
	if baseline != nil {
		return nil
	}
	boot, err := v.hasBootBaseline(clientID)
	if err != nil {
		return err
	}
	if !boot {
		return ErrUnknownClient
	}
	return nil
}

// ForceReanchor clears the client's baseline, so its next attestation pins
// afresh under the active policy. Under RequireBootEnrollment that
// attestation passes the enrollment gate once on the operator's consent.
func (v *Verifier) ForceReanchor(clientID string) error {
	// the in-memory store keeps the boot baseline apart
	if err := v.knownClient(clientID); err != nil {
		return err
	}
	if fr, ok := v.baselineStore.(ForcedReanchorStorer); ok {
		if err := fr.MarkForcedReanchor(clientID); err != nil {
			return err
		}
	}
	if err := v.baselineStore.ClearBaseline(clientID); err != nil {
		return err
	}
	v.metrics.Reanchors.Inc(metrics.OutcomeForced)
	return nil
}

// DeleteClient clears the client's baseline, a forced re-anchor consent and
// its nonce store state. Revocations and bans stay.
func (v *Verifier) DeleteClient(clientID string) error {
	if err := v.knownClient(clientID); err != nil {
		return err
	}
	if fr, ok := v.baselineStore.(ForcedReanchorStorer); ok {
		if _, err := fr.TakeForcedReanchor(clientID); err != nil {
			return err
		}
	}
	if err := v.baselineStore.ClearBaseline(clientID); err != nil {
		return err
	}

	// otherwise listed until the nonce store evicts it
	v.nonceStore.ForgetClient(clientID)
	return nil
}
