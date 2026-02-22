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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

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

	// monitoring
	startTime      time.Time
	totalAttests   atomic.Int64
	successAttests atomic.Int64
	failedAttests  atomic.Int64
	revokedAttests atomic.Int64
	bannedAttests  atomic.Int64

	// policy enforcement
	requireEventLog bool
	requireCert     bool
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
}

// returns sensible defaults for verifier
func DefaultConfig() VerifierConfig {
	return VerifierConfig{
		NonceLifetime:    5 * time.Minute,
		SessionTokenLife: 1 * time.Hour,
		AIKMaxAge:        30 * 24 * time.Hour, // 30 days
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

	return &Verifier{
		nonceStore:       NewNonceStoreFromConfig(nonceCfg),
		pcrVerifier:      NewPCRVerifier(),
		aikStore:         aikStore,
		baselineStore:    baselineStore,
		revocationStore:  cfg.RevocationStore,
		banStore:         cfg.BanStore,
		log:              logger,
		metrics:          m,
		attestationLog:   cfg.AttestationLog,
		nonceLifetime:    cfg.NonceLifetime,
		sessionTokenLife: cfg.SessionTokenLife,
		aikMaxAge:        cfg.AIKMaxAge,
		requireEventLog:  cfg.RequireEventLog,
		requireCert:      cfg.RequireCert,
		startTime:        time.Now(),
	}
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
			resultStr := "OK"
			if retErr != nil {
				resultStr = types.VerifyResultString(result.Result)
			}
			_ = v.attestationLog.Record(store.AttestationRecord{
				Timestamp:  time.Now(),
				ClientID:   clientID,
				HardwareID: hwID,
				Result:     resultStr,
				DurationMs: float64(duration.Milliseconds()),
				PCR14:      pcr14Hex,
			})
		}
	}()

	report, err := types.ParseReport(reportData)
	if err != nil {
		clog.Error("report parse failed", "error", err)
		result.Result = types.VerifyOldVersion
		return result, err
	}

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

	// check if registered AIK has exceeded its maximum age.
	// IMPORTANT: expiry is a policy hint; rotation MUST NOT be performed via TOFU
	// on an existing identity, otherwise an attacker can hijack the client
	aikExpired := false
	if v.aikMaxAge > 0 {
		if regTime, err := v.aikStore.GetRegisteredAt(clientID); err == nil && !regTime.IsZero() {
			if time.Since(regTime) > v.aikMaxAge {
				aikExpired = true
				clog.Warn("AIK registration expired, key rotation required",
					"registered_at", regTime.UTC().Format(time.RFC3339),
					"max_age", v.aikMaxAge,
					"age", time.Since(regTime).Truncate(time.Second))
			}
		}
	}

	storedAIK, err := v.aikStore.GetAIK(clientID)
	newClient := err != nil

	// extract the AIK from the report (untrusted input)
	var reportAIK *rsa.PublicKey
	if report.TPM.AIKPublicSize > 0 {
		aikData := report.TPM.AIKPublic[:report.TPM.AIKPublicSize]
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
			aikCert = report.TPM.AIKCertificate[:report.TPM.AIKCertSize]
			clog.Info("AIK certificate provided", "size", report.TPM.AIKCertSize)
		}
		if report.TPM.EKCertSize > 0 {
			ekCert = report.TPM.EKCertificate[:report.TPM.EKCertSize]
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

		if err := v.aikStore.RegisterAIKWithCert(clientID, reportAIK, aikCert, ekCert); err != nil {
			clog.Error("failed to register AIK", "error", err)
			v.metrics.Rejections.Inc("sig_fail")
			result.Result = types.VerifySigFail
			return result, fmt.Errorf("AIK registration failed: %w", err)
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
				prevKey, perr := ParseRSAPublicKey(report.TPM.PrevAIKPublic[:report.TPM.PrevAIKSize])
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

				// strict cert-backed verification for rotation
				if !v.requireCert {
					logging.Security(clog, "rotation rejected: require-cert is disabled",
						"detail", "refusing insecure AIK rotation")
					v.metrics.Rejections.Inc("sig_fail")
					result.Result = types.VerifySigFail
					return result, errors.New("AIK rotation requires certificates")
				}
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
				aikCert := report.TPM.AIKCertificate[:report.TPM.AIKCertSize]
				ekCert := report.TPM.EKCertificate[:report.TPM.EKCertSize]

				// reported hardware_id must be consistent with EK certificate
				derivedHWID, derr := deriveHardwareIDFromEKCert(ekCert)
				if derr != nil {
					v.metrics.Rejections.Inc("sig_fail")
					result.Result = types.VerifySigFail
					return result, derr
				}
				if !bytes.Equal(derivedHWID[:], report.TPM.HardwareID[:]) {
					logging.Security(clog, "rotation rejected: hardware_id does not match EK certificate")
					v.metrics.Rejections.Inc("sig_fail")
					result.Result = types.VerifySigFail
					return result, errors.New("hardware_id/EK mismatch")
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

	// verify PCR digest binding: ensure reported PCR values match TPM-signed digest
	if report.TPM.AttestSize > 0 {
		attestData := report.TPM.AttestData[:report.TPM.AttestSize]
		if err := VerifyPCRDigest(attestData, report.TPM.PCRValues, report.TPM.PCRMask); err != nil {
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
		if v.requireEventLog {
			clog.Error("event log required by policy but not provided")
			v.metrics.Rejections.Inc("pcr_fail")
			result.Result = types.VerifyPCRFail
			return result, errors.New("event log required by policy but not provided")
		}
		clog.Debug("event log not provided")
	}

	// check agent self-measurement against baseline
	pcr14 := report.TPM.PCRValues[14]
	pcr14Hex = FormatPCR14(pcr14)
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
	result.ValidUntil = uint64(time.Now().Add(v.sessionTokenLife).Unix())

	// Session token is a random challenge returned to the client
	// for optional application-level use. Verifier is stateless
	// by design -> the TPM quote is the trust anchor, not this token.
	// No server-side storage or validation endpoint is needed.
	if _, err := rand.Read(result.SessionToken[:]); err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	return result, nil
}

// loads a PCR policy file
func (v *Verifier) LoadPolicy(path string) error {
	return v.pcrVerifier.LoadPolicy(path)
}

// adds a policy programmatically
func (v *Verifier) AddPolicy(policy *PCRPolicy) {
	v.pcrVerifier.AddPolicy(policy)
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
