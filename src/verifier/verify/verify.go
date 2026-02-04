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
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

// main verification engine
type Verifier struct {
	nonceStore    *NonceStore
	pcrVerifier   *PCRVerifier
	aikStore      store.AIKStore
	baselineStore *BaselineStore

	// configuration
	nonceLifetime    time.Duration
	timestampMaxAge  time.Duration
	sessionTokenLife time.Duration
}

// holds verifier configuration
type VerifierConfig struct {
	// how long a challenge nonce is valid
	NonceLifetime time.Duration

	// maximum age of report timestamp
	TimestampMaxAge time.Duration

	// how long issued tokens are valid
	SessionTokenLife time.Duration
}

// returns sensible defaults for verifier
func DefaultConfig() VerifierConfig {
	return VerifierConfig{
		NonceLifetime:    5 * time.Minute,
		TimestampMaxAge:  2 * time.Minute,
		SessionTokenLife: 1 * time.Hour,
	}
}

// creates a new verification engine
func NewVerifier(cfg VerifierConfig, aikStore store.AIKStore) *Verifier {
	return &Verifier{
		nonceStore:       NewNonceStore(cfg.NonceLifetime),
		pcrVerifier:      NewPCRVerifier(),
		aikStore:         aikStore,
		baselineStore:    NewBaselineStore(),
		nonceLifetime:    cfg.NonceLifetime,
		timestampMaxAge:  cfg.TimestampMaxAge,
		sessionTokenLife: cfg.SessionTokenLife,
	}
}

// creates a challenge for client attestation
func (v *Verifier) GenerateChallenge(clientID string) (*types.Challenge, error) {
	// PCR selection: 0 (SRTM), 1 (BIOS config), 14 (LOTA self)
	pcrMask := uint32((1 << 0) | (1 << 1) | (1 << 14))

	return v.nonceStore.GenerateChallenge(clientID, pcrMask)
}

// performs full verification of attestation report
// returns verification result ready to send back to client
func (v *Verifier) VerifyReport(clientID string, reportData []byte) (*types.VerifyResult, error) {
	result := &types.VerifyResult{
		Magic:   types.ReportMagic,
		Version: types.ReportVersion,
	}

	report, err := types.ParseReport(reportData)
	if err != nil {
		log.Printf("[%s] Report parse failed: %v", clientID, err)
		result.Result = types.VerifyOldVersion
		return result, err
	}

	if err := v.nonceStore.VerifyNonce(report, clientID); err != nil {
		log.Printf("[%s] Nonce verification failed: %v", clientID, err)
		result.Result = types.VerifyNonceFail
		return result, err
	}
	log.Printf("[%s] Nonce verified (challenge-response + TPMS_ATTEST binding)", clientID)

	if err := VerifyTimestamp(report, v.timestampMaxAge); err != nil {
		log.Printf("[%s] Timestamp verification failed: %v", clientID, err)
		result.Result = types.VerifyNonceFail
		return result, err
	}

	aikPubKey, err := v.aikStore.GetAIK(clientID)
	if err != nil {
		// TOFU mode: first connection from this client
		// extract AIK from report and register it
		if report.TPM.AIKPublicSize == 0 {
			log.Printf("[%s] ERROR: No AIK public key in report", clientID)
			result.Result = types.VerifySigFail
			return result, errors.New("no AIK public key in report")
		}

		aikData := report.TPM.AIKPublic[:report.TPM.AIKPublicSize]
		aikPubKey, err = ParseRSAPublicKey(aikData)
		if err != nil {
			log.Printf("[%s] ERROR: Failed to parse AIK public key: %v", clientID, err)
			result.Result = types.VerifySigFail
			return result, fmt.Errorf("failed to parse AIK: %w", err)
		}

		// verify signature before registering
		if err := VerifyReportSignature(report, aikPubKey); err != nil {
			log.Printf("[%s] Signature verification failed: %v", clientID, err)
			result.Result = types.VerifySigFail
			return result, err
		}

		// extract AIK and EK certificates if provided
		var aikCert, ekCert []byte
		if report.TPM.AIKCertSize > 0 {
			aikCert = report.TPM.AIKCertificate[:report.TPM.AIKCertSize]
			log.Printf("[%s] AIK certificate provided (%d bytes)", clientID, report.TPM.AIKCertSize)
		}
		if report.TPM.EKCertSize > 0 {
			ekCert = report.TPM.EKCertificate[:report.TPM.EKCertSize]
			log.Printf("[%s] EK certificate provided (%d bytes)", clientID, report.TPM.EKCertSize)
		}

		// register AIK with certificate verification (if certs provided)
		if err := v.aikStore.RegisterAIKWithCert(clientID, aikPubKey, aikCert, ekCert); err != nil {
			log.Printf("[%s] ERROR: Failed to register AIK: %v", clientID, err)
			result.Result = types.VerifySigFail
			return result, fmt.Errorf("AIK registration failed: %w", err)
		}

		if len(aikCert) > 0 || len(ekCert) > 0 {
			log.Printf("[%s] AIK registered with certificate verification (fingerprint: %s)",
				clientID, AIKFingerprint(aikPubKey))
		} else {
			log.Printf("[%s] TOFU: AIK registered without certificate (fingerprint: %s)",
				clientID, AIKFingerprint(aikPubKey))
		}
	} else {
		// already registered - verify signature
		if err := VerifyReportSignature(report, aikPubKey); err != nil {
			log.Printf("[%s] Signature verification failed: %v", clientID, err)
			result.Result = types.VerifySigFail
			return result, err
		}
		log.Printf("[%s] Signature verified with registered AIK", clientID)
	}

	if err := v.pcrVerifier.VerifyReport(report); err != nil {
		log.Printf("[%s] PCR verification failed: %v", clientID, err)
		result.Result = types.VerifyPCRFail
		return result, err
	}

	// check agent self-measurement against baseline
	pcr14 := report.TPM.PCRValues[14]
	tofuResult, baseline := v.baselineStore.CheckAndUpdate(clientID, pcr14)
	switch tofuResult {
	case TOFUFirstUse:
		log.Printf("[%s] TOFU: First attestation - PCR14 baseline established: %s",
			clientID, FormatPCR14(pcr14))
	case TOFUMatch:
		log.Printf("[%s] TOFU: PCR14 matches baseline (attestation #%d)",
			clientID, baseline.AttestCount)
	case TOFUMismatch:
		log.Printf("[%s] CRITICAL: Potential agent tampering detected! Expected PCR14: %s, Got: %s",
			clientID, FormatPCR14(baseline.PCR14), FormatPCR14(pcr14))
		result.Result = types.VerifyIntegrityMismatch
		return result, fmt.Errorf("FAIL_INTEGRITY_MISMATCH: PCR14 changed from baseline")
	}

	if report.Header.Flags&types.FlagIOMMUOK == 0 {
		log.Printf("[%s] IOMMU not verified", clientID)
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
		log.Printf("[%s] Security features: %v", clientID, secFlags)
	} else {
		log.Printf("[%s] WARNING: No module security features detected", clientID)
	}

	log.Printf("[%s] Verification successful", clientID)

	result.Result = types.VerifyOK
	result.ValidUntil = uint64(time.Now().Add(v.sessionTokenLife).Unix())

	// generate session token
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

// sets which policy to use
func (v *Verifier) SetActivePolicy(name string) error {
	return v.pcrVerifier.SetActivePolicy(name)
}

// returns verifier statistics
type Stats struct {
	PendingChallenges int
	ActivePolicy      string
	LoadedPolicies    []string
}

func (v *Verifier) Stats() Stats {
	return Stats{
		PendingChallenges: v.nonceStore.PendingCount(),
		ActivePolicy:      v.pcrVerifier.GetActivePolicy(),
		LoadedPolicies:    v.pcrVerifier.ListPolicies(),
	}
}
