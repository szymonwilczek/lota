// SPDX-License-Identifier: MIT
// LOTA Verifier - TPMS_ATTEST parser
//
// Parses the raw TPMS_ATTEST structure from TPM2_Quote response.
// Reference: TCG TPM 2.0 Library Specification, Part 2, Section 10.12

package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/szymonwilczek/lota/verifier/types"
)

// TPM constants
const (
	TPMGeneratedValue = 0xff544347 // TPM_GENERATED_VALUE
	TPMSTAttestQuote  = 0x8018     // TPM_ST_ATTEST_QUOTE
)

type TPMSAttest struct {
	Magic           uint32
	Type            uint16
	QualifiedSigner []byte // TPM2B_NAME
	ExtraData       []byte // TPM2B_DATA (IMPORTANT: contains the nonce!!!)
	ClockInfo       ClockInfo
	FirmwareVersion uint64
	QuoteInfo       *QuoteInfo // only if Type == TPM_ST_ATTEST_QUOTE
}

// TPMS_CLOCK_INFO
type ClockInfo struct {
	Clock        uint64
	ResetCount   uint32
	RestartCount uint32
	Safe         bool
}

// TPMS_QUOTE_INFO
type QuoteInfo struct {
	PCRSelect []byte // TPML_PCR_SELECTION
	PCRDigest []byte // TPM2B_DIGEST - hash of selected PCR values
}

// parses raw TPMS_ATTEST blob from TPM
func ParseTPMSAttest(data []byte) (*TPMSAttest, error) {
	if len(data) < 20 {
		return nil, errors.New("attest data too short")
	}

	r := bytes.NewReader(data)
	attest := &TPMSAttest{}

	// magic (4 bytes)
	if err := binary.Read(r, binary.BigEndian, &attest.Magic); err != nil {
		return nil, fmt.Errorf("failed to read magic: %w", err)
	}
	if attest.Magic != TPMGeneratedValue {
		return nil, fmt.Errorf("invalid TPM magic: 0x%08X (expected 0x%08X)",
			attest.Magic, TPMGeneratedValue)
	}

	// type (2 bytes)
	if err := binary.Read(r, binary.BigEndian, &attest.Type); err != nil {
		return nil, fmt.Errorf("failed to read type: %w", err)
	}

	// qualifiedSigner (TPM2B_NAME: 2 bytes size + data)
	var signerSize uint16
	if err := binary.Read(r, binary.BigEndian, &signerSize); err != nil {
		return nil, fmt.Errorf("failed to read signer size: %w", err)
	}
	attest.QualifiedSigner = make([]byte, signerSize)
	if _, err := io.ReadFull(r, attest.QualifiedSigner); err != nil {
		return nil, fmt.Errorf("failed to read signer: %w", err)
	}

	// extraData (TPM2B_DATA: 2 bytes size + data) - nonce
	var extraDataSize uint16
	if err := binary.Read(r, binary.BigEndian, &extraDataSize); err != nil {
		return nil, fmt.Errorf("failed to read extraData size: %w", err)
	}
	attest.ExtraData = make([]byte, extraDataSize)
	if _, err := io.ReadFull(r, attest.ExtraData); err != nil {
		return nil, fmt.Errorf("failed to read extraData: %w", err)
	}

	// clockInfo (17 bytes total)
	if err := binary.Read(r, binary.BigEndian, &attest.ClockInfo.Clock); err != nil {
		return nil, fmt.Errorf("failed to read clock: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &attest.ClockInfo.ResetCount); err != nil {
		return nil, fmt.Errorf("failed to read resetCount: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &attest.ClockInfo.RestartCount); err != nil {
		return nil, fmt.Errorf("failed to read restartCount: %w", err)
	}
	var safeByte uint8
	if err := binary.Read(r, binary.BigEndian, &safeByte); err != nil {
		return nil, fmt.Errorf("failed to read safe: %w", err)
	}
	attest.ClockInfo.Safe = safeByte != 0

	// firmwareVersion (8 bytes)
	if err := binary.Read(r, binary.BigEndian, &attest.FirmwareVersion); err != nil {
		return nil, fmt.Errorf("failed to read firmwareVersion: %w", err)
	}

	// parse quote-specific data if this is a quote
	if attest.Type == TPMSTAttestQuote {
		quoteInfo, err := parseQuoteInfo(r)
		if err != nil {
			return nil, fmt.Errorf("failed to parse quote info: %w", err)
		}
		attest.QuoteInfo = quoteInfo
	}

	return attest, nil
}

// parses TPMS_QUOTE_INFO from reader
func parseQuoteInfo(r *bytes.Reader) (*QuoteInfo, error) {
	qi := &QuoteInfo{}

	// TPML_PCR_SELECTION
	// count (4 bytes) + array of TPMS_PCR_SELECTION
	var count uint32
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, fmt.Errorf("failed to read PCR selection count: %w", err)
	}

	// reconstruct the raw TPML_PCR_SELECTION bytes for signature verification
	var pcrSelectBuf bytes.Buffer
	binary.Write(&pcrSelectBuf, binary.BigEndian, count)

	for i := uint32(0); i < count; i++ {
		var hashAlg uint16
		var sizeOfSelect uint8
		if err := binary.Read(r, binary.BigEndian, &hashAlg); err != nil {
			return nil, err
		}
		if err := binary.Read(r, binary.BigEndian, &sizeOfSelect); err != nil {
			return nil, err
		}
		selectBytes := make([]byte, sizeOfSelect)
		if _, err := io.ReadFull(r, selectBytes); err != nil {
			return nil, err
		}

		binary.Write(&pcrSelectBuf, binary.BigEndian, hashAlg)
		pcrSelectBuf.WriteByte(sizeOfSelect)
		pcrSelectBuf.Write(selectBytes)
	}
	qi.PCRSelect = pcrSelectBuf.Bytes()

	// PCR digest (TPM2B_DIGEST: 2 bytes size + data)
	var digestSize uint16
	if err := binary.Read(r, binary.BigEndian, &digestSize); err != nil {
		return nil, fmt.Errorf("failed to read PCR digest size: %w", err)
	}
	qi.PCRDigest = make([]byte, digestSize)
	if _, err := io.ReadFull(r, qi.PCRDigest); err != nil {
		return nil, fmt.Errorf("failed to read PCR digest: %w", err)
	}

	return qi, nil
}

// verifies that extraData in TPMS_ATTEST matches expected nonce
func VerifyNonceInAttest(attestData []byte, expectedNonce []byte) error {
	attest, err := ParseTPMSAttest(attestData)
	if err != nil {
		return fmt.Errorf("failed to parse TPMS_ATTEST: %w", err)
	}

	if !bytes.Equal(attest.ExtraData, expectedNonce) {
		return fmt.Errorf("nonce mismatch: TPMS_ATTEST extraData does not match challenge nonce")
	}

	return nil
}

// verifies that PCR values in the report match the TPM-signed PCRDigest
func VerifyPCRDigest(attestData []byte, pcrValues [types.PCRCount][types.HashSize]byte, pcrMask uint32) error {
	attest, err := ParseTPMSAttest(attestData)
	if err != nil {
		return fmt.Errorf("failed to parse TPMS_ATTEST: %w", err)
	}

	if attest.Type != TPMSTAttestQuote {
		return fmt.Errorf("not a quote attestation (type 0x%04X)", attest.Type)
	}

	if attest.QuoteInfo == nil {
		return errors.New("no quote info in attestation")
	}

	h := sha256.New()
	for i := 0; i < types.PCRCount; i++ {
		if pcrMask&(1<<uint(i)) != 0 {
			h.Write(pcrValues[i][:])
		}
	}
	computed := h.Sum(nil)

	if !bytes.Equal(computed, attest.QuoteInfo.PCRDigest) {
		return fmt.Errorf("PCR digest mismatch: reported values do not match TPM-signed digest")
	}

	return nil
}

// extracts nonce (extraData) from TPMS_ATTEST
func GetNonceFromAttest(attestData []byte) ([]byte, error) {
	attest, err := ParseTPMSAttest(attestData)
	if err != nil {
		return nil, err
	}
	return attest.ExtraData, nil
}

// computes SHA-256(challengeNonce || hardwareID) to cryptographically
// bind the TPM quote to the hardware identity. Agent uses this as
// qualifyingData for Esys_Quote, and the verifier reconstructs it from
// the report fields to verify the TPMS_ATTEST extraData.
func ComputeBindingNonce(challengeNonce [types.NonceSize]byte, hardwareID [types.HardwareIDSize]byte) [types.NonceSize]byte {
	h := sha256.New()
	h.Write(challengeNonce[:])
	h.Write(hardwareID[:])
	var out [types.NonceSize]byte
	copy(out[:], h.Sum(nil))
	return out
}
