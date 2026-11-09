// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - TPMS_ATTEST parser

package verify

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
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
	ExtraData       []byte // TPM2B_DATA, the binding nonce
	ClockInfo       ClockInfo
	FirmwareVersion uint64
	QuoteInfo       *QuoteInfo // only if Type == TPM_ST_ATTEST_QUOTE
}

// ClockInfo is TPMS_CLOCK_INFO.
type ClockInfo struct {
	Clock        uint64
	ResetCount   uint32
	RestartCount uint32
	Safe         bool
}

// QuoteInfo is TPMS_QUOTE_INFO.
type QuoteInfo struct {
	PCRSelect  []byte // TPML_PCR_SELECTION
	PCRDigest  []byte // TPM2B_DIGEST - hash of selected PCR values
	PCRHashAlg uint16 // hash algorithm from TPMS_PCR_SELECTION
}

// ParseTPMSAttest parses a TPMS_ATTEST; QuoteInfo is set for a quote.
func ParseTPMSAttest(data []byte) (*TPMSAttest, error) {
	if len(data) < 20 {
		return nil, errors.New("attest data too short")
	}

	r := bytes.NewReader(data)
	attest := &TPMSAttest{}

	if err := binary.Read(r, binary.BigEndian, &attest.Magic); err != nil {
		return nil, fmt.Errorf("failed to read magic: %w", err)
	}
	if attest.Magic != TPMGeneratedValue {
		return nil, fmt.Errorf("invalid TPM magic: 0x%08X (expected 0x%08X)",
			attest.Magic, TPMGeneratedValue)
	}

	if err := binary.Read(r, binary.BigEndian, &attest.Type); err != nil {
		return nil, fmt.Errorf("failed to read type: %w", err)
	}

	var signerSize uint16
	if err := binary.Read(r, binary.BigEndian, &signerSize); err != nil {
		return nil, fmt.Errorf("failed to read signer size: %w", err)
	}
	attest.QualifiedSigner = make([]byte, signerSize)
	if _, err := io.ReadFull(r, attest.QualifiedSigner); err != nil {
		return nil, fmt.Errorf("failed to read signer: %w", err)
	}

	var extraDataSize uint16
	if err := binary.Read(r, binary.BigEndian, &extraDataSize); err != nil {
		return nil, fmt.Errorf("failed to read extraData size: %w", err)
	}
	attest.ExtraData = make([]byte, extraDataSize)
	if _, err := io.ReadFull(r, attest.ExtraData); err != nil {
		return nil, fmt.Errorf("failed to read extraData: %w", err)
	}

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

	if err := binary.Read(r, binary.BigEndian, &attest.FirmwareVersion); err != nil {
		return nil, fmt.Errorf("failed to read firmwareVersion: %w", err)
	}

	if attest.Type == TPMSTAttestQuote {
		quoteInfo, err := parseQuoteInfo(r)
		if err != nil {
			return nil, fmt.Errorf("failed to parse quote info: %w", err)
		}
		attest.QuoteInfo = quoteInfo
	}

	return attest, nil
}

func parseQuoteInfo(r *bytes.Reader) (*QuoteInfo, error) {
	qi := &QuoteInfo{}

	var count uint32
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, fmt.Errorf("failed to read PCR selection count: %w", err)
	}

	// bounds the parse loop an untrusted count drives
	if count > 16 {
		return nil, fmt.Errorf("PCR selection count too large: %d", count)
	}

	var pcrSelectBuf bytes.Buffer
	if err := binary.Write(&pcrSelectBuf, binary.BigEndian, count); err != nil {
		return nil, fmt.Errorf("failed to encode PCR selection count: %w", err)
	}
	var pcrHashAlg uint16

	for i := uint32(0); i < count; i++ {
		var hashAlg uint16
		var sizeOfSelect uint8
		if err := binary.Read(r, binary.BigEndian, &hashAlg); err != nil {
			return nil, err
		}
		if i == 0 {
			pcrHashAlg = hashAlg
		} else if hashAlg != pcrHashAlg {
			return nil, fmt.Errorf("mixed PCR hash algorithms in TPMS_ATTEST: 0x%04X and 0x%04X", pcrHashAlg, hashAlg)
		}
		if err := binary.Read(r, binary.BigEndian, &sizeOfSelect); err != nil {
			return nil, err
		}
		selectBytes := make([]byte, sizeOfSelect)
		if _, err := io.ReadFull(r, selectBytes); err != nil {
			return nil, err
		}

		if err := binary.Write(&pcrSelectBuf, binary.BigEndian, hashAlg); err != nil {
			return nil, fmt.Errorf("failed to encode PCR hash algorithm: %w", err)
		}
		pcrSelectBuf.WriteByte(sizeOfSelect)
		pcrSelectBuf.Write(selectBytes)
	}
	qi.PCRSelect = pcrSelectBuf.Bytes()
	qi.PCRHashAlg = pcrHashAlg

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

// VerifyNonceInAttest parses attestData and compares its extraData with
// expectedNonce in constant time.
func VerifyNonceInAttest(attestData, expectedNonce []byte) error {
	attest, err := ParseTPMSAttest(attestData)
	if err != nil {
		return fmt.Errorf("failed to parse TPMS_ATTEST: %w", err)
	}

	if subtle.ConstantTimeCompare(attest.ExtraData, expectedNonce) != 1 {
		return fmt.Errorf("nonce mismatch: TPMS_ATTEST extraData does not match challenge nonce")
	}

	return nil
}

// VerifyPCRDigestParsed checks that the SHA-256 of the masked PCR values,
// in index order, equals the PCR digest of a parsed quote. A quote over a bank
// other than SHA-256 is refused: the report carries SHA-256 values alone.
func VerifyPCRDigestParsed(attest *TPMSAttest, pcrValues *[types.PCRCount][types.HashSize]byte, pcrMask uint32) error {
	if attest == nil {
		return errors.New("nil TPMS_ATTEST")
	}
	if attest.Type != TPMSTAttestQuote {
		return fmt.Errorf("not a quote attestation (type 0x%04X)", attest.Type)
	}
	if attest.QuoteInfo == nil {
		return errors.New("no quote info in attestation")
	}
	if len(attest.QuoteInfo.PCRDigest) == 0 {
		return errors.New("PCR digest is empty (corrupted quote?)")
	}
	if attest.QuoteInfo.PCRHashAlg != types.TPMAlgSHA256 {
		return fmt.Errorf("unsupported PCR bank hash 0x%04X: the LOTA wire format pins PCR values at SHA-256 (%d bytes); rebuild the agent or the quote with a SHA-256 PCR selection",
			attest.QuoteInfo.PCRHashAlg, types.HashSize)
	}

	h := sha256.New()
	for i := 0; i < types.PCRCount; i++ {
		if pcrMask&(uint32(1)<<i) != 0 {
			h.Write(pcrValues[i][:])
		}
	}
	computed := h.Sum(nil)

	if !bytes.Equal(computed, attest.QuoteInfo.PCRDigest) {
		return fmt.Errorf("PCR digest mismatch: reported values do not match TPM-signed digest")
	}

	return nil
}

// ComputeAttestationBindingNonce returns the quote extraData that binds the
// report fields the quote signature does not cover:
//
//	SHA-256(challengeNonce || signedFlags ||
//		kernelHash || agentHash || iommuStatus)
//
// signedFlags is Header.Flags without FlagTPMQuoteOK, which the agent sets
// after the quote. A nil report hashes zeros in place of its fields.
func ComputeAttestationBindingNonce(challengeNonce [types.NonceSize]byte, report *types.AttestationReport) [types.NonceSize]byte {
	var flagsLE [4]byte
	signedFlags := uint32(0)
	if report != nil {
		signedFlags = report.Header.Flags &^ types.FlagTPMQuoteOK
	}
	binary.LittleEndian.PutUint32(flagsLE[:], signedFlags)

	h := sha256.New()
	h.Write(challengeNonce[:])
	h.Write(flagsLE[:])
	if report != nil {
		h.Write(report.System.KernelHash[:])
		h.Write(report.System.AgentHash[:])

		var iommuHdr [12]byte
		binary.LittleEndian.PutUint32(iommuHdr[0:4], report.System.IOMMU.Vendor)
		binary.LittleEndian.PutUint32(iommuHdr[4:8], report.System.IOMMU.Flags)
		binary.LittleEndian.PutUint32(iommuHdr[8:12], report.System.IOMMU.UnitCount)
		h.Write(iommuHdr[:])
		h.Write(report.System.IOMMU.CmdlineParam[:])
	} else {
		h.Write(make([]byte, types.HashSize))
		h.Write(make([]byte, types.HashSize))
		h.Write(make([]byte, 12+types.CmdlineParamMax))
	}
	var out [types.NonceSize]byte
	copy(out[:], h.Sum(nil))
	return out
}
