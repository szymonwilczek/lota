// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Shared fuzzing harness helpers
//
// Raw byte mutation cannot forge the RSA quote signature or the CA-issued
// AIK certificate, so a fuzzer that mutates a serialized report bounces off
// the signature gate and never reaches the policy logic that actually
// decides trust.
// These helpers let a target consume fuzzer bytes into the policy-relevant
// report fields and then RE-SIGN a self-consistent report, so mutation drives
// PCR-digest binding, nonce binding, event-log replay, kernel/agent baseline
// and IOMMU gates instead of the parser alone.

package verify

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

// fuzzConsumer slices a fuzzer-supplied byte slice into typed fields.
// It never panics on exhaustion:
// reads past the end return zero bytes, so short or empty input still
// produces a fully-formed (all-zero) spec.
type fuzzConsumer struct {
	data []byte
	pos  int
}

func newFuzzConsumer(data []byte) *fuzzConsumer { return &fuzzConsumer{data: data} }

func (c *fuzzConsumer) byteAt() byte {
	if c.pos >= len(c.data) {
		return 0
	}
	b := c.data[c.pos]
	c.pos++
	return b
}

// take returns the next n bytes, zero-padded when the input is exhausted
func (c *fuzzConsumer) take(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = c.byteAt()
	}
	return out
}

func (c *fuzzConsumer) fill(dst []byte) {
	for i := range dst {
		dst[i] = c.byteAt()
	}
}

func (c *fuzzConsumer) u32() uint32 { return binary.LittleEndian.Uint32(c.take(4)) }
func (c *fuzzConsumer) u64() uint64 { return binary.LittleEndian.Uint64(c.take(8)) }
func (c *fuzzConsumer) flag() bool  { return c.byteAt()&1 == 1 }

// fuzzReportSpec is the policy-relevant slice of an attestation report that
// the fuzzer controls.
// crypto envelope (quote signature, AIK certificate, PCR digest, attestation
// binding nonce) is always recomputed by buildSignedReport so the report is
// self-consistent regardless of these values;
// the fuzzer therefore drives the verifier's decision logic, not its
// reject-on-malformed-bytes paths.
type fuzzReportSpec struct {
	flags      uint32
	pcrMask    uint32
	pcrValues  [types.PCRCount][types.HashSize]byte
	kernelHash [types.HashSize]byte
	agentHash  [types.HashSize]byte
	kernelPath []byte
	iommu      struct {
		vendor  uint32
		flags   uint32
		units   uint32
		cmdline []byte
	}
	aikGen uint64

	// bindNonce controls whether the quote binds the real challenge nonce.
	// false exercises the nonce-fail gate with an otherwise valid envelope.
	bindNonce bool
}

// decodeFuzzReportSpec maps fuzzer bytes onto the controllable fields.
func decodeFuzzReportSpec(data []byte) *fuzzReportSpec {
	c := newFuzzConsumer(data)
	s := &fuzzReportSpec{}
	s.flags = c.u32()
	s.pcrMask = c.u32()
	// only PCR 0, 1, 14 participate in the fixture digest
	// fuzz those + couple more to exercise mask handling without 24*32 byte appetite
	for _, idx := range []int{0, 1, 7, 8, 14} {
		c.fill(s.pcrValues[idx][:])
	}
	c.fill(s.kernelHash[:])
	c.fill(s.agentHash[:])
	s.kernelPath = trimToMax(c.take(int(c.byteAt())), types.MaxKernelPath)
	s.iommu.vendor = c.u32()
	s.iommu.flags = c.u32()
	s.iommu.units = c.u32()
	s.iommu.cmdline = trimToMax(c.take(int(c.byteAt())), types.CmdlineParamMax)
	s.aikGen = c.u64()
	s.bindNonce = c.flag()
	return s
}

func trimToMax(b []byte, max int) []byte {
	if len(b) > max {
		return b[:max]
	}
	return b
}

// nominalSpec mirrors createValidReportWithKey's known-good values
// report built from it passes the full pipeline under createTestVerifier,
// so the seed gives the corpus a path through every gate
func nominalSpec() *fuzzReportSpec {
	s := &fuzzReportSpec{
		flags:     types.FlagTPMQuoteOK | types.FlagModuleSig | types.FlagEnforce,
		pcrMask:   0x00004003,
		aikGen:    1,
		bindNonce: true,
	}
	for i := range types.PCRCount {
		for j := range types.HashSize {
			s.pcrValues[i][j] = byte(i ^ j)
		}
	}
	// PCR 14 stays zero
	for j := range types.HashSize {
		s.pcrValues[14][j] = 0
		s.kernelHash[j] = byte(0xAA ^ j)
		s.agentHash[j] = byte(0xBB ^ j)
	}
	s.iommu.vendor = 0x8086
	s.iommu.flags = 0x07
	s.iommu.units = 2
	s.iommu.cmdline = []byte("intel_iommu=on")
	return s
}

// encodeFuzzReportSpec produces a corpus seed that decodeFuzzReportSpec maps
// back to the nominal spec, so `go test -fuzz` starts from a through-path
func encodeFuzzReportSpec(s *fuzzReportSpec) []byte {
	buf := make([]byte, 0, 512)
	var u4 [4]byte
	var u8 [8]byte
	putu32 := func(v uint32) { binary.LittleEndian.PutUint32(u4[:], v); buf = append(buf, u4[:]...) }
	putu64 := func(v uint64) { binary.LittleEndian.PutUint64(u8[:], v); buf = append(buf, u8[:]...) }

	putu32(s.flags)
	putu32(s.pcrMask)
	for _, idx := range []int{0, 1, 7, 8, 14} {
		buf = append(buf, s.pcrValues[idx][:]...)
	}
	buf = append(buf, s.kernelHash[:]...)
	buf = append(buf, s.agentHash[:]...)
	buf = append(buf, byte(len(s.kernelPath)))
	buf = append(buf, s.kernelPath...)
	putu32(s.iommu.vendor)
	putu32(s.iommu.flags)
	putu32(s.iommu.units)
	buf = append(buf, byte(len(s.iommu.cmdline)))
	buf = append(buf, s.iommu.cmdline...)
	putu64(s.aikGen)
	if s.bindNonce {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	return buf
}

// buildSignedReport lays out wire report from spec and recomputes the full
// crypto envelope (PCR digest, attestation binding nonce, quote signature,
// CA-issued AIK certificate) so the report is always self-consistent.
// Returned bytes parse, carry a valid AIK chain and a valid signature;
// only the policy-relevant contents vary, so VerifyReport's decision is
// driven by its trust logic rather than by malformed-input rejection
func buildSignedReport(s *fuzzReportSpec, clientID string, challengeNonce [types.NonceSize]byte, key *rsa.PrivateKey) []byte {
	hwID := sha256.Sum256([]byte(clientID))
	buf := make([]byte, types.MinReportSize)
	offset := 0

	binary.LittleEndian.PutUint32(buf[offset:], types.ReportMagic)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], types.ReportVersion)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], types.MinReportSize)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], s.flags)
	offset += 4

	for i := range types.PCRCount {
		copy(buf[offset:offset+types.HashSize], s.pcrValues[i][:])
		offset += types.HashSize
	}

	binary.LittleEndian.PutUint32(buf[offset:], s.pcrMask)
	offset += 4

	pcrDigest := computeTestPCRDigest(buf, 16, s.pcrMask)

	// binding report must mirror exactly the fields written into buf,
	// because the verifier recomputes the binding nonce from the parsed
	// report (see ComputeAttestationBindingNonce)
	bindingReport := &types.AttestationReport{}
	bindingReport.Header.Flags = s.flags
	copy(bindingReport.TPM.HardwareID[:], hwID[:])
	copy(bindingReport.System.KernelHash[:], s.kernelHash[:])
	copy(bindingReport.System.AgentHash[:], s.agentHash[:])
	bindingReport.System.IOMMU.Vendor = s.iommu.vendor
	bindingReport.System.IOMMU.Flags = s.iommu.flags
	bindingReport.System.IOMMU.UnitCount = s.iommu.units
	copy(bindingReport.System.IOMMU.CmdlineParam[:], s.iommu.cmdline)

	nonceForBinding := challengeNonce
	if !s.bindNonce {
		nonceForBinding[0] ^= 0xFF // valid envelope, wrong nonce -> nonce gate
	}
	bindingNonce := ComputeAttestationBindingNonce(nonceForBinding, bindingReport)
	attestData := createTPMSAttestWithNonce(bindingNonce[:], pcrDigest)

	hash := sha256.Sum256(attestData)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])

	copy(buf[offset:], signature)
	offset += types.MaxSigSize
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(signature)))
	offset += 2

	copy(buf[offset:], attestData)
	offset += types.MaxAttestSize
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(attestData)))
	offset += 2

	aikDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	copy(buf[offset:], aikDER)
	offset += types.MaxAIKPubSize
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(aikDER)))
	offset += 2

	aikCertDER := issueAIKCertOrPanic(testPseudonym(clientID), &key.PublicKey)
	copy(buf[offset:], aikCertDER)
	offset += types.MaxAIKCertSize
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(aikCertDER)))
	offset += 2

	// EK certificate left empty
	offset += types.MaxEKCertSize
	binary.LittleEndian.PutUint16(buf[offset:], 0)
	offset += 2

	copy(buf[offset:], challengeNonce[:])
	offset += types.NonceSize
	copy(buf[offset:offset+types.HardwareIDSize], hwID[:])
	offset += types.HardwareIDSize
	binary.LittleEndian.PutUint64(buf[offset:], s.aikGen)
	offset += 8

	// prev_aik_public empty
	offset += types.MaxAIKPubSize
	binary.LittleEndian.PutUint16(buf[offset:], 0)
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:], types.TPMAlgRSASSA)
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:], types.TPMAlgSHA256)
	offset += 2

	copy(buf[offset:offset+types.HashSize], s.kernelHash[:])
	offset += types.HashSize
	copy(buf[offset:offset+types.HashSize], s.agentHash[:])
	offset += types.HashSize
	copy(buf[offset:offset+types.MaxKernelPath], s.kernelPath)
	offset += types.MaxKernelPath

	binary.LittleEndian.PutUint32(buf[offset:], s.iommu.vendor)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], s.iommu.flags)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], s.iommu.units)
	offset += 4
	copy(buf[offset:offset+types.CmdlineParamMax], s.iommu.cmdline)
	offset += types.CmdlineParamMax

	// BPF summary (advisory; fixed)
	binary.LittleEndian.PutUint32(buf[offset:], 1)
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], 1)
	offset += 4
	offset += 16 // first_seen + last_seen timestamps left zero
	// bpf event_count = 0
	binary.LittleEndian.PutUint32(buf[offset:], 0)
	offset += 4

	eventLog := buildTestEventLog(nil)
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(eventLog)))
	buf = append(buf, eventLog...)
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(buf)))

	return buf
}

// newFuzzCertStore returns a certificate-verifying AIK store that trusts the
// shared test CA.
// VerifyReport refuses any store that is not an AIKCertVerifier (verify.go),
// so a fuzz target MUST use this and not MemoryStore, or every input is rejected
// before reaching trust logic
func newFuzzCertStore(tb testing.TB) store.AIKStore {
	tb.Helper()
	dir := tb.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCACert.Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		tb.Fatalf("write test CA: %v", err)
	}
	cs, err := store.NewCertificateStore(filepath.Join(dir, "store"), []string{caPath}, true)
	if err != nil {
		tb.Fatalf("NewCertificateStore: %v", err)
	}
	return cs
}
