// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"time"

	verifysdk "github.com/szymonwilczek/lota/sdk/server"
)

// LACH wire constants. Mirror include/lota_anticheat.h. Any drift is
// caught by the test suite which fabricates packets with these exact
// offsets.
const (
	lachMagic           uint32 = 0x4C414348 // 'LACH'
	lachVersion         uint8  = 3
	lachHeaderSize             = 110
	lachSessionIDSize          = 16
	lachGameHashSize           = 32
	lachRuntimeMeasSize        = 32
	lachMaxToken               = 1608
	lachMaxPacket              = lachHeaderSize + lachMaxToken

	// V2 binds the runtime measurement into the heartbeat nonce
	heartbeatNonceDomainV2 = "lota-ac-heartbeat:v2\x00"
	domainVersionV2        = 2

	// Runtime measures every file-backed loaded object.
	// Each object yields a content digest under runtimeObjectDomain.
	// Combined image digest folds them, keyed by soname, under runtimeMeasureDomain.
	runtimeObjectDomain  = "lota-ac-runtime-object:v1\x00"
	runtimeMeasureDomain = "lota-ac-runtime-measure:v2\x00"
)

// rejectErr signals that a packet failed at the wire-format layer and
// must be answered with the REJECT verdict. Anything else is treated
// as UNTRUSTED so the operator can distinguish "client sent garbage"
// from "client sent a structurally valid packet that did not verify".
type rejectErr struct{ msg string }

func (e *rejectErr) Error() string { return "reject: " + e.msg }

type lachHeader struct {
	magic         uint32
	version       uint8
	provider      uint8
	totalSize     uint16
	sessionID     [lachSessionIDSize]byte
	sequence      uint32
	lotaFlags     uint32
	timestamp     uint64
	gameIDHash    [lachGameHashSize]byte
	tokenSize     uint16
	domainVersion uint32
	runtimeMeas   [lachRuntimeMeasSize]byte
}

func (s *demoServer) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, lachMaxPacket+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, heartbeatResponse{
			State: verdictReject, Reason: "read body",
		})
		return
	}

	hdr, tokenBytes, parseErr := parseHeartbeat(body)
	if parseErr != nil {
		logf("session=? state=REJECT reason=%q", parseErr.Error())
		writeJSON(w, http.StatusBadRequest, heartbeatResponse{
			State: verdictReject, Reason: parseErr.Error(),
		})
		return
	}

	sessionHex := hex.EncodeToString(hdr.sessionID[:])
	gameHashHex := hex.EncodeToString(hdr.gameIDHash[:])

	game, known := s.gamesByHash[hdr.gameIDHash]
	if !known {
		s.recordVerdictWithLicense(sessionHex, gameHashHex,
			verdictUntrust, "")
		logf("session=%s seq=%d state=UNTRUSTED reason=%q",
			sessionHex, hdr.sequence, "unknown game_id_hash")
		writeJSON(w, http.StatusOK, heartbeatResponse{
			State: verdictUntrust, Reason: "unknown game_id_hash",
		})
		return
	}

	// Producer-reported runtime measurement (hdr.runtimeMeas) is
	// advisory only: it is computed inside the game process, which an
	// attacker with code in that process can forge, so it is logged on
	// mismatch but never gates trust.
	// Authoritative runtime measurement is taken by the agent from the
	// kernel side and bound into the TPM-signed token verified below.
	if hdr.runtimeMeas != game.runtimeMeasure {
		logf("session=%s seq=%d advisory=%q",
			sessionHex, hdr.sequence,
			"producer runtime measurement differs from registered baseline")
	}

	if reason, ok := s.checkFreshness(hdr); !ok {
		s.recordVerdictWithLicense(sessionHex, gameHashHex,
			verdictUntrust, game.licenseID)
		logf("session=%s seq=%d state=UNTRUSTED reason=%q",
			sessionHex, hdr.sequence, reason)
		writeJSON(w, http.StatusOK, heartbeatResponse{
			State: verdictUntrust, Reason: reason,
		})
		return
	}

	if s.aik == nil {
		s.recordVerdict(sessionHex, gameHashHex,
			verdictReject, game.licenseID, hdr)
		logf("session=%s seq=%d state=REJECT reason=%q",
			sessionHex, hdr.sequence, "server has no AIK configured")
		writeJSON(w, http.StatusServiceUnavailable, heartbeatResponse{
			State: verdictReject, Reason: "no AIK configured",
		})
		return
	}

	expected := computeHeartbeatNonce(hdr)
	claims, verr := verifysdk.VerifyToken(tokenBytes, s.aik, expected[:])
	if verr != nil {
		s.recordVerdict(sessionHex, gameHashHex,
			verdictUntrust, game.licenseID, hdr)
		logf("session=%s seq=%d state=UNTRUSTED reason=%q",
			sessionHex, hdr.sequence, verr.Error())
		writeJSON(w, http.StatusOK, heartbeatResponse{
			State: verdictUntrust, Reason: verr.Error(),
		})
		return
	}
	if claims.Flags != hdr.lotaFlags {
		s.recordVerdict(sessionHex, gameHashHex,
			verdictUntrust, game.licenseID, hdr)
		logf("session=%s seq=%d state=UNTRUSTED reason=%q",
			sessionHex, hdr.sequence, "flag mismatch")
		writeJSON(w, http.StatusOK, heartbeatResponse{
			State: verdictUntrust, Reason: "header flags do not match signed token",
		})
		return
	}

	s.recordVerdict(sessionHex, gameHashHex,
		verdictTrusted, game.licenseID, hdr)
	logf("session=%s seq=%d state=TRUSTED license=%s",
		sessionHex, hdr.sequence, game.licenseID)
	writeJSON(w, http.StatusOK, heartbeatResponse{
		State: verdictTrusted, License: game.licenseID,
	})
}

// parseHeartbeat decodes a LACH-framed packet. Returns a rejectErr for
// anything the wire format itself disallows; callers translate that
// into the REJECT verdict.
func parseHeartbeat(buf []byte) (*lachHeader, []byte, error) {
	if len(buf) < lachHeaderSize {
		return nil, nil, &rejectErr{msg: fmt.Sprintf("packet too short (%d bytes)", len(buf))}
	}
	hdr := &lachHeader{}
	hdr.magic = binary.LittleEndian.Uint32(buf[0:4])
	if hdr.magic != lachMagic {
		return nil, nil, &rejectErr{msg: fmt.Sprintf("bad magic 0x%08x", hdr.magic)}
	}
	hdr.version = buf[4]
	if hdr.version != lachVersion {
		return nil, nil, &rejectErr{msg: fmt.Sprintf("unsupported version %d", hdr.version)}
	}
	hdr.provider = buf[5]
	hdr.totalSize = binary.LittleEndian.Uint16(buf[6:8])
	if int(hdr.totalSize) != len(buf) {
		return nil, nil, &rejectErr{msg: fmt.Sprintf("total_size %d does not match body %d",
			hdr.totalSize, len(buf))}
	}
	copy(hdr.sessionID[:], buf[8:24])
	hdr.sequence = binary.LittleEndian.Uint32(buf[24:28])
	hdr.lotaFlags = binary.LittleEndian.Uint32(buf[28:32])
	hdr.timestamp = binary.LittleEndian.Uint64(buf[32:40])
	copy(hdr.gameIDHash[:], buf[40:72])
	hdr.tokenSize = binary.LittleEndian.Uint16(buf[72:74])
	hdr.domainVersion = binary.LittleEndian.Uint32(buf[74:78])
	copy(hdr.runtimeMeas[:], buf[78:110])

	if hdr.domainVersion != domainVersionV2 {
		return nil, nil, &rejectErr{msg: fmt.Sprintf("unsupported domain_version %d",
			hdr.domainVersion)}
	}
	if hdr.tokenSize == 0 || int(hdr.tokenSize) > lachMaxToken {
		return nil, nil, &rejectErr{msg: fmt.Sprintf("token_size %d out of range",
			hdr.tokenSize)}
	}
	if lachHeaderSize+int(hdr.tokenSize) != len(buf) {
		return nil, nil, &rejectErr{msg: "token_size does not match body remainder"}
	}
	token := buf[lachHeaderSize : lachHeaderSize+int(hdr.tokenSize)]
	return hdr, token, nil
}

// computeHeartbeatNonce mirrors compute_heartbeat_nonce() in
// src/sdk/lota_anticheat.c. Drift here would make every TRUSTED path
// fall back to UNTRUSTED because the embedded TPMS_ATTEST.extraData
// would no longer match the nonce the server expects.
func computeHeartbeatNonce(hdr *lachHeader) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(heartbeatNonceDomainV2))
	_, _ = h.Write(hdr.sessionID[:])
	_, _ = h.Write([]byte{hdr.provider})
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], hdr.sequence)
	_, _ = h.Write(u32[:])
	binary.LittleEndian.PutUint32(u32[:], hdr.lotaFlags)
	_, _ = h.Write(u32[:])
	var u64 [8]byte
	binary.LittleEndian.PutUint64(u64[:], hdr.timestamp)
	_, _ = h.Write(u64[:])
	_, _ = h.Write(hdr.gameIDHash[:])
	binary.LittleEndian.PutUint32(u32[:], hdr.domainVersion)
	_, _ = h.Write(u32[:])
	// V2 binds the runtime measurement
	_, _ = h.Write(hdr.runtimeMeas[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// runtimeObject is one measured object: its soname (file basename) and
// the content digest over its executable segments.
type runtimeObject struct {
	soname string
	digest [32]byte
}

// runtimeObjectDigest mirrors rt_file_object_digest() in
// src/sdk/lota_anticheat.c. It hashes the file-backed bytes of the
// executable (PF_X) PT_LOAD segments of an ELF object, in ascending
// p_vaddr order, under runtimeObjectDomain. hasExec is false for an
// object with no executable segment; such an object contributes nothing.
func runtimeObjectDigest(path string) (digest [32]byte, hasExec bool, err error) {
	f, err := elf.Open(path)
	if err != nil {
		return digest, false, err
	}
	defer f.Close()

	var segs []*elf.Prog
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 &&
			p.Filesz > 0 {
			segs = append(segs, p)
		}
	}
	if len(segs) == 0 {
		return digest, false, nil
	}
	sort.Slice(segs, func(i, j int) bool {
		return segs[i].Vaddr < segs[j].Vaddr
	})

	h := sha256.New()
	_, _ = h.Write([]byte(runtimeObjectDomain))
	var le4 [4]byte
	binary.LittleEndian.PutUint32(le4[:], uint32(len(segs)))
	_, _ = h.Write(le4[:])
	var le8 [8]byte
	for _, p := range segs {
		binary.LittleEndian.PutUint64(le8[:], p.Vaddr)
		_, _ = h.Write(le8[:])
		binary.LittleEndian.PutUint64(le8[:], p.Off)
		_, _ = h.Write(le8[:])
		binary.LittleEndian.PutUint64(le8[:], p.Filesz)
		_, _ = h.Write(le8[:])
		if _, err := io.CopyN(h, p.Open(), int64(p.Filesz)); err != nil {
			return digest, false, fmt.Errorf("read segment of %s: %w",
				path, err)
		}
	}
	copy(digest[:], h.Sum(nil))
	return digest, true, nil
}

// computeExpectedRuntimeMeasureSet mirrors
// lota_ac_compute_expected_runtime_measure_set(). It folds the per-object
// digests of the given ELF files (the trusted runtime manifest) into the
// combined image digest, keyed by soname (file basename) and sorted, so
// the order of paths does not matter. Files with no executable segment
// are skipped. The server reproduces this to reject heartbeats whose live
// code pages no longer match the registered binaries.
func computeExpectedRuntimeMeasureSet(paths []string) ([32]byte, error) {
	var out [32]byte
	objs := make([]runtimeObject, 0, len(paths))
	for _, p := range paths {
		dg, hasExec, err := runtimeObjectDigest(p)
		if err != nil {
			return out, err
		}
		if !hasExec {
			continue
		}
		objs = append(objs, runtimeObject{
			soname: filepath.Base(p),
			digest: dg,
		})
	}
	if len(objs) == 0 {
		return out, fmt.Errorf("no executable object in runtime manifest")
	}
	sort.Slice(objs, func(i, j int) bool {
		if objs[i].soname != objs[j].soname {
			return objs[i].soname < objs[j].soname
		}
		return bytes.Compare(objs[i].digest[:], objs[j].digest[:]) < 0
	})

	h := sha256.New()
	_, _ = h.Write([]byte(runtimeMeasureDomain))
	var le4 [4]byte
	binary.LittleEndian.PutUint32(le4[:], uint32(len(objs)))
	_, _ = h.Write(le4[:])
	for _, o := range objs {
		binary.LittleEndian.PutUint32(le4[:], uint32(len(o.soname)))
		_, _ = h.Write(le4[:])
		_, _ = h.Write([]byte(o.soname))
		_, _ = h.Write(o.digest[:])
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

// computeExpectedRuntimeMeasure is the single-object convenience: the
// combined measurement for an image made of one object (a statically
// linked producer, or when verifying the main executable alone).
func computeExpectedRuntimeMeasure(path string) ([32]byte, error) {
	return computeExpectedRuntimeMeasureSet([]string{path})
}

// checkFreshness enforces the demo's monotonic-sequence and bounded-
// age contract. The wire-format checks are best-effort: a real anti-
// cheat would also need replay protection across server restarts,
// which is out of scope here.
func (s *demoServer) checkFreshness(hdr *lachHeader) (string, bool) {
	now := uint64(time.Now().Unix())
	if hdr.timestamp > now+60 {
		return "timestamp in the future", false
	}
	maxAge := uint64(s.maxHeartbeatAge / time.Second)
	if maxAge > 0 && now-hdr.timestamp > maxAge {
		return "heartbeat too old", false
	}

	sessionHex := hex.EncodeToString(hdr.sessionID[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.sessions[sessionHex]; ok {
		if hdr.sequence <= prev.lastSeq {
			return "sequence not monotonic", false
		}
		if hdr.timestamp < prev.lastTimestamp {
			return "timestamp regressed", false
		}
	}
	return "", true
}

func (s *demoServer) recordVerdictWithLicense(sessionHex, gameHashHex, verdict, license string) {
	s.recordVerdict(sessionHex, gameHashHex, verdict, license, nil)
}

// recordVerdict updates per-session and per-game state. When hdr is
// non-nil the per-session row also advances lastSeq + lastTimestamp
// so a subsequent replay of the same packet trips the freshness gate.
func (s *demoServer) recordVerdict(sessionHex, gameHashHex, verdict, license string,
	hdr *lachHeader,
) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	if sessionHex != "" {
		st, ok := s.sessions[sessionHex]
		if !ok {
			st = &sessionState{gameIDHex: gameHashHex}
			s.sessions[sessionHex] = st
		}
		st.lastVerdict = verdict
		st.lastLicense = license
		st.updatedAt = now
		if hdr != nil {
			st.lastSeq = hdr.sequence
			st.lastTimestamp = hdr.timestamp
		}
	}
	if gameHashHex != "" {
		s.verdict[gameHashHex] = &sessionState{
			lastVerdict: verdict,
			lastLicense: license,
			updatedAt:   now,
			gameIDHex:   gameHashHex,
		}
	}
}
