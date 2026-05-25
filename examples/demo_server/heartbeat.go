// SPDX-License-Identifier: MIT

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	verifysdk "github.com/szymonwilczek/lota/sdk/server"
)

// LACH wire constants. Mirror include/lota_anticheat.h. Any drift is
// caught by the test suite which fabricates packets with these exact
// offsets.
const (
	lachMagic         uint32 = 0x4C414348 // 'LACH'
	lachVersion       uint8  = 2
	lachHeaderSize           = 78
	lachSessionIDSize        = 16
	lachGameHashSize         = 32
	lachMaxToken             = 1608
	lachMaxPacket            = lachHeaderSize + lachMaxToken

	heartbeatNonceDomainV1 = "lota-ac-heartbeat:v1\x00"
	domainVersionV1        = 1
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

	if hdr.domainVersion != domainVersionV1 {
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
	_, _ = h.Write([]byte(heartbeatNonceDomainV1))
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
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
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
	hdr *lachHeader) {
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
