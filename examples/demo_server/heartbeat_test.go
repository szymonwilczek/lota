// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	verifysdk "github.com/szymonwilczek/lota/sdk/server"
)

const testGameID = "trust-pong"
const testLicense = "lota-demo-CS2-clone"

func newTestServer(t *testing.T, key *rsa.PrivateKey) *demoServer {
	t.Helper()
	games, err := parseExpectedGames(testGameID + "=" + testLicense)
	if err != nil {
		t.Fatalf("parseExpectedGames: %v", err)
	}
	var pub *rsa.PublicKey
	if key != nil {
		pub = &key.PublicKey
	}
	s, err := newServer(pub, games, 5*time.Minute)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	return s
}

func newSignedHeartbeat(t *testing.T, key *rsa.PrivateKey,
	mutate func(h *lachHeader)) []byte {
	t.Helper()

	hdr := &lachHeader{
		magic:         lachMagic,
		version:       lachVersion,
		provider:      1,
		sessionID:     [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		sequence:      1,
		lotaFlags:     0x07,
		timestamp:     uint64(time.Now().Unix()),
		gameIDHash:    computeGameBindingHash(testGameID),
		domainVersion: domainVersionV1,
	}
	if mutate != nil {
		mutate(hdr)
	}

	heartbeatNonce := computeHeartbeatNonce(hdr)
	validUntil := uint64(time.Now().Add(5 * time.Minute).Unix())
	pcrMask := uint32(0x4001)
	policyDigest := [32]byte{0xA1, 0xB2, 0xC3}
	runtimeDigest := runtimeProtectDigest(nil)

	pcrDigest := make([]byte, 32)
	for i := range pcrDigest {
		pcrDigest[i] = byte(i)
	}

	expectedTPMNonce := verifysdk.ComputeTokenQuoteNonce(validUntil,
		hdr.lotaFlags, pcrMask, heartbeatNonce, policyDigest, runtimeDigest, 0)

	attest := buildFakeTPMSAttest(expectedTPMNonce[:], pcrMask, pcrDigest)
	hash := sha256.Sum256(attest)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	token, err := verifysdk.SerializeToken(validUntil, hdr.lotaFlags,
		heartbeatNonce, 0x0014, 0x000B, pcrMask, policyDigest, runtimeDigest,
		nil, attest, sig)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	pkt := make([]byte, lachHeaderSize+len(token))
	binary.LittleEndian.PutUint32(pkt[0:4], hdr.magic)
	pkt[4] = hdr.version
	pkt[5] = hdr.provider
	binary.LittleEndian.PutUint16(pkt[6:8], uint16(len(pkt)))
	copy(pkt[8:24], hdr.sessionID[:])
	binary.LittleEndian.PutUint32(pkt[24:28], hdr.sequence)
	binary.LittleEndian.PutUint32(pkt[28:32], hdr.lotaFlags)
	binary.LittleEndian.PutUint64(pkt[32:40], hdr.timestamp)
	copy(pkt[40:72], hdr.gameIDHash[:])
	binary.LittleEndian.PutUint16(pkt[72:74], uint16(len(token)))
	binary.LittleEndian.PutUint32(pkt[74:78], hdr.domainVersion)
	copy(pkt[lachHeaderSize:], token)
	hdr.totalSize = uint16(len(pkt))
	hdr.tokenSize = uint16(len(token))
	return pkt
}

func runtimeProtectDigest(pids []uint32) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("lota-runtime-protect-pids:v1\x00"))
	var le [4]byte
	binary.LittleEndian.PutUint32(le[:], uint32(len(pids)))
	_, _ = h.Write(le[:])
	for _, pid := range pids {
		binary.LittleEndian.PutUint32(le[:], pid)
		_, _ = h.Write(le[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func buildFakeTPMSAttest(extraData []byte, pcrMask uint32, pcrDigest []byte) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint32(b, 0xff544347)
	b = binary.BigEndian.AppendUint16(b, 0x8018)
	b = binary.BigEndian.AppendUint16(b, 4)
	b = append(b, 0x00, 0x0B, 0xAA, 0xBB)
	b = binary.BigEndian.AppendUint16(b, uint16(len(extraData)))
	b = append(b, extraData...)
	b = append(b, make([]byte, 17)...)
	b = append(b, make([]byte, 8)...)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = binary.BigEndian.AppendUint16(b, 0x000B)
	b = append(b, 3)
	b = append(b, byte(pcrMask), byte(pcrMask>>8), byte(pcrMask>>16))
	b = binary.BigEndian.AppendUint16(b, uint16(len(pcrDigest)))
	b = append(b, pcrDigest...)
	return b
}

func postHeartbeat(s *demoServer, body []byte) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/heartbeat", bytes.NewReader(body))
	s.handleHeartbeat(w, r)
	return w
}

func decodeVerdict(t *testing.T, w *httptest.ResponseRecorder) heartbeatResponse {
	t.Helper()
	var resp heartbeatResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v (body=%q)", err, w.Body.String())
	}
	return resp
}

func TestHeartbeat_TrustedPath(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	s := newTestServer(t, key)
	pkt := newSignedHeartbeat(t, key, nil)

	w := postHeartbeat(s, pkt)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	resp := decodeVerdict(t, w)
	if resp.State != verdictTrusted {
		t.Fatalf("state=%s reason=%s", resp.State, resp.Reason)
	}
	if resp.License != testLicense {
		t.Fatalf("license=%q want %q", resp.License, testLicense)
	}
}

func TestHeartbeat_UntrustedOnSignatureFromOtherKey(t *testing.T) {
	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	attackerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := newTestServer(t, serverKey)

	pkt := newSignedHeartbeat(t, attackerKey, nil)
	resp := decodeVerdict(t, postHeartbeat(s, pkt))
	if resp.State != verdictUntrust {
		t.Fatalf("state=%s want UNTRUSTED reason=%s", resp.State, resp.Reason)
	}
	if !strings.Contains(resp.Reason, "signature") {
		t.Fatalf("reason=%q does not mention signature", resp.Reason)
	}
}

func TestHeartbeat_UntrustedOnUnknownGameHash(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := newTestServer(t, key)

	pkt := newSignedHeartbeat(t, key, func(h *lachHeader) {
		for i := range h.gameIDHash {
			h.gameIDHash[i] = 0xFF
		}
	})
	resp := decodeVerdict(t, postHeartbeat(s, pkt))
	if resp.State != verdictUntrust || resp.Reason != "unknown game_id_hash" {
		t.Fatalf("state=%s reason=%q", resp.State, resp.Reason)
	}
}

func TestHeartbeat_UntrustedOnTamperedHeader(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := newTestServer(t, key)

	pkt := newSignedHeartbeat(t, key, nil)
	// flip the sequence field after signing: the nonce binding falls apart.
	binary.LittleEndian.PutUint32(pkt[24:28], 999)

	resp := decodeVerdict(t, postHeartbeat(s, pkt))
	if resp.State != verdictUntrust {
		t.Fatalf("state=%s reason=%s", resp.State, resp.Reason)
	}
}

func TestHeartbeat_UntrustedOnFlagMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := newTestServer(t, key)
	pkt := newSignedHeartbeat(t, key, nil)
	// rewrite header flags so they differ from the signed token, but keep
	// the rest of the nonce-bound fields intact. Verification of the token
	// itself succeeds (the producer used the original flags for the
	// nonce binding too, so flipping the header alone changes nothing
	// in the signed payload); the demo server then catches the
	// mismatch in its post-verify guard.
	hdr, _, err := parseHeartbeat(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	hdr.lotaFlags ^= 0x01
	binary.LittleEndian.PutUint32(pkt[28:32], hdr.lotaFlags)

	resp := decodeVerdict(t, postHeartbeat(s, pkt))
	if resp.State != verdictUntrust {
		t.Fatalf("state=%s reason=%s", resp.State, resp.Reason)
	}
}

func TestHeartbeat_RejectOnBadMagic(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := newTestServer(t, key)

	pkt := newSignedHeartbeat(t, key, nil)
	binary.LittleEndian.PutUint32(pkt[0:4], 0xDEADBEEF)

	w := postHeartbeat(s, pkt)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", w.Code)
	}
	resp := decodeVerdict(t, w)
	if resp.State != verdictReject {
		t.Fatalf("state=%s want REJECT", resp.State)
	}
}

func TestHeartbeat_RejectOnUnsupportedDomainVersion(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := newTestServer(t, key)

	pkt := newSignedHeartbeat(t, key, nil)
	binary.LittleEndian.PutUint32(pkt[74:78], 999)
	resp := decodeVerdict(t, postHeartbeat(s, pkt))
	if resp.State != verdictReject {
		t.Fatalf("state=%s", resp.State)
	}
}

func TestHeartbeat_RejectOnTokenSizeMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := newTestServer(t, key)

	pkt := newSignedHeartbeat(t, key, nil)
	binary.LittleEndian.PutUint16(pkt[72:74], 1)
	resp := decodeVerdict(t, postHeartbeat(s, pkt))
	if resp.State != verdictReject {
		t.Fatalf("state=%s", resp.State)
	}
}

func TestHeartbeat_UntrustedOnReplay(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := newTestServer(t, key)

	first := newSignedHeartbeat(t, key, nil)
	if r := decodeVerdict(t, postHeartbeat(s, first)); r.State != verdictTrusted {
		t.Fatalf("first state=%s", r.State)
	}

	// replay the exact same packet: same sequence, same session.
	replay := decodeVerdict(t, postHeartbeat(s, first))
	if replay.State != verdictUntrust {
		t.Fatalf("replay state=%s reason=%s", replay.State, replay.Reason)
	}
}

func TestNonce_IssuesUniqueSessionAndNonce(t *testing.T) {
	s := newTestServer(t, nil)

	body := strings.NewReader(`{"game_id":"trust-pong"}`)
	r := httptest.NewRequest(http.MethodPost, "/nonce", body)
	w := httptest.NewRecorder()
	s.handleNonce(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	var resp nonceResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.License != testLicense || resp.SessionID == "" || len(resp.Nonce) < 40 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestNonce_RejectsUnknownGame(t *testing.T) {
	s := newTestServer(t, nil)
	body := strings.NewReader(`{"game_id":"hl3"}`)
	r := httptest.NewRequest(http.MethodPost, "/nonce", body)
	w := httptest.NewRecorder()
	s.handleNonce(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestState_TracksMostRecentVerdict(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := newTestServer(t, key)

	// pending before any heartbeat
	r := httptest.NewRequest(http.MethodGet, "/state?game_id="+testGameID, nil)
	w := httptest.NewRecorder()
	s.handleState(w, r)
	var st stateResponse
	if err := json.NewDecoder(w.Body).Decode(&st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.State != "PENDING" {
		t.Fatalf("expected PENDING before heartbeat, got %s", st.State)
	}

	// after a TRUSTED heartbeat the state advances
	pkt := newSignedHeartbeat(t, key, nil)
	_ = decodeVerdict(t, postHeartbeat(s, pkt))

	r = httptest.NewRequest(http.MethodGet, "/state?game_id="+testGameID, nil)
	w = httptest.NewRecorder()
	s.handleState(w, r)
	if err := json.NewDecoder(w.Body).Decode(&st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.State != verdictTrusted || st.License != testLicense {
		t.Fatalf("state=%s license=%s", st.State, st.License)
	}
}
