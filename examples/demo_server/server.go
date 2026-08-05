// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	maxRequestBody = 1 << 16
	verdictTrusted = "TRUSTED"
	verdictUntrust = "UNTRUSTED"
	verdictReject  = "REJECT"
)

// gameBinding is the demo's representation of an accepted game: the
// SHA-256 over the game-binding domain string and the game_id (the
// same hash trust_pong's heartbeat producer stamps into LACH headers)
// plus the license string the server returns on the TRUSTED path.
type gameBinding struct {
	gameID         string
	gameIDHash     [32]byte
	runtimeMeasure [32]byte
	licenseID      string
}

// sessionState tracks the most recent verdict the server saw for a
// single anti-cheat session id (16 bytes from the LACH header). The
// store is intentionally a flat in-memory map: the demo never has to
// survive a restart and the operator can clear state by restarting
// the binary.
type sessionState struct {
	lastSeq       uint32
	lastTimestamp uint64
	lastVerdict   string
	lastLicense   string
	gameIDHex     string
	updatedAt     time.Time
}

type demoServer struct {
	aik             *rsa.PublicKey
	games           map[string]gameBinding // keyed by game_id
	gamesByHash     map[[32]byte]gameBinding
	maxHeartbeatAge time.Duration

	mu       sync.Mutex
	sessions map[string]*sessionState // keyed by hex(session_id)
	verdict  map[string]*sessionState // keyed by hex(game_id_hash)
}

func newServer(aik *rsa.PublicKey, games map[string]gameBinding,
	maxAge time.Duration,
) (*demoServer, error) {
	if len(games) == 0 {
		return nil, errors.New("no expected games configured")
	}
	byHash := make(map[[32]byte]gameBinding, len(games))
	for _, g := range games {
		byHash[g.gameIDHash] = g
	}
	if maxAge <= 0 {
		maxAge = 300 * time.Second
	}
	return &demoServer{
		aik:             aik,
		games:           games,
		gamesByHash:     byHash,
		maxHeartbeatAge: maxAge,
		sessions:        make(map[string]*sessionState),
		verdict:         make(map[string]*sessionState),
	}, nil
}

// nonceRequest is the body of POST /nonce.
type nonceRequest struct {
	GameID string `json:"game_id"`
}

type nonceResponse struct {
	SessionID string `json:"session_id"`
	Nonce     string `json:"nonce"` // base64-encoded 32 bytes
	License   string `json:"license"`
}

func (s *demoServer) handleNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req nonceRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
	}
	if req.GameID == "" {
		req.GameID = defaultGameID
	}
	game, ok := s.games[req.GameID]
	if !ok {
		http.Error(w, "unknown game_id", http.StatusForbidden)
		return
	}

	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		http.Error(w, "rng failure", http.StatusInternalServerError)
		return
	}

	resp := nonceResponse{
		SessionID: uuid.NewString(),
		Nonce:     base64.StdEncoding.EncodeToString(nonce[:]),
		License:   game.licenseID,
	}
	logf("session=%s game=%s state=NONCE_ISSUED", resp.SessionID, game.gameID)
	writeJSON(w, http.StatusOK, resp)
}

type heartbeatResponse struct {
	State   string `json:"state"`
	License string `json:"license,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type stateResponse struct {
	GameID    string `json:"game_id"`
	State     string `json:"state"`
	License   string `json:"license,omitempty"`
	UpdatedAt int64  `json:"updated_at_unix"`
}

func (s *demoServer) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	gameID := r.URL.Query().Get("game_id")
	if gameID == "" {
		gameID = defaultGameID
	}
	game, ok := s.games[gameID]
	if !ok {
		http.Error(w, "unknown game_id", http.StatusNotFound)
		return
	}
	hashHex := hex.EncodeToString(game.gameIDHash[:])

	s.mu.Lock()
	st, present := s.verdict[hashHex]
	s.mu.Unlock()

	resp := stateResponse{GameID: gameID}
	if present {
		resp.State = st.lastVerdict
		resp.License = st.lastLicense
		resp.UpdatedAt = st.updatedAt.Unix()
	} else {
		resp.State = "PENDING"
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		// status line is already written, so there is nothing left
		// to tell the client; say it where the operator can see it.
		logf("write response: %v", err)
	}
}

func logf(format string, args ...any) {
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	fmt.Printf("[%s] %s\n", stamp, fmt.Sprintf(format, args...))
}

// parseExpectedGames accepts a comma-separated list of game_id=license
// entries. Returns an error if the list is empty or any entry is
// missing a license string. The game-binding hash is derived from the
// game_id with the same SDK domain string the C heartbeat producer
// stamps into the LACH header, mixed with the producer binary's
// SHA-256 (passed as anticheatExeDigest) so the verdict map keys
// reproduce lota_ac_compute_game_binding_hash() byte for byte.
func parseExpectedGames(spec string, anticheatExeDigest [32]byte,
	runtimeMeasure [32]byte,
) (map[string]gameBinding, error) {
	out := make(map[string]gameBinding)
	for raw := range strings.SplitSeq(spec, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		kv := strings.SplitN(entry, "=", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			return nil, fmt.Errorf("entry %q must be game_id=license", entry)
		}
		gid := kv[0]
		out[gid] = gameBinding{
			gameID:         gid,
			gameIDHash:     computeGameBindingHash(gid, anticheatExeDigest),
			runtimeMeasure: runtimeMeasure,
			licenseID:      kv[1],
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no entries")
	}
	return out, nil
}

// computeGameBindingHash reproduces the SDK-side game-binding domain
// hash that lota_ac_compute_game_binding_hash() (src/sdk/lota_anticheat.c)
// stamps into the LACH header. The C helper hashes
//
//	SHA-256("lota-ac-game-binding:v2" || 0x00 || game_id || sha256(exe))
//
// using the LOTA_AC_DOMAIN_VERSION_V1 entry of lota_ac_domain_table.
// The Go derivation must mirror it byte for byte or the server keys
// its verdict map by a hash the producer never sends, which surfaces
// as state=UNTRUSTED reason="unknown game_id_hash" on a clean run.
func computeGameBindingHash(gameID string, exeDigest [32]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("lota-ac-game-binding:v2"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(gameID))
	_, _ = h.Write(exeDigest[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// parseAIKBytes accepts either a raw DER PKIX/SPKI blob or the PEM
// wrapper produced by `openssl rsa -pubout`. The function rejects any
// key smaller than RSA-2048 so a demo operator cannot accidentally
// bring up a server that accepts weak keys.
func parseAIKBytes(blob []byte) (*rsa.PublicKey, error) {
	der := blob
	if block, _ := pem.Decode(blob); block != nil {
		der = block.Bytes
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("AIK key is not RSA")
	}
	if rsaPub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("AIK key %d bits, minimum 2048", rsaPub.N.BitLen())
	}
	return rsaPub, nil
}
