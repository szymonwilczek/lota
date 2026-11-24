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

// gameBinding is an accepted game: the binding hash its producer stamps into
// the LACH header, the runtime measurement a matching producer reports and
// the license returned on TRUSTED.
type gameBinding struct {
	gameID         string
	gameIDHash     [32]byte
	runtimeMeasure [32]byte
	licenseID      string
}

// sessionState is the latest verdict for one session or one game,
// held in memory only.
type sessionState struct {
	lastSeq       uint32
	lastTimestamp uint64
	lastVerdict   string
	lastLicense   string
	lastReason    string // repeated by /state, empty when trusted
	updatedAt     time.Time
}

type demoServer struct {
	aik             *rsa.PublicKey
	games           map[string]gameBinding // keyed by game_id
	gamesByHash     map[[32]byte]gameBinding
	maxHeartbeatAge time.Duration

	// token flags the publisher demands; missing one makes UNTRUSTED
	requiredFlags uint32

	mu       sync.Mutex
	sessions map[string]*sessionState // keyed by hex(session_id)
	verdict  map[string]*sessionState // keyed by hex(game_id_hash)
}

func newServer(aik *rsa.PublicKey, games map[string]gameBinding,
	maxAge time.Duration, requiredFlags uint32,
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
		requiredFlags:   requiredFlags,
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
	Reason    string `json:"reason,omitempty"`
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
		resp.Reason = st.lastReason
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
		// the status line is out; only the log can carry the error
		logf("write response: %v", err)
	}
}

func logf(format string, args ...any) {
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	fmt.Printf("[%s] %s\n", stamp, fmt.Sprintf(format, args...))
}

// parseExpectedGames parses comma-separated game_id=license entries and
// binds each game_id to anticheatExeDigest as the producer does.
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

// computeGameBindingHash mirrors lota_ac_compute_game_binding_hash():
//
//	SHA-256("lota-ac-game-binding:v1" || 0x00 || game_id || sha256(exe))
//
// A mismatch is answered "unknown game_id_hash".
func computeGameBindingHash(gameID string, exeDigest [32]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("lota-ac-game-binding:v1"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(gameID))
	_, _ = h.Write(exeDigest[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// parseAIKBytes reads a PKIX RSA key in DER or PEM and refuses one under
// 2048 bits.
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
