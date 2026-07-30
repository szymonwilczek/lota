// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	verifysdk "github.com/szymonwilczek/lota/sdk/server"
)

// Attestation flags a token can carry, from include/lota_gaming.h.
// Gate's policy is expressed as a required subset of these.
const (
	flagAttested   uint32 = 1 << 0
	flagTPMOK      uint32 = 1 << 1
	flagIOMMUOK    uint32 = 1 << 2
	flagBPFLoaded  uint32 = 1 << 3
	flagSecureBoot uint32 = 1 << 4
)

var flagNames = map[string]uint32{
	"attested":   flagAttested,
	"tpm":        flagTPMOK,
	"iommu":      flagIOMMUOK,
	"bpf":        flagBPFLoaded,
	"secureboot": flagSecureBoot,
}

// parseFlags turns the --require list into a mask.
func parseFlags(list string) (uint32, error) {
	var mask uint32
	for name := range strings.SplitSeq(list, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		bit, ok := flagNames[name]
		if !ok {
			return 0, fmt.Errorf("unknown flag %q", name)
		}
		mask |= bit
	}
	return mask, nil
}

func flagList(mask uint32) string {
	var names []string
	for _, name := range []string{"attested", "tpm", "iommu", "bpf", "secureboot"} {
		if mask&flagNames[name] != 0 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}

// gate is the relying party:
// it decides whether the caller's host is trustworthy enough to receive
// the secret it is guarding.
type gate struct {
	aik      *rsa.PublicKey
	secret   []byte
	required uint32
	maxLife  time.Duration
	nonces   *nonceStore
	audit    *log.Logger
}

type nonceResponse struct {
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"expires_at"`
}

type releaseRequest struct {
	Nonce string `json:"nonce"`
	Token string `json:"token"`
}

type releaseResponse struct {
	Secret string `json:"secret,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func (g *gate) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /nonce", g.handleNonce)
	mux.HandleFunc("POST /release", g.handleRelease)
	return mux
}

func (g *gate) handleNonce(w http.ResponseWriter, _ *http.Request) {
	nonce, expires, err := g.nonces.issue()
	if err != nil {
		http.Error(w, "cannot issue a nonce", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, nonceResponse{
		Nonce:     base64.StdEncoding.EncodeToString(nonce[:]),
		ExpiresAt: expires.Unix(),
	})
}

// handleRelease is the gate proper.
// Every path out of it either releases the secret or states a reason,
// and the reason is what a pipeline log will carry,
// so it names the check that failed rather than "denied".
func (g *gate) handleRelease(w http.ResponseWriter, r *http.Request) {
	var req releaseRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).
		Decode(&req); err != nil {
		g.deny(w, "", "malformed request: "+err.Error())
		return
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil || len(nonceBytes) != 32 {
		g.deny(w, "", "nonce is not 32 base64-encoded bytes")
		return
	}
	tokenBytes, err := base64.StdEncoding.DecodeString(req.Token)
	if err != nil || len(tokenBytes) == 0 {
		g.deny(w, "", "token is not base64-encoded")
		return
	}

	var nonce [32]byte
	copy(nonce[:], nonceBytes)

	// Spend the nonce before verifying,
	// so a caller cannot retry a captured token against the same challenge.
	if err := g.nonces.consume(nonce); err != nil {
		g.deny(w, req.Nonce, err.Error())
		return
	}

	claims, err := verifysdk.VerifyToken(tokenBytes, g.aik, nonce[:])
	if err != nil {
		g.deny(w, req.Nonce, "token verification failed: "+err.Error())
		return
	}

	// VerifyToken proves the token is this TPM's and answers this challenge.
	// What the host must additionally be is the gate's own policy, checked below.
	if !constantTimeEqual(claims.Nonce[:], nonce[:]) {
		g.deny(w, req.Nonce, "verified token carries a different nonce")
		return
	}

	if missing := g.required &^ claims.Flags; missing != 0 {
		g.deny(w, req.Nonce, "host is missing required state: "+flagList(missing))
		return
	}

	// Token carries an expiry, not an issue time, so freshness past
	// valid_until is this gate's policy:
	// refuse a token whose remaining life is longer than a token the agent
	// would mint now, which is what replayed long-lived token from another
	// host would look like.
	if g.maxLife > 0 {
		remaining := time.Until(claims.ExpiresAt)
		if remaining > g.maxLife {
			g.deny(w, req.Nonce, fmt.Sprintf(
				"token outlives the gate's window: %s remaining, limit %s",
				remaining.Truncate(time.Second), g.maxLife))
			return
		}
	}

	g.audit.Printf("release granted nonce=%s flags=[%s] expires_at=%s",
		shortNonce(req.Nonce), flagList(claims.Flags),
		claims.ExpiresAt.UTC().Format(time.RFC3339))

	writeJSON(w, http.StatusOK, releaseResponse{
		Secret: base64.StdEncoding.EncodeToString(g.secret),
	})
}

// deny is the only way this service says no,
// so every refusal is audited and none of them leaks the secret through a partial response.
func (g *gate) deny(w http.ResponseWriter, nonce, reason string) {
	g.audit.Printf("release refused nonce=%s reason=%q", shortNonce(nonce), reason)
	writeJSON(w, http.StatusForbidden, releaseResponse{Reason: reason})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// shortNonce keeps audit line readable and correlatable without writing the whole
// challenge into a log a pipeline may publish.
func shortNonce(nonce string) string {
	if len(nonce) > 12 {
		return nonce[:12] + "..."
	}
	if nonce == "" {
		return "-"
	}
	return nonce
}
