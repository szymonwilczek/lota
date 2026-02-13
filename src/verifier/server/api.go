// SPDX-License-Identifier: MIT
// LOTA Verifier - REST Monitoring API
//
// HTTP endpoints for monitoring and health checking:
//   GET /health              - Load balancer health check
//   GET /api/v1/stats        - Verification statistics
//   GET /api/v1/clients      - List registered clients
//   GET /api/v1/clients/{id} - Per-client details
//   GET /metrics             - Prometheus-compatible metrics

package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// serves the monitoring REST API
type APIHandler struct {
	verifier       *verify.Verifier
	server         *Server
	auditLog       store.AuditLog
	attestationLog store.AttestationLog
	log            *slog.Logger
	metrics        *metrics.Metrics
	startTime      time.Time
	adminAPIKey    string // if non-empty, required for mutating endpoints
	readerAPIKey   string // if non-empty, required for sensitive read-only endpoints
}

// creates a new API handler and registers routes on the given mux
// adminAPIKey controls access to mutating endpoints (revoke, ban):
//   - non-empty: requires Authorization: Bearer <key> header
//   - empty: all mutating endpoints return 403
//
// readerAPIKey controls access to sensitive read-only endpoints:
//   - non-empty: requires Authorization: Bearer <reader-key|admin-key>
//   - empty: sensitive read-only endpoints are public (not recommended)
func NewAPIHandler(mux *http.ServeMux, verifier *verify.Verifier, srv *Server, auditLog store.AuditLog, logger *slog.Logger, m *metrics.Metrics, attestLog store.AttestationLog, adminAPIKey string, readerAPIKey string) *APIHandler {
	if logger == nil {
		logger = logging.Nop()
	}
	if m == nil {
		m = metrics.New()
	}

	h := &APIHandler{
		verifier:       verifier,
		server:         srv,
		auditLog:       auditLog,
		attestationLog: attestLog,
		log:            logger.With("component", "api"),
		metrics:        m,
		startTime:      time.Now(),
		adminAPIKey:    adminAPIKey,
		readerAPIKey:   readerAPIKey,
	}

	// public monitoring endpoints (no auth required)
	mux.HandleFunc("GET /health", h.handleHealth)
	mux.HandleFunc("GET /api/v1/stats", h.handleStats)
	mux.HandleFunc("GET /metrics", h.handleMetrics)

	// sensitive read-only endpoints (reader or admin auth required)
	mux.HandleFunc("GET /api/v1/clients", h.requireReader(h.handleListClients))
	mux.HandleFunc("GET /api/v1/clients/", h.requireReader(h.handleClientInfo))
	mux.HandleFunc("GET /api/v1/revocations", h.requireReader(h.handleListRevocations))
	mux.HandleFunc("GET /api/v1/bans", h.requireReader(h.handleListBans))
	mux.HandleFunc("GET /api/v1/audit", h.requireReader(h.handleAuditLog))
	mux.HandleFunc("GET /api/v1/attestations", h.requireReader(h.handleAttestationLog))

	// revocation management (admin auth required)
	mux.HandleFunc("POST /api/v1/clients/", h.requireAdmin(h.handleClientAction))
	mux.HandleFunc("DELETE /api/v1/clients/", h.requireAdmin(h.handleClientAction))

	// hardware ban management (admin auth required)
	mux.HandleFunc("POST /api/v1/bans", h.requireAdmin(h.handleBanHardware))
	mux.HandleFunc("DELETE /api/v1/bans/", h.requireAdmin(h.handleUnbanHardware))

	return h
}

// wraps a handler with Bearer token authentication
// if no admin API key is configured, all mutating requests are rejected
func (h *APIHandler) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.adminAPIKey == "" {
			h.log.Warn("admin endpoint called but no API key configured",
				"method", r.Method, "path", r.URL.Path,
				"remote_addr", r.RemoteAddr)
			w.WriteHeader(http.StatusForbidden)
			writeJSON(w, errorResponse{Error: "admin API key not configured"})
			return
		}

		token := extractBearerToken(r)
		if token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="lota-admin"`)
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, errorResponse{Error: "missing Authorization header"})
			return
		}

		// constant-time comparison to prevent timing side-channels
		if subtle.ConstantTimeCompare([]byte(token), []byte(h.adminAPIKey)) != 1 {
			logging.Security(h.log, "admin auth failed",
				"method", r.Method, "path", r.URL.Path,
				"remote_addr", r.RemoteAddr)
			w.WriteHeader(http.StatusForbidden)
			writeJSON(w, errorResponse{Error: "invalid API key"})
			return
		}

		next(w, r)
	}
}

// wraps a handler with reader-level authentication
// accepts either the reader API key or the admin API key
// if no reader key is configured, the endpoint is public
func (h *APIHandler) requireReader(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.readerAPIKey == "" {
			// endpoint is public
			next(w, r)
			return
		}

		token := extractBearerToken(r)
		if token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="lota"`)
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, errorResponse{Error: "missing Authorization header"})
			return
		}

		readerOK := h.readerAPIKey != "" &&
			subtle.ConstantTimeCompare([]byte(token), []byte(h.readerAPIKey)) == 1
		adminOK := h.adminAPIKey != "" &&
			subtle.ConstantTimeCompare([]byte(token), []byte(h.adminAPIKey)) == 1

		if !readerOK && !adminOK {
			logging.Security(h.log, "reader auth failed",
				"method", r.Method, "path", r.URL.Path,
				"remote_addr", r.RemoteAddr)
			w.WriteHeader(http.StatusForbidden)
			writeJSON(w, errorResponse{Error: "invalid API key"})
			return
		}

		next(w, r)
	}
}

// extracts the Bearer token from the Authorization header
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(auth[len(prefix):])
}

// response structs (JSON serialization)
type healthResponse struct {
	Status    string `json:"status"`
	Uptime    string `json:"uptime"`
	UptimeSec int64  `json:"uptime_sec"`
	TLS       struct {
		Listening bool   `json:"listening"`
		Address   string `json:"address"`
	} `json:"tls"`
}

type statsResponse struct {
	PendingChallenges int      `json:"pending_challenges"`
	UsedNonces        int      `json:"used_nonces"`
	RegisteredClients int      `json:"registered_clients"`
	ActivePolicy      string   `json:"active_policy"`
	LoadedPolicies    []string `json:"loaded_policies"`
	TotalAttestations int64    `json:"total_attestations"`
	SuccessfulAttests int64    `json:"successful_attestations"`
	FailedAttests     int64    `json:"failed_attestations"`
	RevokedAttests    int64    `json:"revoked_attestations"`
	BannedAttests     int64    `json:"banned_attestations"`
	ActiveRevocations int      `json:"active_revocations"`
	ActiveBans        int      `json:"active_bans"`
	Uptime            string   `json:"uptime"`
	UptimeSec         int64    `json:"uptime_sec"`
}

type clientListResponse struct {
	Clients []string `json:"clients"`
	Count   int      `json:"count"`
}

type clientInfoResponse struct {
	ClientID          string `json:"client_id"`
	HasAIK            bool   `json:"has_aik"`
	HardwareID        string `json:"hardware_id,omitempty"`
	Revoked           bool   `json:"revoked"`
	RevocationReason  string `json:"revocation_reason,omitempty"`
	LastAttestation   string `json:"last_attestation,omitempty"`
	LastAttestUnix    int64  `json:"last_attestation_unix,omitempty"`
	AttestCount       uint64 `json:"attestation_count"`
	MonotonicCounter  uint64 `json:"monotonic_counter"`
	PendingChallenges int    `json:"pending_challenges"`
	PCR14Baseline     string `json:"pcr14_baseline,omitempty"`
	FirstSeen         string `json:"first_seen,omitempty"`
	FirstSeenUnix     int64  `json:"first_seen_unix,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// health check for load balancers
// returns 200 if the verifier is healthy and accepting connections
func (h *APIHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := h.server.HealthCheck()

	resp := healthResponse{
		Status:    "ok",
		Uptime:    time.Since(h.startTime).Truncate(time.Second).String(),
		UptimeSec: int64(time.Since(h.startTime).Seconds()),
	}
	resp.TLS.Listening = health.Listening
	resp.TLS.Address = health.Address

	if !health.Listening {
		resp.Status = "degraded"
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, resp)
		return
	}

	writeJSON(w, resp)
}

// GET /api/v1/stats - verification engine statistics
func (h *APIHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := h.verifier.Stats()

	resp := statsResponse{
		PendingChallenges: stats.PendingChallenges,
		UsedNonces:        stats.UsedNonces,
		RegisteredClients: stats.RegisteredClients,
		ActivePolicy:      stats.ActivePolicy,
		LoadedPolicies:    stats.LoadedPolicies,
		TotalAttestations: stats.TotalAttestations,
		SuccessfulAttests: stats.SuccessAttests,
		FailedAttests:     stats.FailedAttests,
		RevokedAttests:    stats.RevokedAttests,
		BannedAttests:     stats.BannedAttests,
		ActiveRevocations: stats.ActiveRevocations,
		ActiveBans:        stats.ActiveBans,
		Uptime:            stats.Uptime.Truncate(time.Second).String(),
		UptimeSec:         int64(stats.Uptime.Seconds()),
	}

	if resp.LoadedPolicies == nil {
		resp.LoadedPolicies = []string{}
	}

	writeJSON(w, resp)
}

// GET /api/v1/clients - list all registered clients
func (h *APIHandler) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients := h.verifier.ListClients()

	if clients == nil {
		clients = []string{}
	}

	resp := clientListResponse{
		Clients: clients,
		Count:   len(clients),
	}

	writeJSON(w, resp)
}

// GET /api/v1/clients/{id} - per-client attestation details
func (h *APIHandler) handleClientInfo(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	clientID := strings.TrimRight(path, "/")

	if clientID == "" {
		h.handleListClients(w, r)
		return
	}

	info, found := h.verifier.ClientInfo(clientID)
	if !found {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, errorResponse{Error: "client not found"})
		return
	}

	resp := clientInfoResponse{
		ClientID:          info.ClientID,
		HasAIK:            info.HasAIK,
		HardwareID:        info.HardwareID,
		Revoked:           info.Revoked,
		RevocationReason:  info.RevocationReason,
		AttestCount:       info.AttestCount,
		MonotonicCounter:  info.MonotonicCounter,
		PendingChallenges: info.PendingChallenges,
		PCR14Baseline:     info.PCR14Baseline,
	}

	if !info.LastAttestation.IsZero() {
		resp.LastAttestation = info.LastAttestation.UTC().Format(time.RFC3339)
		resp.LastAttestUnix = info.LastAttestation.Unix()
	}
	if !info.FirstSeen.IsZero() {
		resp.FirstSeen = info.FirstSeen.UTC().Format(time.RFC3339)
		resp.FirstSeenUnix = info.FirstSeen.Unix()
	}

	writeJSON(w, resp)
}

// GET /metrics - Prometheus text exposition format
func (h *APIHandler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// sync gauges from verifier stats before export
	stats := h.verifier.Stats()
	h.metrics.PendingChallenges.Store(int64(stats.PendingChallenges))
	h.metrics.RegisteredClients.Store(int64(stats.RegisteredClients))
	h.metrics.ActiveRevocations.Store(int64(stats.ActiveRevocations))
	h.metrics.ActiveBans.Store(int64(stats.ActiveBans))
	h.metrics.UsedNonces.Store(int64(stats.UsedNonces))
	h.metrics.LoadedPolicies.Store(int64(len(stats.LoadedPolicies)))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprint(w, h.metrics.Export())
}

// JSON request for revoke/unrevoke actions
type revokeRequest struct {
	Reason string `json:"reason"` // cheating|compromised|hardware_change|admin
	Actor  string `json:"actor"`  // administrator identifier
	Note   string `json:"note"`   // free-form justification
}

// JSON response for revocation entries
type revocationResponse struct {
	ClientID  string `json:"client_id"`
	Reason    string `json:"reason"`
	RevokedAt string `json:"revoked_at"`
	RevokedBy string `json:"revoked_by"`
	Note      string `json:"note"`
}

// handles POST/DELETE on /api/v1/clients/{id}/revoke
func (h *APIHandler) handleClientAction(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	parts := strings.SplitN(path, "/", 2)

	clientID := parts[0]
	if clientID == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, errorResponse{Error: "missing client ID"})
		return
	}

	// determine sub-action
	action := ""
	if len(parts) > 1 {
		action = strings.TrimRight(parts[1], "/")
	}

	switch {
	case action == "revoke" && r.Method == http.MethodPost:
		h.handleRevokeClient(w, r, clientID)
	case action == "revoke" && r.Method == http.MethodDelete:
		h.handleUnrevokeClient(w, r, clientID)
	default:
		if r.Method == http.MethodGet {
			h.handleClientInfo(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, errorResponse{Error: "unknown action"})
	}
}

// POST /api/v1/clients/{id}/revoke - revoke a client's AIK
func (h *APIHandler) handleRevokeClient(w http.ResponseWriter, r *http.Request, clientID string) {
	revStore := h.verifier.RevocationStore()
	if revStore == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, errorResponse{Error: "revocation not configured"})
		return
	}

	var req revokeRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, errorResponse{Error: "invalid JSON: " + err.Error()})
		return
	}

	if !store.IsValidReason(req.Reason) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, errorResponse{Error: fmt.Sprintf("invalid reason %q, must be one of: cheating, compromised, hardware_change, admin", req.Reason)})
		return
	}

	if req.Actor == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, errorResponse{Error: "actor is required"})
		return
	}

	err := revStore.Revoke(clientID, store.RevocationReason(req.Reason), req.Actor, req.Note)
	if err != nil {
		if err == store.ErrAlreadyRevoked {
			w.WriteHeader(http.StatusConflict)
			writeJSON(w, errorResponse{Error: "client is already revoked"})
			return
		}
		h.log.Error("revocation failed", "client_id", clientID, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, errorResponse{Error: "internal error"})
		return
	}

	logging.Security(h.log, "client revoked",
		"client_id", clientID, "actor", req.Actor, "reason", req.Reason, "note", req.Note)

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]string{
		"status":    "revoked",
		"client_id": clientID,
		"reason":    req.Reason,
	})
}

// DELETE /api/v1/clients/{id}/revoke - unrevoke a client
func (h *APIHandler) handleUnrevokeClient(w http.ResponseWriter, r *http.Request, clientID string) {
	revStore := h.verifier.RevocationStore()
	if revStore == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, errorResponse{Error: "revocation not configured"})
		return
	}

	err := revStore.Unrevoke(clientID)
	if err != nil {
		if err == store.ErrNotRevoked {
			w.WriteHeader(http.StatusNotFound)
			writeJSON(w, errorResponse{Error: "client is not revoked"})
			return
		}
		h.log.Error("unrevoke failed", "client_id", clientID, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, errorResponse{Error: "internal error"})
		return
	}

	logging.Security(h.log, "client unrevoked", "client_id", clientID)

	writeJSON(w, map[string]string{
		"status":    "unrevoked",
		"client_id": clientID,
	})
}

// GET /api/v1/revocations - list all active revocations
func (h *APIHandler) handleListRevocations(w http.ResponseWriter, r *http.Request) {
	revStore := h.verifier.RevocationStore()
	if revStore == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, errorResponse{Error: "revocation not configured"})
		return
	}

	entries := revStore.ListRevocations()
	resp := make([]revocationResponse, len(entries))
	for i, e := range entries {
		resp[i] = revocationResponse{
			ClientID:  e.ClientID,
			Reason:    string(e.Reason),
			RevokedAt: e.RevokedAt.UTC().Format(time.RFC3339),
			RevokedBy: e.RevokedBy,
			Note:      e.Note,
		}
	}

	writeJSON(w, map[string]any{
		"revocations": resp,
		"count":       len(resp),
	})
}

// JSON request for ban actions
type banRequest struct {
	HardwareID string `json:"hardware_id"` // hex-encoded 32 bytes
	Reason     string `json:"reason"`      // cheating|compromised|hardware_change|admin
	Actor      string `json:"actor"`       // administrator identifier
	Note       string `json:"note"`        // free-form justification
}

// JSON response for ban entries
type banResponse struct {
	HardwareID string `json:"hardware_id"`
	Reason     string `json:"reason"`
	BannedAt   string `json:"banned_at"`
	BannedBy   string `json:"banned_by"`
	Note       string `json:"note"`
}

// POST /api/v1/bans - ban a hardware identity
func (h *APIHandler) handleBanHardware(w http.ResponseWriter, r *http.Request) {
	banStr := h.verifier.BanStore()
	if banStr == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, errorResponse{Error: "hardware bans not configured"})
		return
	}

	var req banRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, errorResponse{Error: "invalid JSON: " + err.Error()})
		return
	}

	hwid, err := store.ParseHardwareID(req.HardwareID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, errorResponse{Error: "invalid hardware_id: " + err.Error()})
		return
	}

	if !store.IsValidReason(req.Reason) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, errorResponse{Error: fmt.Sprintf("invalid reason %q, must be one of: cheating, compromised, hardware_change, admin", req.Reason)})
		return
	}

	if req.Actor == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, errorResponse{Error: "actor is required"})
		return
	}

	err = banStr.BanHardware(hwid, store.RevocationReason(req.Reason), req.Actor, req.Note)
	if err != nil {
		if err == store.ErrAlreadyBanned {
			w.WriteHeader(http.StatusConflict)
			writeJSON(w, errorResponse{Error: "hardware ID is already banned"})
			return
		}
		h.log.Error("ban failed", "hardware_id", req.HardwareID, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, errorResponse{Error: "internal error"})
		return
	}

	logging.Security(h.log, "hardware banned",
		"hardware_id", req.HardwareID, "actor", req.Actor, "reason", req.Reason)

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]string{
		"status":      "banned",
		"hardware_id": req.HardwareID,
		"reason":      req.Reason,
	})
}

// DELETE /api/v1/bans/{hwid} - unban a hardware identity
func (h *APIHandler) handleUnbanHardware(w http.ResponseWriter, r *http.Request) {
	banStr := h.verifier.BanStore()
	if banStr == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, errorResponse{Error: "hardware bans not configured"})
		return
	}

	hwidHex := strings.TrimPrefix(r.URL.Path, "/api/v1/bans/")
	hwidHex = strings.TrimRight(hwidHex, "/")

	if hwidHex == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, errorResponse{Error: "missing hardware ID"})
		return
	}

	hwid, err := store.ParseHardwareID(hwidHex)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, errorResponse{Error: "invalid hardware_id: " + err.Error()})
		return
	}

	err = banStr.UnbanHardware(hwid)
	if err != nil {
		if err == store.ErrNotBanned {
			w.WriteHeader(http.StatusNotFound)
			writeJSON(w, errorResponse{Error: "hardware ID is not banned"})
			return
		}
		h.log.Error("unban failed", "hardware_id", hwidHex, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, errorResponse{Error: "internal error"})
		return
	}

	logging.Security(h.log, "hardware unbanned", "hardware_id", hwidHex)

	writeJSON(w, map[string]string{
		"status":      "unbanned",
		"hardware_id": hwidHex,
	})
}

// GET /api/v1/bans - list all active hardware bans
func (h *APIHandler) handleListBans(w http.ResponseWriter, r *http.Request) {
	banStr := h.verifier.BanStore()
	if banStr == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, errorResponse{Error: "hardware bans not configured"})
		return
	}

	entries := banStr.ListBans()
	resp := make([]banResponse, len(entries))
	for i, e := range entries {
		resp[i] = banResponse{
			HardwareID: store.FormatHardwareID(e.HardwareID),
			Reason:     string(e.Reason),
			BannedAt:   e.BannedAt.UTC().Format(time.RFC3339),
			BannedBy:   e.BannedBy,
			Note:       e.Note,
		}
	}

	writeJSON(w, map[string]any{
		"bans":  resp,
		"count": len(resp),
	})
}

// JSON response for audit entries
type auditResponse struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	TargetID  string `json:"target_id"`
	Reason    string `json:"reason,omitempty"`
	Actor     string `json:"actor,omitempty"`
	Note      string `json:"note,omitempty"`
}

// GET /api/v1/audit?limit=N - query audit log
func (h *APIHandler) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if h.auditLog == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, errorResponse{Error: "audit log not configured"})
		return
	}

	limit := 100 // default
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	entries := h.auditLog.Query(limit)
	resp := make([]auditResponse, len(entries))
	for i, e := range entries {
		resp[i] = auditResponse{
			ID:        e.ID,
			Timestamp: e.Timestamp.UTC().Format(time.RFC3339),
			Action:    e.Action,
			TargetID:  e.TargetID,
			Reason:    e.Reason,
			Actor:     e.Actor,
			Note:      e.Note,
		}
	}

	writeJSON(w, map[string]any{
		"entries": resp,
		"count":   len(resp),
	})
}

// JSON response for attestation decision entries
type attestationResponse struct {
	ID         int64   `json:"id"`
	Timestamp  string  `json:"timestamp"`
	ClientID   string  `json:"client_id"`
	HardwareID string  `json:"hardware_id,omitempty"`
	Result     string  `json:"result"`
	DurationMs float64 `json:"duration_ms"`
	PCR14      string  `json:"pcr14,omitempty"`
	Details    string  `json:"details,omitempty"`
	RemoteAddr string  `json:"remote_addr,omitempty"`
}

// GET /api/v1/attestations?limit=N - query attestation decision log
func (h *APIHandler) handleAttestationLog(w http.ResponseWriter, r *http.Request) {
	if h.attestationLog == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, errorResponse{Error: "attestation log not configured"})
		return
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	entries := h.attestationLog.QueryAttestations(limit)
	resp := make([]attestationResponse, len(entries))
	for i, e := range entries {
		resp[i] = attestationResponse{
			ID:         e.ID,
			Timestamp:  e.Timestamp.UTC().Format(time.RFC3339),
			ClientID:   e.ClientID,
			HardwareID: e.HardwareID,
			Result:     e.Result,
			DurationMs: e.DurationMs,
			PCR14:      e.PCR14,
			Details:    e.Details,
			RemoteAddr: e.RemoteAddr,
		}
	}

	writeJSON(w, map[string]any{
		"attestations": resp,
		"count":        len(resp),
	})
}

// writes JSON response with proper headers
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("JSON encode error", "error", err)
	}
}
