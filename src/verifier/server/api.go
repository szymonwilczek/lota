// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

const (
	maxJSONBodyBytes = 1 << 20
	maxJSONDepth     = 64
	maxJSONTokens    = 32768
	maxClientOffset  = 10000
	maxDetailChars   = 2048
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
	adminKeyHash   [32]byte
	readerKeyHash  [32]byte
}

// creates a new API handler and registers routes on the given mux
// adminAPIKey controls access to mutating endpoints (revoke, ban):
//   - non-empty: requires Authorization: Bearer <key> header
//   - empty: all mutating endpoints return 403
//
// readerAPIKey controls access to sensitive read-only endpoints:
//   - non-empty: requires Authorization: Bearer <reader-key|admin-key>
//   - empty but admin key set: still requires Authorization: Bearer <admin-key>
//   - both empty: sensitive read-only endpoints are public (loopback dev only;
//     the server refuses a non-loopback bind in this state)
func NewAPIHandler(mux *http.ServeMux, verifier *verify.Verifier, srv *Server, auditLog store.AuditLog, logger *slog.Logger, m *metrics.Metrics, attestLog store.AttestationLog, adminAPIKey, readerAPIKey string) *APIHandler {
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

	if adminAPIKey != "" {
		h.adminKeyHash = sha256.Sum256([]byte(adminAPIKey))
	}
	if readerAPIKey != "" {
		h.readerKeyHash = sha256.Sum256([]byte(readerAPIKey))
	}

	// public monitoring endpoints (no auth required)
	mux.HandleFunc("GET /health", h.handleHealth)

	// operational intelligence endpoints (reader or admin auth required)
	mux.HandleFunc("GET /api/v1/stats", h.requireReader(h.handleStats))
	mux.HandleFunc("GET /metrics", h.requireReader(h.handleMetrics))

	// sensitive read-only endpoints (reader or admin auth required)
	mux.HandleFunc("GET /api/v1/clients", h.requireReader(h.handleListClients))
	mux.HandleFunc("GET /api/v1/clients/", h.requireReader(h.handleClientInfo))
	mux.HandleFunc("POST /api/v1/session/validate", h.requireReader(h.handleValidateSessionToken))
	mux.HandleFunc("GET /api/v1/revocations", h.requireReader(h.handleListRevocations))
	mux.HandleFunc("GET /api/v1/bans", h.requireReader(h.handleListBans))
	mux.HandleFunc("GET /api/v1/audit", h.requireReader(h.handleAuditLog))
	mux.HandleFunc("GET /api/v1/attestations", h.requireReader(h.handleAttestationLog))

	// revocation management (admin auth required)
	mux.HandleFunc("POST /api/v1/clients/", h.requireAdmin(h.handleClientAction))
	mux.HandleFunc("DELETE /api/v1/clients/", h.requireAdmin(h.handleClientAction))

	// post-fact review of Low-Firmware-Assurance re-anchors.
	// LFA re-anchors apply automatically; these endpoints let an operator see
	// which clients took that path and acknowledge having reviewed them.
	// Acknowledge route is more specific than the POST /clients/ pattern
	// above, so Go's mux routes it here.
	mux.HandleFunc("GET /api/v1/reanchor/review",
		h.requireReader(h.handleReanchorReviewList))
	mux.HandleFunc("POST /api/v1/clients/{clientID}/reanchor-review-ack",
		h.requireAdmin(h.handleReanchorReviewAck))

	// operator-forced re-baseline;
	// deliberate counterpart of the self-service re-anchor above (admin auth required)
	mux.HandleFunc("POST /api/v1/clients/{clientID}/reanchor",
		h.requireAdmin(h.handleForceReanchor))

	// hardware ban management (admin auth required)
	mux.HandleFunc("POST /api/v1/bans", h.requireAdmin(h.handleBanHardware))
	mux.HandleFunc("DELETE /api/v1/bans/", h.requireAdmin(h.handleUnbanHardware))

	return h
}

// principalCtxKey carries the authenticated Principal through the
// request context so handlers can scope responses to its tenant set.
type principalCtxKey struct{}

// requestPrincipal returns the authenticated principal of a request.
// nil means the endpoint was served without authentication (loopback
// dev default) and scopes as every-tenant for backwards compatibility.
func requestPrincipal(r *http.Request) *Principal {
	if p, ok := r.Context().Value(principalCtxKey{}).(*Principal); ok {
		return p
	}
	return nil
}

// principalAllowsTenant reports whether the request principal may see
// or act within a tenant.
// Unauthenticated (nil) principal scopes as every tenant,
// matching the loopback dev default.
func principalAllowsTenant(p *Principal, tenant string) bool {
	if p == nil {
		return true
	}
	return p.AllowsTenant(tenant)
}

// scopedToTenants reports whether the principal carries restricted tenant set
// (i.e. listings must be filtered).
func scopedToTenants(p *Principal) bool {
	return p != nil && !p.AllTenants
}

// clientTenant resolves the CA-assigned tenant of a client,
// falling back to the default tenant for clients without baseline row.
func (h *APIHandler) clientTenant(clientID string) string {
	if info, found := h.verifier.ClientInfo(clientID); found {
		return info.Tenant
	}
	return verify.DefaultTenant
}

// withPrincipal stashes the principal on the request context.
func withPrincipal(r *http.Request, p *Principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalCtxKey{}, p))
}

// scopedKeySet returns the scoped key set when the server carries one.
func (h *APIHandler) scopedKeySet() *APIKeySet {
	if h.server == nil {
		return nil
	}
	return h.server.apiKeySet()
}

// resolvePrincipal authenticates bearer token against the env keys
// (global scope, back-compat) and the scoped key file.
func (h *APIHandler) resolvePrincipal(token string) *Principal {
	if h.adminAPIKey != "" && tokenMatchesHash(token, h.adminKeyHash) {
		return &Principal{Role: RoleAdmin, AllTenants: true}
	}
	if h.readerAPIKey != "" && tokenMatchesHash(token, h.readerKeyHash) {
		return &Principal{Role: RoleReader, AllTenants: true}
	}
	if p, ok := h.scopedKeySet().Lookup(token); ok {
		return p
	}
	return nil
}

// authConfigured reports whether any auth tier exists at all.
func (h *APIHandler) authConfigured() bool {
	return h.adminAPIKey != "" || h.readerAPIKey != "" || h.scopedKeySet().Len() > 0
}

// adminConfigured reports whether any key can reach the admin tier.
func (h *APIHandler) adminConfigured() bool {
	return h.adminAPIKey != "" || h.scopedKeySet().Len() > 0
}

// wraps a handler with Bearer token authentication
// if no admin-capable key is configured, all mutating requests are rejected
func (h *APIHandler) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.adminConfigured() {
			h.log.Warn("admin endpoint called but no API key configured",
				"method", r.Method, "path", r.URL.Path,
				"remote_addr", r.RemoteAddr)
			writeJSONStatus(w, http.StatusForbidden, errorResponse{Error: "admin API key not configured"})
			return
		}

		token := extractBearerToken(r)
		if token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="lota-admin"`)
			writeJSONStatus(w, http.StatusUnauthorized, errorResponse{Error: "missing Authorization header"})
			return
		}

		p := h.resolvePrincipal(token)
		if !p.CanAdmin() {
			logging.Security(h.log, "admin auth failed",
				"method", r.Method, "path", r.URL.Path,
				"remote_addr", r.RemoteAddr)
			writeJSONStatus(w, http.StatusForbidden, errorResponse{Error: "invalid API key"})
			return
		}

		next(w, withPrincipal(r, p))
	}
}

// wraps a handler with reader-level authentication
// accepts the reader env key, the admin env key, or any scoped key
// (admin implies reader).
// Endpoint is public only when no auth tier is configured at all;
// configured admin key alone is sufficient to gate reader endpoints,
// so an operator who sets only an admin key does not silently expose the sensitive read tier
func (h *APIHandler) requireReader(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.authConfigured() {
			// no auth configured: endpoint is public (loopback dev default)
			next(w, r)
			return
		}

		token := extractBearerToken(r)
		if token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="lota"`)
			writeJSONStatus(w, http.StatusUnauthorized, errorResponse{Error: "missing Authorization header"})
			return
		}

		p := h.resolvePrincipal(token)
		if p == nil {
			logging.Security(h.log, "reader auth failed",
				"method", r.Method, "path", r.URL.Path,
				"remote_addr", r.RemoteAddr)
			writeJSONStatus(w, http.StatusForbidden, errorResponse{Error: "invalid API key"})
			return
		}

		next(w, withPrincipal(r, p))
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

// compares provided token against expected key hash using fixed-size
// constant-time comparison to avoid key-length timing side channels
func tokenMatchesHash(token string, expectedHash [32]byte) bool {
	tokenHash := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(tokenHash[:], expectedHash[:]) == 1
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
	// TenantScoped is set when the response counts were narrowed to
	// the caller's tenant set.
	// Fleet-wide attestation counters are then omitted because they
	// are not attributable per tenant.
	TenantScoped bool     `json:"tenant_scoped,omitempty"`
	Tenants      []string `json:"tenants,omitempty"`
}

type clientListResponse struct {
	Clients []string `json:"clients"`
	Count   int      `json:"count"`
	Total   int      `json:"total"`
	Limit   int      `json:"limit"`
	Offset  int      `json:"offset"`
}

type clientInfoResponse struct {
	ClientID          string `json:"client_id"`
	Tenant            string `json:"tenant"`
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

type validateSessionTokenRequest struct {
	SessionToken string `json:"session_token"`
	Consume      bool   `json:"consume"`
}

type validateSessionTokenResponse struct {
	Valid      bool   `json:"valid"`
	Consumed   bool   `json:"consumed"`
	ClientID   string `json:"client_id,omitempty"`
	Tenant     string `json:"tenant,omitempty"`
	HardwareID string `json:"hardware_id,omitempty"`
	ResultCode uint32 `json:"result_code,omitempty"`
	Flags      uint32 `json:"flags,omitempty"`
	PCRMask    uint32 `json:"pcr_mask,omitempty"`
	ValidUntil uint64 `json:"valid_until,omitempty"`
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
		writeJSONStatus(w, http.StatusServiceUnavailable, resp)
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

	// tenant-scoped key gets tenant-narrowed counts;
	// fleet-wide attestation/nonce counters are not attributable per tenant,
	// so they are zeroed and the response flags itself as scoped
	if p := requestPrincipal(r); scopedToTenants(p) {
		resp.TenantScoped = true
		resp.Tenants = sortedTenantSet(p)

		registered := 0
		for _, id := range h.verifier.ListClients() {
			if info, found := h.verifier.ClientInfo(id); found && p.AllowsTenant(info.Tenant) {
				registered++
			}
		}
		resp.RegisteredClients = registered

		resp.ActiveRevocations = 0
		if revStore := h.verifier.RevocationStore(); revStore != nil {
			for _, e := range revStore.ListRevocations() {
				if p.AllowsTenant(e.Tenant) {
					resp.ActiveRevocations++
				}
			}
		}

		resp.ActiveBans = 0
		if banStr := h.verifier.BanStore(); banStr != nil {
			for _, e := range banStr.ListBans() {
				if p.AllowsTenant(e.Tenant) {
					resp.ActiveBans++
				}
			}
		}

		resp.PendingChallenges = 0
		resp.UsedNonces = 0
		resp.TotalAttestations = 0
		resp.SuccessfulAttests = 0
		resp.FailedAttests = 0
		resp.RevokedAttests = 0
		resp.BannedAttests = 0
	}

	writeJSON(w, resp)
}

// sortedTenantSet returns the principal's explicit tenants in sorted
// order for a stable stats response.
func sortedTenantSet(p *Principal) []string {
	tenants := make([]string, 0, len(p.Tenants))
	for t := range p.Tenants {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants)
	return tenants
}

// GET /api/v1/clients - list all registered clients
func (h *APIHandler) handleListClients(w http.ResponseWriter, r *http.Request) {
	const (
		defaultLimit = 100
		maxLimit     = 1000
	)

	limit, offset, err := parsePagination(r, defaultLimit, maxLimit)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	// tenant-scoped key sees only its tenants' clients;
	// SQL-paged fast path below serves the global view, so scoped keys walk
	// the full list and paginate the filtered result
	if p := requestPrincipal(r); scopedToTenants(p) {
		all := h.verifier.ListClients()
		visible := make([]string, 0, len(all))
		for _, id := range all {
			if info, found := h.verifier.ClientInfo(id); found && p.AllowsTenant(info.Tenant) {
				visible = append(visible, id)
			}
		}
		sort.Strings(visible)

		page := []string{}
		if offset < len(visible) {
			end := offset + limit
			if end > len(visible) {
				end = len(visible)
			}
			page = visible[offset:end]
		}
		writeJSON(w, clientListResponse{
			Clients: page,
			Count:   len(page),
			Total:   len(visible),
			Limit:   limit,
			Offset:  offset,
		})
		return
	}

	var clients []string
	total := 0

	aikStore := h.verifier.AIKStore()
	if lister, ok := aikStore.(store.PaginatedClientLister); ok {
		if listerE, ok := aikStore.(store.PaginatedClientListerWithError); ok {
			clients, err = listerE.ListClientsPageE(limit, offset)
			if err != nil {
				h.log.Error("failed to list clients page", "error", err)
				writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "database unavailable"})
				return
			}
		} else {
			clients = lister.ListClientsPage(limit, offset)
		}

		dbTotal := 0
		switch counter := aikStore.(type) {
		case store.ClientCounterWithError:
			var err error
			dbTotal, err = counter.CountClientsE()
			if err != nil {
				h.log.Error("failed to count clients", "error", err)
				writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "database unavailable"})
				return
			}
		case store.ClientCounter:
			dbTotal = counter.CountClients()
		}

		active := h.verifier.ListActiveClients()
		activeOnly := make([]string, 0, len(active))

		switch checker := aikStore.(type) {
		case store.ClientExistenceBatchChecker:
			existing, err := checker.ExistingClients(active)
			if err != nil {
				h.log.Error("failed to check active client existence in batch", "error", err)
				writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "database unavailable"})
				return
			}

			for _, id := range active {
				if _, exists := existing[id]; !exists {
					activeOnly = append(activeOnly, id)
				}
			}
		case store.ClientExistenceChecker:
			for _, id := range active {
				exists, err := checker.HasClient(id)
				if err != nil {
					h.log.Error("failed to check client existence", "client_id", id, "error", err)
					writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "database unavailable"})
					return
				}
				if !exists {
					activeOnly = append(activeOnly, id)
				}
			}
		default:
			registered := make(map[string]struct{})
			for _, id := range aikStore.ListClients() {
				registered[id] = struct{}{}
			}
			for _, id := range active {
				if _, ok := registered[id]; !ok {
					activeOnly = append(activeOnly, id)
				}
			}
		}

		sort.Strings(activeOnly)

		total = dbTotal + len(activeOnly)

		if len(clients) < limit {
			activeOffset := 0
			if offset > dbTotal {
				activeOffset = offset - dbTotal
			}

			if activeOffset < len(activeOnly) {
				need := limit - len(clients)
				end := activeOffset + need
				if end > len(activeOnly) {
					end = len(activeOnly)
				}
				clients = append(clients, activeOnly[activeOffset:end]...)
			}
		}
	} else {
		all := h.verifier.ListClients()
		total = len(all)
		if offset < len(all) {
			end := offset + limit
			if end > len(all) {
				end = len(all)
			}
			clients = all[offset:end]
		}
	}

	if clients == nil {
		clients = []string{}
	}

	resp := clientListResponse{
		Clients: clients,
		Count:   len(clients),
		Total:   total,
		Limit:   limit,
		Offset:  offset,
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
		writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
		return
	}
	// client outside the key's tenant set does not exist for it
	if !principalAllowsTenant(requestPrincipal(r), info.Tenant) {
		writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
		return
	}

	resp := clientInfoResponse{
		ClientID:          info.ClientID,
		Tenant:            info.Tenant,
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

// POST /api/v1/session/validate - verify issued session token
func (h *APIHandler) handleValidateSessionToken(w http.ResponseWriter, r *http.Request) {
	var req validateSessionTokenRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON: " + err.Error()})
		return
	}

	req.SessionToken = strings.TrimSpace(req.SessionToken)
	if len(req.SessionToken) != 64 {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "session_token must be 64 hex characters"})
		return
	}

	tokBytes, err := hexDecodeFixed32(req.SessionToken)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid session_token hex"})
		return
	}

	// resolve without consuming first so a token outside the key's
	// tenant set is reported as not found and, crucially, is NOT
	// consumed by a foreign caller
	if scopedToTenants(requestPrincipal(r)) {
		peek := h.verifier.ValidateSessionToken(tokBytes, false)
		if !peek.Exists || !principalAllowsTenant(requestPrincipal(r), peek.Tenant) {
			writeJSON(w, validateSessionTokenResponse{Valid: false})
			return
		}
	}

	status := h.verifier.ValidateSessionToken(tokBytes, req.Consume)
	if !status.Exists {
		writeJSON(w, validateSessionTokenResponse{Valid: false})
		return
	}

	writeJSON(w, validateSessionTokenResponse{
		Valid:      !status.Expired,
		Consumed:   status.Consumed,
		ClientID:   status.ClientID,
		Tenant:     status.Tenant,
		HardwareID: fmt.Sprintf("%x", status.HardwareID[:]),
		ResultCode: status.ResultCode,
		Flags:      status.Flags,
		PCRMask:    status.PCRMask,
		ValidUntil: status.ValidUntil,
	})
}

func hexDecodeFixed32(s string) ([32]byte, error) {
	var out [32]byte
	for i := 0; i < 32; i++ {
		v, ok := fromHexByte(s[i*2], s[i*2+1])
		if !ok {
			return out, fmt.Errorf("invalid hex")
		}
		out[i] = v
	}
	return out, nil
}

func fromHexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func fromHexByte(hi, lo byte) (byte, bool) {
	h, ok := fromHexNibble(hi)
	if !ok {
		return 0, false
	}
	l, ok := fromHexNibble(lo)
	if !ok {
		return 0, false
	}
	return (h << 4) | l, true
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
	Tenant    string `json:"tenant"`
	Reason    string `json:"reason"`
	RevokedAt string `json:"revoked_at"`
	RevokedBy string `json:"revoked_by"`
	Note      string `json:"note"`
}

// handles POST/DELETE on /api/v1/clients/{id}[/revoke]
func (h *APIHandler) handleClientAction(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	parts := strings.SplitN(path, "/", 2)

	clientID := parts[0]
	if clientID == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "missing client ID"})
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
	case action == "" && r.Method == http.MethodDelete:
		h.handleDeleteClient(w, r, clientID)
	default:
		if r.Method == http.MethodGet {
			h.handleClientInfo(w, r)
			return
		}
		writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "unknown action"})
	}
}

// POST /api/v1/clients/{id}/revoke - revoke a client's AIK
func (h *APIHandler) handleRevokeClient(w http.ResponseWriter, r *http.Request, clientID string) {
	revStore := h.verifier.RevocationStore()
	if revStore == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, errorResponse{Error: "revocation not configured"})
		return
	}

	var req revokeRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON: " + err.Error()})
		return
	}

	if !store.IsValidReason(req.Reason) {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: fmt.Sprintf("invalid reason %q, must be one of: cheating, compromised, hardware_change, admin", req.Reason)})
		return
	}

	if req.Actor == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "actor is required"})
		return
	}

	// Record the tenant the CA assigned to this client so listings can be scoped
	// Client with no baseline row falls into the default tenant
	tenant := h.clientTenant(clientID)
	// foreign-tenant client does not exist for this key
	if !principalAllowsTenant(requestPrincipal(r), tenant) {
		writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
		return
	}

	err := revStore.Revoke(tenant, clientID, store.RevocationReason(req.Reason), req.Actor, req.Note)
	if err != nil {
		if err == store.ErrAlreadyRevoked {
			writeJSONStatus(w, http.StatusConflict, errorResponse{Error: "client is already revoked"})
			return
		}
		h.log.Error("revocation failed", "client_id", clientID, "error", err)
		writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	logging.Security(h.log, "client revoked",
		"client_id", clientID, "actor", req.Actor, "reason", req.Reason, "note", req.Note)

	writeJSONStatus(w, http.StatusCreated, map[string]string{
		"status":    "revoked",
		"client_id": clientID,
		"reason":    req.Reason,
	})
}

// DELETE /api/v1/clients/{id}/revoke - unrevoke a client
func (h *APIHandler) handleUnrevokeClient(w http.ResponseWriter, r *http.Request, clientID string) {
	revStore := h.verifier.RevocationStore()
	if revStore == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, errorResponse{Error: "revocation not configured"})
		return
	}

	// scope on the revocation's recorded tenant;
	// foreign-tenant revocation is reported as "not revoked"
	// so a key cannot probe another tenant's revocation state
	if scopedToTenants(requestPrincipal(r)) {
		entry, revoked := revStore.IsRevoked(clientID)
		if !revoked || !principalAllowsTenant(requestPrincipal(r), entry.Tenant) {
			writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client is not revoked"})
			return
		}
	}

	err := revStore.Unrevoke(clientID)
	if err != nil {
		if err == store.ErrNotRevoked {
			writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client is not revoked"})
			return
		}
		h.log.Error("unrevoke failed", "client_id", clientID, "error", err)
		writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
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
		writeJSONStatus(w, http.StatusServiceUnavailable, errorResponse{Error: "revocation not configured"})
		return
	}

	p := requestPrincipal(r)
	entries := revStore.ListRevocations()
	resp := make([]revocationResponse, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		if !principalAllowsTenant(p, e.Tenant) {
			continue
		}
		resp = append(resp, revocationResponse{
			ClientID:  e.ClientID,
			Tenant:    e.Tenant,
			Reason:    string(e.Reason),
			RevokedAt: e.RevokedAt.UTC().Format(time.RFC3339),
			RevokedBy: e.RevokedBy,
			Note:      e.Note,
		})
	}

	writeJSON(w, map[string]any{
		"revocations": resp,
		"count":       len(resp),
	})
}

// JSON request for ban actions
type banRequest struct {
	HardwareID string `json:"hardware_id"`      // hex-encoded 32 bytes
	Tenant     string `json:"tenant,omitempty"` // ban scope; default tenant when empty
	Reason     string `json:"reason"`           // cheating|compromised|hardware_change|admin
	Actor      string `json:"actor"`            // administrator identifier
	Note       string `json:"note"`             // free-form justification
}

// JSON response for ban entries
type banResponse struct {
	HardwareID string `json:"hardware_id"`
	Tenant     string `json:"tenant"`
	Reason     string `json:"reason"`
	BannedAt   string `json:"banned_at"`
	BannedBy   string `json:"banned_by"`
	Note       string `json:"note"`
}

type banListResponse struct {
	Bans   []banResponse `json:"bans"`
	Count  int           `json:"count"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	NextID string        `json:"next_id,omitempty"`
}

func parsePagination(r *http.Request, defaultLimit, maxLimit int) (limit, offset int, err error) {
	limit = defaultLimit
	offset = 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	if limit > maxLimit {
		limit = maxLimit
	}

	if offset > maxClientOffset {
		return 0, 0, fmt.Errorf("offset exceeds maximum (%d)", maxClientOffset)
	}

	return limit, offset, nil
}

// POST /api/v1/bans - ban a hardware identity
func (h *APIHandler) handleBanHardware(w http.ResponseWriter, r *http.Request) {
	banStr := h.verifier.BanStore()
	if banStr == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, errorResponse{Error: "hardware bans not configured"})
		return
	}

	var req banRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON: " + err.Error()})
		return
	}

	hwid, err := store.ParseHardwareID(req.HardwareID)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid hardware_id: " + err.Error()})
		return
	}
	canonicalHWID := store.FormatHardwareID(hwid)

	if !store.IsValidReason(req.Reason) {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: fmt.Sprintf("invalid reason %q, must be one of: cheating, compromised, hardware_change, admin", req.Reason)})
		return
	}

	if req.Actor == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "actor is required"})
		return
	}

	// ban scope is explicit:
	// default tenant when omitted, validated otherwise,
	// and always within the key's tenant set
	tenant := req.Tenant
	if tenant == "" {
		tenant = verify.DefaultTenant
	} else if !verify.ValidTenantName(tenant) {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid tenant"})
		return
	}
	if !principalAllowsTenant(requestPrincipal(r), tenant) {
		writeJSONStatus(w, http.StatusForbidden, errorResponse{Error: "tenant not permitted for this key"})
		return
	}

	err = banStr.BanHardware(tenant, hwid, store.RevocationReason(req.Reason), req.Actor, req.Note)
	if err != nil {
		if err == store.ErrAlreadyBanned {
			writeJSONStatus(w, http.StatusConflict, errorResponse{Error: "hardware ID is already banned"})
			return
		}
		h.log.Error("ban failed", "hardware_id", canonicalHWID, "error", err)
		writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	logging.Security(h.log, "hardware banned",
		"hardware_id", canonicalHWID, "tenant", tenant, "actor", req.Actor, "reason", req.Reason)

	writeJSONStatus(w, http.StatusCreated, map[string]string{
		"status":      "banned",
		"hardware_id": canonicalHWID,
		"tenant":      tenant,
		"reason":      req.Reason,
	})
}

// DELETE /api/v1/bans/{hwid} - unban a hardware identity
func (h *APIHandler) handleUnbanHardware(w http.ResponseWriter, r *http.Request) {
	banStr := h.verifier.BanStore()
	if banStr == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, errorResponse{Error: "hardware bans not configured"})
		return
	}

	hwidHex := strings.TrimPrefix(r.URL.Path, "/api/v1/bans/")
	hwidHex = strings.TrimRight(hwidHex, "/")

	if hwidHex == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "missing hardware ID"})
		return
	}

	hwid, err := store.ParseHardwareID(hwidHex)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid hardware_id: " + err.Error()})
		return
	}
	canonicalHWID := store.FormatHardwareID(hwid)

	// ban to lift is identified by (tenant, hardware_id);
	// tenant comes from the ?tenant= query parameter,
	// default when omitted, and must be within the key's tenant set
	tenant := r.URL.Query().Get("tenant")
	if tenant == "" {
		tenant = verify.DefaultTenant
	} else if !verify.ValidTenantName(tenant) {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid tenant"})
		return
	}
	if !principalAllowsTenant(requestPrincipal(r), tenant) {
		writeJSONStatus(w, http.StatusForbidden, errorResponse{Error: "tenant not permitted for this key"})
		return
	}

	err = banStr.UnbanHardware(tenant, hwid)
	if err != nil {
		if err == store.ErrNotBanned {
			writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "hardware ID is not banned"})
			return
		}
		h.log.Error("unban failed", "hardware_id", canonicalHWID, "error", err)
		writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	logging.Security(h.log, "hardware unbanned", "hardware_id", canonicalHWID, "tenant", tenant)

	writeJSON(w, map[string]string{
		"status":      "unbanned",
		"hardware_id": canonicalHWID,
		"tenant":      tenant,
	})
}

// GET /api/v1/bans?limit=N&next_id=<cursor> - list active hardware bans (keyset-paged)
func (h *APIHandler) handleListBans(w http.ResponseWriter, r *http.Request) {
	banStr := h.verifier.BanStore()
	if banStr == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, errorResponse{Error: "hardware bans not configured"})
		return
	}

	if r.URL.Query().Get("offset") != "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "offset pagination is not supported for bans; use next_id cursor"})
		return
	}

	const (
		defaultLimit = 100
		maxLimit     = 1000
	)

	limit := defaultLimit
	if l := r.URL.Query().Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed <= 0 {
			writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid limit"})
			return
		}
		limit = parsed
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	nextID := strings.TrimSpace(r.URL.Query().Get("next_id"))

	var entries []store.BanEntry
	total := 0

	switch lister := banStr.(type) {
	case store.CursorBanLister:
		var err error
		entries, err = lister.ListBansAfter(limit+1, nextID)
		if err != nil {
			writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
			return
		}

		switch counter := banStr.(type) {
		case store.BanCounterWithError:
			total, err = counter.CountBansE()
			if err != nil {
				h.log.Error("failed to count bans", "error", err)
				writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "database unavailable"})
				return
			}
		case store.BanCounter:
			total = counter.CountBans()
		}
	case store.PaginatedBanLister:
		if nextID != "" {
			writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "next_id pagination is not supported by configured ban store"})
			return
		}
		if listerE, ok := banStr.(store.PaginatedBanListerWithError); ok {
			var err error
			entries, err = listerE.ListBansPageE(limit+1, 0)
			if err != nil {
				h.log.Error("failed to list bans page", "error", err)
				writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "database unavailable"})
				return
			}
		} else {
			entries = lister.ListBansPage(limit+1, 0)
		}

		switch counter := banStr.(type) {
		case store.BanCounterWithError:
			var err error
			total, err = counter.CountBansE()
			if err != nil {
				h.log.Error("failed to count bans", "error", err)
				writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "database unavailable"})
				return
			}
		case store.BanCounter:
			total = counter.CountBans()
		}
	default:
		if nextID != "" {
			writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "next_id pagination is not supported by configured ban store"})
			return
		}
		all := banStr.ListBans()
		total = len(all)
		if len(all) > 0 {
			end := limit + 1
			if end > len(all) {
				end = len(all)
			}
			entries = all[:end]
		}
	}

	if entries == nil {
		entries = []store.BanEntry{}
	}

	respNextID := ""
	if len(entries) > limit {
		last := entries[limit-1]
		respNextID = store.EncodeBanCursor(last)
		entries = entries[:limit]
	}

	// tenant-scoped key sees only its tenants' bans;
	// cursor still advances over every entry (respNextID above),
	// so filtered page may come back short but pagination stays consistent
	p := requestPrincipal(r)
	resp := make([]banResponse, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		if !principalAllowsTenant(p, e.Tenant) {
			continue
		}
		resp = append(resp, banResponse{
			HardwareID: store.FormatHardwareID(e.HardwareID),
			Tenant:     e.Tenant,
			Reason:     string(e.Reason),
			BannedAt:   e.BannedAt.UTC().Format(time.RFC3339),
			BannedBy:   e.BannedBy,
			Note:       e.Note,
		})
	}

	// when scoped, the store-wide total would leak other tenants' counts;
	// recompute the visible total from the filtered full list
	if scopedToTenants(p) {
		total = 0
		for _, e := range banStr.ListBans() {
			if p.AllowsTenant(e.Tenant) {
				total++
			}
		}
	}

	writeJSON(w, banListResponse{
		Bans:   resp,
		Count:  len(resp),
		Total:  total,
		Limit:  limit,
		NextID: respNextID,
	})
}

// JSON response for audit entries
type auditResponse struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Tenant    string `json:"tenant"`
	Action    string `json:"action"`
	TargetID  string `json:"target_id"`
	Reason    string `json:"reason,omitempty"`
	Actor     string `json:"actor,omitempty"`
	Note      string `json:"note,omitempty"`
}

// GET /api/v1/audit?limit=N - query audit log
func (h *APIHandler) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if h.auditLog == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, errorResponse{Error: "audit log not configured"})
		return
	}

	limit := 100 // default
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > 10000 {
		limit = 10000
	}

	p := requestPrincipal(r)
	entries := h.auditLog.Query(limit)
	resp := make([]auditResponse, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		if !principalAllowsTenant(p, e.Tenant) {
			continue
		}
		resp = append(resp, auditResponse{
			ID:        e.ID,
			Timestamp: e.Timestamp.UTC().Format(time.RFC3339),
			Tenant:    e.Tenant,
			Action:    e.Action,
			TargetID:  e.TargetID,
			Reason:    e.Reason,
			Actor:     e.Actor,
			Note:      e.Note,
		})
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
	Tenant     string  `json:"tenant,omitempty"`
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
		writeJSONStatus(w, http.StatusServiceUnavailable, errorResponse{Error: "attestation log not configured"})
		return
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > 10000 {
		limit = 10000
	}

	p := requestPrincipal(r)
	entries := h.attestationLog.QueryAttestations(limit)
	resp := make([]attestationResponse, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		if !principalAllowsTenant(p, e.Tenant) {
			continue
		}
		resp = append(resp, attestationResponse{
			ID:         e.ID,
			Timestamp:  e.Timestamp.UTC().Format(time.RFC3339),
			Tenant:     e.Tenant,
			ClientID:   e.ClientID,
			HardwareID: e.HardwareID,
			Result:     e.Result,
			DurationMs: e.DurationMs,
			PCR14:      e.PCR14,
			Details:    sanitizeAttestationDetail(e.Details),
			RemoteAddr: e.RemoteAddr,
		})
	}

	writeJSON(w, map[string]any{
		"attestations": resp,
		"count":        len(resp),
	})
}

// writes JSON response with proper headers and explicit status code
func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("JSON encode error", "error", err)
	}
}

// writes JSON response with implicit 200 status
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("JSON encode error", "error", err)
	}
}

func decodeJSONRequest(w http.ResponseWriter, r *http.Request, dst any) error {
	if r == nil || r.Body == nil {
		return errors.New("empty request body")
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return fmt.Errorf("request body too large (max %d bytes)", maxJSONBodyBytes)
		}
		return err
	}

	if len(bytes.TrimSpace(body)) == 0 {
		return errors.New("empty request body")
	}

	if err := validateJSONComplexity(body); err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(dst); err != nil {
		return err
	}

	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values in request body")
		}
		return err
	}

	return nil
}

func sanitizeAttestationDetail(s string) string {
	if s == "" {
		return ""
	}

	b := strings.Builder{}
	b.Grow(len(s))
	count := 0
	for _, r := range s {
		if count >= maxDetailChars {
			break
		}
		if (r < 0x20 && r != '\n' && r != '\r' && r != '\t') || r == 0x7f {
			b.WriteRune(' ')
		} else {
			b.WriteRune(r)
		}
		count++
	}

	out := html.EscapeString(b.String())
	if count < len([]rune(s)) {
		out += "...[truncated]"
	}

	return out
}

// strips CR and LF from a request-supplied value
// so it cannot forge additional log records
func sanitizeLogField(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}

func validateJSONComplexity(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	depth := 0
	tokens := 0

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		tokens++
		if tokens > maxJSONTokens {
			return fmt.Errorf("JSON token count exceeds limit (%d)", maxJSONTokens)
		}

		delim, ok := tok.(json.Delim)
		if !ok {
			continue
		}

		switch delim {
		case '{', '[':
			depth++
			if depth > maxJSONDepth {
				return fmt.Errorf("JSON nesting exceeds limit (%d)", maxJSONDepth)
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return errors.New("malformed JSON nesting")
			}
		}
	}

	if depth != 0 {
		return errors.New("malformed JSON nesting")
	}

	return nil
}

// handleReanchorReviewList returns the clients that re-anchored on the
// Low-Firmware-Assurance path and have not yet been reviewed (reader).
func (h *APIHandler) handleReanchorReviewList(w http.ResponseWriter, r *http.Request) {
	clients, err := h.verifier.ListReanchorReview()
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}
	if p := requestPrincipal(r); scopedToTenants(p) {
		visible := make([]string, 0, len(clients))
		for _, id := range clients {
			if p.AllowsTenant(h.clientTenant(id)) {
				visible = append(visible, id)
			}
		}
		clients = visible
	}
	if clients == nil {
		clients = []string{}
	}
	writeJSON(w, map[string]any{"pending_review": clients, "count": len(clients)})
}

// handleReanchorReviewAck clears a client's pending-review flag once an
// operator has inspected its LFA re-anchor (admin only).
func (h *APIHandler) handleReanchorReviewAck(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("clientID")
	if clientID == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "missing client id"})
		return
	}
	if !principalAllowsTenant(requestPrincipal(r), h.clientTenant(clientID)) {
		writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
		return
	}
	if err := h.verifier.AcknowledgeReanchorReview(clientID); err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}
	h.log.Info("operator acknowledged LFA re-anchor review", "client_id", clientID)
	writeJSON(w, map[string]string{"status": "reviewed", "client_id": clientID})
}

// JSON request for operator lifecycle actions
// (forced re-anchor, delete)
type lifecycleRequest struct {
	Actor string `json:"actor"` // administrator identifier
	Note  string `json:"note"`  // free-form justification
}

// POST /api/v1/clients/{clientID}/reanchor
// Drop the client's stored baselines so the next attestation re-establishes
// trust (admin only).
// This is the deliberate operator re-baseline for platform changes
// the self-service re-anchor refuses or is not enabled for.
// AIK registration is untouched.
func (h *APIHandler) handleForceReanchor(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("clientID")
	if clientID == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "missing client id"})
		return
	}

	var req lifecycleRequest
	if err := decodeJSONRequest(w, r, &req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON: " + err.Error()})
		return
	}
	if req.Actor == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "actor is required"})
		return
	}

	logID := sanitizeLogField(clientID)

	// resolve the tenant for scoping and the audit entry
	tenant := h.clientTenant(clientID)
	if !principalAllowsTenant(requestPrincipal(r), tenant) {
		writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
		return
	}

	if err := h.verifier.ForceReanchor(clientID); err != nil {
		if errors.Is(err, verify.ErrUnknownClient) {
			writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
			return
		}
		h.log.Error("forced re-anchor failed", "client_id", logID, "error", err)
		writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	if h.auditLog != nil {
		if err := h.auditLog.Log(tenant, "reanchor", clientID, "", req.Actor, req.Note); err != nil {
			h.log.Error("audit log write failed",
				"action", "reanchor", "client_id", logID, "error", err)
		}
	}
	logging.Security(h.log, "client baseline force re-anchored",
		"client_id", logID, "actor", req.Actor, "note", req.Note)

	writeJSON(w, map[string]string{
		"status":    "reanchored",
		"client_id": clientID,
	})
}

// DELETE /api/v1/clients/{id}
// Remove the client's AIK registration and baselines, forcing fresh
// enrollment (admin only).
// Revocations and hardware bans survive the delete.
// Body is optional audit metadata ({"actor","note"}).
// DELETE has no required payload.
func (h *APIHandler) handleDeleteClient(w http.ResponseWriter, r *http.Request, clientID string) {
	var req lifecycleRequest
	if r.ContentLength != 0 {
		if err := decodeJSONRequest(w, r, &req); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON: " + err.Error()})
			return
		}
	}

	logID := sanitizeLogField(clientID)

	// resolve the tenant before the delete removes the baseline row
	tenant := h.clientTenant(clientID)
	if !principalAllowsTenant(requestPrincipal(r), tenant) {
		writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
		return
	}

	if err := h.verifier.DeleteClient(clientID); err != nil {
		switch {
		case errors.Is(err, verify.ErrUnknownClient):
			writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
		case errors.Is(err, store.ErrInvalidClientID):
			writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid client ID"})
		default:
			h.log.Error("client delete failed", "client_id", logID, "error", err)
			writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		}
		return
	}

	if h.auditLog != nil {
		if err := h.auditLog.Log(tenant, "delete_client", clientID, "", req.Actor, req.Note); err != nil {
			h.log.Error("audit log write failed",
				"action", "delete_client", "client_id", logID, "error", err)
		}
	}
	logging.Security(h.log, "client deleted",
		"client_id", logID, "actor", req.Actor, "note", req.Note)

	writeJSON(w, map[string]string{
		"status":    "deleted",
		"client_id": clientID,
	})
}
