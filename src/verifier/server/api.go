// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - REST Monitoring API

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
	"slices"
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
	maxDetailChars   = 2048
)

// APIHandler serves the monitoring REST API.
type APIHandler struct {
	verifier       *verify.Verifier
	server         *Server
	auditLog       store.AuditLog
	attestationLog store.AttestationLog
	log            *slog.Logger
	metrics        *metrics.Metrics
	startTime      time.Time
	adminAPIKey    string
	reportOnly     bool // instance reads a database it cannot write
	readerAPIKey   string
	adminKeyHash   [32]byte
	readerKeyHash  [32]byte
	routes         []string // patterns handed to the mux, in order
	endpoints      []string // what those patterns serve, as an operator calls it
}

// NewAPIHandler registers the monitoring routes on mux. The reader endpoints
// are open while no key of any kind is configured; the admin endpoints answer
// 403 while neither an admin key nor a key file is.
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
		reportOnly:     srv != nil && srv.reportOnly,
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

	h.handle(mux, "GET /health", h.handleHealth)

	h.handle(mux, "GET /api/v1/stats", h.requireReader(h.handleStats))
	h.handle(mux, "GET /metrics", h.requireReader(h.handleMetrics))

	h.handle(mux, "GET /api/v1/clients", h.requireReader(h.handleListClients))
	h.handle(mux, "GET /api/v1/clients/", h.requireReader(h.handleClientInfo),
		"GET /api/v1/clients/{id}")
	h.handle(mux, "GET /api/v1/revocations", h.requireReader(h.handleListRevocations))
	h.handle(mux, "GET /api/v1/bans", h.requireReader(h.handleListBans))
	h.handle(mux, "GET /api/v1/audit", h.requireReader(h.handleAuditLog))
	h.handle(mux, "GET /api/v1/attestations", h.requireReader(h.handleAttestationLog))

	h.handle(mux, "POST /api/v1/clients/", h.requireAdmin(h.handleClientAction),
		"POST /api/v1/clients/{id}/revoke")
	h.handle(mux, "DELETE /api/v1/clients/", h.requireAdmin(h.handleClientAction),
		"DELETE /api/v1/clients/{id}/revoke", "DELETE /api/v1/clients/{id}")

	h.handle(mux, "GET /api/v1/reanchor/review",
		h.requireReader(h.handleReanchorReviewList))
	// more specific than POST /api/v1/clients/, so the mux routes the
	// acknowledgement here
	h.handle(mux, "POST /api/v1/clients/{clientID}/reanchor-review-ack",
		h.requireAdmin(h.handleReanchorReviewAck),
		"POST /api/v1/clients/{id}/reanchor-review-ack")

	h.handle(mux, "POST /api/v1/clients/{clientID}/reanchor",
		h.requireAdmin(h.handleForceReanchor),
		"POST /api/v1/clients/{id}/reanchor")

	h.handle(mux, "POST /api/v1/bans", h.requireAdmin(h.handleBanHardware))
	h.handle(mux, "DELETE /api/v1/bans/", h.requireAdmin(h.handleUnbanHardware),
		"DELETE /api/v1/bans/{id}")

	// catch-all, so 404/405 use the error envelope; not via handle(),
	// as it is no endpoint to list
	mux.HandleFunc("/", h.handleUnmatched(mux))

	return h
}

// probeMethods are tried against the mux to build Allow. HEAD is left out:
// the mux serves it from the GET route, and it is added whenever GET is allowed.
var probeMethods = []string{
	http.MethodGet, http.MethodPost, http.MethodPut,
	http.MethodPatch, http.MethodDelete, http.MethodOptions,
}

// handleUnmatched answers 405 with Allow when another method serves the path,
// 404 otherwise. Neither echoes the caller's path or method.
func (h *APIHandler) handleUnmatched(mux *http.ServeMux) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var allowed []string
		for _, method := range probeMethods {
			if method == r.Method {
				continue
			}
			probe := r.Clone(r.Context())
			probe.Method = method
			if _, pattern := mux.Handler(probe); pattern != "" && pattern != "/" {
				allowed = append(allowed, method)
			}
		}

		if len(allowed) > 0 {
			if slices.Contains(allowed, http.MethodGet) {
				allowed = append(allowed, http.MethodHead)
			}
			w.Header().Set("Allow", strings.Join(allowed, ", "))
			writeJSONStatus(w, http.StatusMethodNotAllowed,
				errorResponse{Error: "method not allowed on this endpoint; see the Allow header"})
			return
		}

		writeJSONStatus(w, http.StatusNotFound,
			errorResponse{Error: "no such endpoint"})
	}
}

// handle registers pattern and records the endpoints it serves, which differ
// where one pattern dispatches several actions by path; given none, the pattern
// is its own endpoint.
func (h *APIHandler) handle(mux *http.ServeMux, pattern string,
	handler http.HandlerFunc, endpoints ...string,
) {
	h.routes = append(h.routes, pattern)
	if len(endpoints) == 0 {
		endpoints = []string{pattern}
	}
	h.endpoints = append(h.endpoints, endpoints...)
	mux.HandleFunc(pattern, handler)
}

// AdvertisedRoutes returns the endpoints handle registered,
// so the banner names exactly what is served.
func (h *APIHandler) AdvertisedRoutes() []string {
	return h.endpoints
}

type principalCtxKey struct{}

// requestPrincipal returns the authenticated principal of a request,
// nil when the endpoint was served without authentication.
func requestPrincipal(r *http.Request) *Principal {
	if p, ok := r.Context().Value(principalCtxKey{}).(*Principal); ok {
		return p
	}
	return nil
}

// principalAllowsTenant reports whether p may see or act within tenant;
// a nil p may act in every tenant.
func principalAllowsTenant(p *Principal, tenant string) bool {
	if p == nil {
		return true
	}
	return p.AllowsTenant(tenant)
}

// scopedToTenants reports whether p is limited to a tenant set.
func scopedToTenants(p *Principal) bool {
	return p != nil && !p.AllTenants
}

// clientTenant returns the tenant of a client, the default tenant when
// ClientInfo finds none.
func (h *APIHandler) clientTenant(clientID string) (string, error) {
	info, found, err := h.verifier.ClientInfo(clientID)
	if err != nil {
		return "", err
	}
	if found {
		return info.Tenant, nil
	}
	return verify.DefaultTenant, nil
}

// writeStoreError answers a request a store could not serve.
func (h *APIHandler) writeStoreError(w http.ResponseWriter, err error) {
	h.log.Error("store read failed", "error", err)
	writeJSONStatus(w, http.StatusInternalServerError,
		errorResponse{Error: "database unavailable"})
}

func withPrincipal(r *http.Request, p *Principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalCtxKey{}, p))
}

func (h *APIHandler) scopedKeySet() *APIKeySet {
	if h.server == nil {
		return nil
	}
	return h.server.apiKeySet()
}

// resolvePrincipal matches token against the environment keys,
// which cover every tenant, and then the scoped key file.
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

func (h *APIHandler) authConfigured() bool {
	return h.adminAPIKey != "" || h.readerAPIKey != "" || h.scopedKeySet().Len() > 0
}

func (h *APIHandler) adminConfigured() bool {
	return h.adminAPIKey != "" || h.scopedKeySet().Len() > 0
}

// requireAdmin admits a principal with the admin role. A report-only
// instance answers 503 first. With neither an admin key nor a key file every
// call gets 403; otherwise a missing token gets 401 and a key without the
// admin role 403.
func (h *APIHandler) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.reportOnly {
			h.log.Warn("state-changing endpoint called on a reporting instance",
				"method", logging.SanitizeField(r.Method),
				"path", logging.SanitizeField(r.URL.Path),
				"remote_addr", logging.SanitizeField(r.RemoteAddr))
			writeJSONStatus(w, http.StatusServiceUnavailable, errorResponse{
				Error: "this instance serves reports from a read-only database; " +
					"send state changes to an instance on the primary",
			})
			return
		}

		if !h.adminConfigured() {
			h.log.Warn("admin endpoint called but no API key configured",
				"method", logging.SanitizeField(r.Method),
				"path", logging.SanitizeField(r.URL.Path),
				"remote_addr", logging.SanitizeField(r.RemoteAddr))
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
				"method", logging.SanitizeField(r.Method),
				"path", logging.SanitizeField(r.URL.Path),
				"remote_addr", logging.SanitizeField(r.RemoteAddr))
			writeJSONStatus(w, http.StatusForbidden, errorResponse{Error: "invalid API key"})
			return
		}

		next(w, withPrincipal(r, p))
	}
}

// requireReader admits any principal.
// With no key of any kind configured it admits every request.
func (h *APIHandler) requireReader(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.authConfigured() {
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
				"method", logging.SanitizeField(r.Method),
				"path", logging.SanitizeField(r.URL.Path),
				"remote_addr", logging.SanitizeField(r.RemoteAddr))
			writeJSONStatus(w, http.StatusForbidden, errorResponse{Error: "invalid API key"})
			return
		}

		next(w, withPrincipal(r, p))
	}
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(auth[len(prefix):])
}

// tokenMatchesHash compares hashes, so the time does not depend on the key
// length.
func tokenMatchesHash(token string, expectedHash [32]byte) bool {
	tokenHash := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(tokenHash[:], expectedHash[:]) == 1
}

type healthResponse struct {
	Status    string `json:"status"`
	Mode      string `json:"mode,omitempty"` // "reporting" when report-only
	Uptime    string `json:"uptime"`
	UptimeSec int64  `json:"uptime_sec"`
	TLS       struct {
		Listening bool   `json:"listening"`
		Address   string `json:"address"`
	} `json:"tls"`
}

// statsResponse keeps fleet-wide counters as pointers, so a tenant-scoped
// response can omit them.
type statsResponse struct {
	PendingChallenges *int     `json:"pending_challenges,omitempty"`
	UsedNonces        *int     `json:"used_nonces,omitempty"`
	RegisteredClients int      `json:"registered_clients"`
	ActivePolicy      string   `json:"active_policy"`
	LoadedPolicies    []string `json:"loaded_policies"`
	TotalAttestations *int64   `json:"total_attestations,omitempty"`
	SuccessfulAttests *int64   `json:"successful_attestations,omitempty"`
	FailedAttests     *int64   `json:"failed_attestations,omitempty"`
	RevokedAttests    *int64   `json:"revoked_attestations,omitempty"`
	BannedAttests     *int64   `json:"banned_attestations,omitempty"`
	ActiveRevocations int      `json:"active_revocations"`
	ActiveBans        int      `json:"active_bans"`
	Uptime            string   `json:"uptime"`
	UptimeSec         int64    `json:"uptime_sec"`
	TenantScoped      bool     `json:"tenant_scoped,omitempty"`
	Tenants           []string `json:"tenants,omitempty"`
}

// clientListResponse is one page of clients; Next is the after cursor of
// the following page, empty on the last one.
type clientListResponse struct {
	Clients []string `json:"clients"`
	Count   int      `json:"count"`
	Next    string   `json:"next,omitempty"`
}

type clientInfoResponse struct {
	ClientID         string `json:"client_id"`
	Tenant           string `json:"tenant"`
	HardwareID       string `json:"hardware_id,omitempty"`
	Revoked          bool   `json:"revoked"`
	RevocationReason string `json:"revocation_reason,omitempty"`
	LastAttestation  string `json:"last_attestation,omitempty"`
	LastAttestUnix   int64  `json:"last_attestation_unix,omitempty"`
	AttestCount      uint64 `json:"attestation_count"`
	MonotonicCounter uint64 `json:"monotonic_counter"`
	PCR14Baseline    string `json:"pcr14_baseline,omitempty"`
	FirstSeen        string `json:"first_seen,omitempty"`
	FirstSeenUnix    int64  `json:"first_seen_unix,omitempty"`

	MachineKeys *verify.MachineKeys `json:"machine_keys,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// handleHealth answers 503 "degraded" while the attestation listener is not
// accepting; a report-only instance, which has none, answers 200.
func (h *APIHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := h.server.HealthCheck()

	resp := healthResponse{
		Status:    "ok",
		Uptime:    time.Since(h.startTime).Truncate(time.Second).String(),
		UptimeSec: int64(time.Since(h.startTime).Seconds()),
	}
	resp.TLS.Listening = health.Listening
	resp.TLS.Address = health.Address

	if h.reportOnly {
		resp.Mode = "reporting"
		resp.TLS.Address = ""
		writeJSON(w, resp)
		return
	}

	if !health.Listening {
		resp.Status = "degraded"
		writeJSONStatus(w, http.StatusServiceUnavailable, resp)
		return
	}

	writeJSON(w, resp)
}

func (h *APIHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	p := requestPrincipal(r)
	var tenants []string
	if scopedToTenants(p) {
		tenants = sortedTenantSet(p)
	}

	stats, err := h.verifier.Stats(tenants)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}

	resp := statsResponse{
		PendingChallenges: &stats.PendingChallenges,
		UsedNonces:        &stats.UsedNonces,
		RegisteredClients: stats.RegisteredClients,
		ActivePolicy:      stats.ActivePolicy,
		LoadedPolicies:    stats.LoadedPolicies,
		TotalAttestations: &stats.TotalAttestations,
		SuccessfulAttests: &stats.SuccessAttests,
		FailedAttests:     &stats.FailedAttests,
		RevokedAttests:    &stats.RevokedAttests,
		BannedAttests:     &stats.BannedAttests,
		ActiveRevocations: stats.ActiveRevocations,
		ActiveBans:        stats.ActiveBans,
		Uptime:            stats.Uptime.Truncate(time.Second).String(),
		UptimeSec:         int64(stats.Uptime.Seconds()),
	}

	if resp.LoadedPolicies == nil {
		resp.LoadedPolicies = []string{}
	}

	// fleet-wide counters cannot be split per tenant, so they are omitted
	if tenants != nil {
		resp.TenantScoped = true
		resp.Tenants = tenants
		resp.PendingChallenges = nil
		resp.UsedNonces = nil
		resp.TotalAttestations = nil
		resp.SuccessfulAttests = nil
		resp.FailedAttests = nil
		resp.RevokedAttests = nil
		resp.BannedAttests = nil
	}

	writeJSON(w, resp)
}

func sortedTenantSet(p *Principal) []string {
	tenants := make([]string, 0, len(p.Tenants))
	for t := range p.Tenants {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants)
	return tenants
}

func (h *APIHandler) handleListClients(w http.ResponseWriter, r *http.Request) {
	const (
		defaultLimit = 100
		maxLimit     = 1000
	)

	q := r.URL.Query()
	if q.Has("offset") {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{
			Error: "offset pagination is not supported for " +
				"clients; use the after cursor",
		})
		return
	}

	limit := defaultLimit
	parsed, err := strconv.Atoi(q.Get("limit"))
	if err == nil && parsed > 0 {
		limit = min(parsed, maxLimit)
	}

	var tenants []string
	if p := requestPrincipal(r); scopedToTenants(p) {
		tenants = sortedTenantSet(p)
	}

	clients, err := h.verifier.ClientsPage(tenants, q.Get("after"), limit)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}

	resp := clientListResponse{Clients: clients, Count: len(clients)}
	if len(clients) == limit {
		resp.Next = clients[len(clients)-1]
	}
	writeJSON(w, resp)
}

func (h *APIHandler) handleClientInfo(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	clientID := strings.TrimRight(path, "/")

	if clientID == "" {
		h.handleListClients(w, r)
		return
	}

	info, found, err := h.verifier.ClientInfo(clientID)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	if !found {
		writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
		return
	}
	// outside the key's tenants a client reads as absent
	if !principalAllowsTenant(requestPrincipal(r), info.Tenant) {
		writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
		return
	}

	resp := clientInfoResponse{
		ClientID:         info.ClientID,
		Tenant:           info.Tenant,
		HardwareID:       info.HardwareID,
		Revoked:          info.Revoked,
		RevocationReason: info.RevocationReason,
		AttestCount:      info.AttestCount,
		MonotonicCounter: info.MonotonicCounter,
		PCR14Baseline:    info.PCR14Baseline,
		MachineKeys:      info.MachineKeys,
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

func (h *APIHandler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// the exposition has no tenant dimension
	if scopedToTenants(requestPrincipal(r)) {
		writeJSONStatus(w, http.StatusForbidden,
			errorResponse{Error: "metrics are global-scope; use a key with tenants [\"*\"]"})
		return
	}

	stats, err := h.verifier.Stats(nil)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	h.metrics.PendingChallenges.Store(int64(stats.PendingChallenges))
	h.metrics.RegisteredClients.Store(int64(stats.RegisteredClients))
	h.metrics.ActiveRevocations.Store(int64(stats.ActiveRevocations))
	h.metrics.ActiveBans.Store(int64(stats.ActiveBans))
	h.metrics.UsedNonces.Store(int64(stats.UsedNonces))
	h.metrics.LoadedPolicies.Store(int64(len(stats.LoadedPolicies)))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprint(w, h.metrics.Export())
}

type revokeRequest struct {
	Reason string `json:"reason"`
	Actor  string `json:"actor"`
	Note   string `json:"note"`
}

type revocationResponse struct {
	ClientID  string `json:"client_id"`
	Tenant    string `json:"tenant"`
	Reason    string `json:"reason"`
	RevokedAt string `json:"revoked_at"`
	RevokedBy string `json:"revoked_by"`
	Note      string `json:"note"`
}

func (h *APIHandler) handleClientAction(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	parts := strings.SplitN(path, "/", 2)

	clientID := parts[0]
	if clientID == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "missing client ID"})
		return
	}

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

	tenant, err := h.clientTenant(clientID)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	if !principalAllowsTenant(requestPrincipal(r), tenant) {
		writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
		return
	}

	err = revStore.Revoke(tenant, clientID,
		store.RevocationReason(req.Reason), req.Actor, req.Note)
	if err != nil {
		if err == store.ErrAlreadyRevoked {
			writeJSONStatus(w, http.StatusConflict, errorResponse{Error: "client is already revoked"})
			return
		}
		h.log.Error("revocation failed",
			"client_id", logging.SanitizeField(clientID), "error", err)
		writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	logging.Security(h.log, "client revoked",
		"client_id", logging.SanitizeField(clientID),
		"actor", logging.SanitizeField(req.Actor),
		"reason", logging.SanitizeField(req.Reason),
		"note", logging.SanitizeField(req.Note))

	writeJSONStatus(w, http.StatusCreated, map[string]string{
		"status":    "revoked",
		"client_id": clientID,
		"reason":    req.Reason,
	})
}

func (h *APIHandler) handleUnrevokeClient(w http.ResponseWriter, r *http.Request, clientID string) {
	revStore := h.verifier.RevocationStore()
	if revStore == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, errorResponse{Error: "revocation not configured"})
		return
	}

	var req lifecycleRequest
	if r.ContentLength != 0 {
		if err := decodeJSONRequest(w, r, &req); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON: " + err.Error()})
			return
		}
	}
	if req.Actor == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "actor is required"})
		return
	}
	if req.Reason == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "reason is required"})
		return
	}

	// a revocation in another tenant reads as absent
	if scopedToTenants(requestPrincipal(r)) {
		entry, revoked, err := revStore.IsRevoked(clientID)
		if err != nil {
			h.writeStoreError(w, err)
			return
		}
		if !revoked || !principalAllowsTenant(requestPrincipal(r), entry.Tenant) {
			writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client is not revoked"})
			return
		}
	}

	err := revStore.Unrevoke(clientID, req.Reason, req.Actor, req.Note)
	if err != nil {
		if err == store.ErrNotRevoked {
			writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client is not revoked"})
			return
		}
		h.log.Error("unrevoke failed",
			"client_id", logging.SanitizeField(clientID), "error", err)
		writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	logging.Security(h.log, "client unrevoked",
		"client_id", logging.SanitizeField(clientID),
		"actor", logging.SanitizeField(req.Actor),
		"reason", logging.SanitizeField(req.Reason))

	writeJSON(w, map[string]string{
		"status":    "unrevoked",
		"client_id": clientID,
	})
}

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

type banRequest struct {
	HardwareID string `json:"hardware_id"`
	Tenant     string `json:"tenant,omitempty"` // empty = default tenant
	Reason     string `json:"reason"`
	Actor      string `json:"actor"`
	Note       string `json:"note"`
}

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
		"hardware_id", canonicalHWID,
		"tenant", logging.SanitizeField(tenant),
		"actor", logging.SanitizeField(req.Actor),
		"reason", logging.SanitizeField(req.Reason))

	writeJSONStatus(w, http.StatusCreated, map[string]string{
		"status":      "banned",
		"hardware_id": canonicalHWID,
		"tenant":      tenant,
		"reason":      req.Reason,
	})
}

func (h *APIHandler) handleUnbanHardware(w http.ResponseWriter, r *http.Request) {
	banStr := h.verifier.BanStore()
	if banStr == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, errorResponse{Error: "hardware bans not configured"})
		return
	}

	var req unbanRequest
	if r.ContentLength != 0 {
		if err := decodeJSONRequest(w, r, &req); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON: " + err.Error()})
			return
		}
	}
	if req.Actor == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "actor is required"})
		return
	}
	if req.Reason == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "reason is required"})
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

	// a tenant in the query would otherwise be ignored without a word
	if r.URL.Query().Has("tenant") {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{
			Error: "tenant goes in the request body on " +
				"this endpoint",
		})
		return
	}

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

	err = banStr.UnbanHardware(tenant, hwid, req.Reason, req.Actor, req.Note)
	if err != nil {
		if err == store.ErrNotBanned {
			writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "hardware ID is not banned"})
			return
		}
		h.log.Error("unban failed", "hardware_id", canonicalHWID, "error", err)
		writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	logging.Security(h.log, "hardware unbanned",
		"hardware_id", canonicalHWID,
		"tenant", logging.SanitizeField(tenant))

	writeJSON(w, map[string]string{
		"status":      "unbanned",
		"hardware_id": canonicalHWID,
		"tenant":      tenant,
	})
}

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
		if nextID != "" {
			if _, err := store.DecodeBanCursor(nextID); err != nil {
				writeJSONStatus(w, http.StatusBadRequest,
					errorResponse{Error: "invalid next_id"})
				return
			}
		}
		var err error
		entries, err = lister.ListBansAfter(limit+1, nextID)
		if err != nil {
			h.log.Error("failed to list bans", "error", err)
			writeJSONStatus(w, http.StatusInternalServerError,
				errorResponse{Error: "database unavailable"})
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

	// the cursor covers every entry, so a scoped page may come back short
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

	// the store-wide total would count other tenants' bans
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

func (h *APIHandler) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if h.auditLog == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, errorResponse{Error: "audit log not configured"})
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

type attestationResponse struct {
	ID         int64   `json:"id"`
	Timestamp  string  `json:"timestamp"`
	Tenant     string  `json:"tenant,omitempty"`
	ClientID   string  `json:"client_id"`
	HardwareID string  `json:"hardware_id,omitempty"`
	Result     string  `json:"result"`
	DurationMs float64 `json:"duration_ms"`
	PCR14      string  `json:"pcr14,omitempty"`
	KernelHash string  `json:"kernel_hash,omitempty"`
	Details    string  `json:"details,omitempty"`
	RemoteAddr string  `json:"remote_addr,omitempty"`

	LastSeen string `json:"last_seen,omitempty"` // last round of the row
	Rounds   int64  `json:"rounds,omitempty"`    // identical rounds it covers
}

// attestationTimeParam parses an RFC 3339 query value; an unparsable one is
// ignored, widening the window.
func attestationTimeParam(r *http.Request, key string) time.Time {
	v := r.URL.Query().Get(key)
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

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

	q := store.AttestationQuery{
		Limit:      limit,
		Since:      attestationTimeParam(r, "since"),
		Until:      attestationTimeParam(r, "until"),
		Result:     r.URL.Query().Get("result"),
		EventsOnly: r.URL.Query().Get("events") == "true",
		ClientID:   r.URL.Query().Get("client_id"),
	}

	p := requestPrincipal(r)
	entries := h.attestationLog.QueryAttestations(q)
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
			KernelHash: e.KernelHash,
			Details:    sanitizeAttestationDetail(e.Details),
			RemoteAddr: e.RemoteAddr,
			LastSeen:   e.LastSeen.UTC().Format(time.RFC3339),
			Rounds:     e.Rounds,
		})
	}

	writeJSON(w, map[string]any{
		"attestations": resp,
		"count":        len(resp),
	})
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("JSON encode error", "error", err)
	}
}

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
	dec.DisallowUnknownFields()
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

// sanitizeLogField replaces CR and LF in a request-supplied value, so it
// cannot forge log records.
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

// handleReanchorReviewList returns the clients whose Low-Firmware-Assurance
// re-anchor awaits review.
func (h *APIHandler) handleReanchorReviewList(w http.ResponseWriter, r *http.Request) {
	clients, err := h.verifier.ListReanchorReview()
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	if p := requestPrincipal(r); scopedToTenants(p) {
		visible := make([]string, 0, len(clients))
		for _, id := range clients {
			tenant, err := h.clientTenant(id)
			if err != nil {
				h.writeStoreError(w, err)
				return
			}
			if p.AllowsTenant(tenant) {
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

// handleReanchorReviewAck clears a client's pending LFA review. Actor and
// reason are required; a client without a baseline or a pending review is
// refused.
func (h *APIHandler) handleReanchorReviewAck(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("clientID")
	if clientID == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "missing client id"})
		return
	}

	var req lifecycleRequest
	if r.ContentLength != 0 {
		if err := decodeJSONRequest(w, r, &req); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON: " + err.Error()})
			return
		}
	}
	if req.Actor == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "actor is required"})
		return
	}
	if req.Reason == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "reason is required"})
		return
	}

	logID := sanitizeLogField(clientID)

	tenant, err := h.clientTenant(clientID)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	if !principalAllowsTenant(requestPrincipal(r), tenant) {
		writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
		return
	}
	if err := h.verifier.AcknowledgeReanchorReview(clientID); err != nil {
		switch {
		case errors.Is(err, verify.ErrUnknownClient):
			writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
		case errors.Is(err, verify.ErrNoReviewPending):
			writeJSONStatus(w, http.StatusConflict,
				errorResponse{Error: "no re-anchor review pending for this client"})
		default:
			h.log.Error("re-anchor review acknowledgement failed",
				"client_id", logID, "error", err)
			writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		}
		return
	}

	if h.auditLog != nil {
		if err := h.auditLog.Log(tenant, "reanchor_review_ack", clientID,
			req.Reason, req.Actor, req.Note); err != nil {
			h.log.Error("audit log write failed",
				"action", "reanchor_review_ack", "client_id", logID, "error", err)
		}
	}
	h.log.Info("operator acknowledged LFA re-anchor review",
		"client_id", logID,
		"actor", logging.SanitizeField(req.Actor),
		"note", logging.SanitizeField(req.Note))
	writeJSON(w, map[string]string{"status": "reviewed", "client_id": clientID})
}

type lifecycleRequest struct {
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
	Note   string `json:"note"`
}

// unbanRequest names the tenant in the body, as banRequest does:
// a ban is keyed by tenant and hardware ID.
type unbanRequest struct {
	Tenant string `json:"tenant,omitempty"` // empty = default tenant
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
	Note   string `json:"note"`
}

// handleForceReanchor clears a client's baseline, boot baseline included,
// so its next attestation is a first use again.
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
	if req.Reason == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "reason is required"})
		return
	}

	logID := sanitizeLogField(clientID)

	tenant, err := h.clientTenant(clientID)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
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
		if err := h.auditLog.Log(tenant, "reanchor", clientID, req.Reason, req.Actor, req.Note); err != nil {
			h.log.Error("audit log write failed",
				"action", "reanchor", "client_id", logID, "error", err)
		}
	}
	logging.Security(h.log, "client baseline force re-anchored",
		"client_id", logID,
		"actor", logging.SanitizeField(req.Actor),
		"note", logging.SanitizeField(req.Note))

	writeJSON(w, map[string]string{
		"status":    "reanchored",
		"client_id": clientID,
	})
}

// handleDeleteClient clears a client's baseline, boot baseline included,
// and its nonce store state; its next attestation is a first use again.
// Revocations and bans stay.
func (h *APIHandler) handleDeleteClient(w http.ResponseWriter, r *http.Request, clientID string) {
	var req lifecycleRequest
	if r.ContentLength != 0 {
		if err := decodeJSONRequest(w, r, &req); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON: " + err.Error()})
			return
		}
	}

	if req.Actor == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "actor is required"})
		return
	}
	if req.Reason == "" {
		writeJSONStatus(w, http.StatusBadRequest, errorResponse{Error: "reason is required"})
		return
	}

	logID := sanitizeLogField(clientID)

	// resolve the tenant before the delete removes the baseline row
	tenant, err := h.clientTenant(clientID)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	if !principalAllowsTenant(requestPrincipal(r), tenant) {
		writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
		return
	}

	if err := h.verifier.DeleteClient(clientID); err != nil {
		switch {
		case errors.Is(err, verify.ErrUnknownClient):
			writeJSONStatus(w, http.StatusNotFound, errorResponse{Error: "client not found"})
		default:
			h.log.Error("client delete failed", "client_id", logID, "error", err)
			writeJSONStatus(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		}
		return
	}

	if h.auditLog != nil {
		if err := h.auditLog.Log(tenant, "delete_client", clientID, req.Reason, req.Actor, req.Note); err != nil {
			h.log.Error("audit log write failed",
				"action", "delete_client", "client_id", logID, "error", err)
		}
	}
	logging.Security(h.log, "client deleted",
		"client_id", logID,
		"actor", logging.SanitizeField(req.Actor),
		"note", logging.SanitizeField(req.Note))

	writeJSON(w, map[string]string{
		"status":    "deleted",
		"client_id": clientID,
	})
}
