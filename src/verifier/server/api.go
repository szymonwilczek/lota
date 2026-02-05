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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/szymonwilczek/lota/verifier/verify"
)

// serves the monitoring REST API
type APIHandler struct {
	verifier  *verify.Verifier
	server    *Server
	startTime time.Time
}

// creates a new API handler and registers routes on the given mux
func NewAPIHandler(mux *http.ServeMux, verifier *verify.Verifier, srv *Server) *APIHandler {
	h := &APIHandler{
		verifier:  verifier,
		server:    srv,
		startTime: time.Now(),
	}

	mux.HandleFunc("GET /health", h.handleHealth)
	mux.HandleFunc("GET /api/v1/stats", h.handleStats)
	mux.HandleFunc("GET /api/v1/clients", h.handleListClients)
	mux.HandleFunc("GET /api/v1/clients/", h.handleClientInfo)
	mux.HandleFunc("GET /metrics", h.handleMetrics)

	return h
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
	stats := h.verifier.Stats()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	fmt.Fprintf(w, "# HELP lota_pending_challenges Number of outstanding attestation challenges\n")
	fmt.Fprintf(w, "# TYPE lota_pending_challenges gauge\n")
	fmt.Fprintf(w, "lota_pending_challenges %d\n\n", stats.PendingChallenges)

	fmt.Fprintf(w, "# HELP lota_used_nonces Number of consumed nonces in replay history\n")
	fmt.Fprintf(w, "# TYPE lota_used_nonces gauge\n")
	fmt.Fprintf(w, "lota_used_nonces %d\n\n", stats.UsedNonces)

	fmt.Fprintf(w, "# HELP lota_registered_clients Number of registered attestation clients\n")
	fmt.Fprintf(w, "# TYPE lota_registered_clients gauge\n")
	fmt.Fprintf(w, "lota_registered_clients %d\n\n", stats.RegisteredClients)

	fmt.Fprintf(w, "# HELP lota_attestations_total Total number of attestation attempts\n")
	fmt.Fprintf(w, "# TYPE lota_attestations_total counter\n")
	fmt.Fprintf(w, "lota_attestations_total %d\n\n", stats.TotalAttestations)

	fmt.Fprintf(w, "# HELP lota_attestations_success_total Total successful attestations\n")
	fmt.Fprintf(w, "# TYPE lota_attestations_success_total counter\n")
	fmt.Fprintf(w, "lota_attestations_success_total %d\n\n", stats.SuccessAttests)

	fmt.Fprintf(w, "# HELP lota_attestations_failed_total Total failed attestations\n")
	fmt.Fprintf(w, "# TYPE lota_attestations_failed_total counter\n")
	fmt.Fprintf(w, "lota_attestations_failed_total %d\n\n", stats.FailedAttests)

	fmt.Fprintf(w, "# HELP lota_uptime_seconds Verifier uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE lota_uptime_seconds gauge\n")
	fmt.Fprintf(w, "lota_uptime_seconds %.0f\n\n", stats.Uptime.Seconds())

	fmt.Fprintf(w, "# HELP lota_loaded_policies Number of loaded PCR policies\n")
	fmt.Fprintf(w, "# TYPE lota_loaded_policies gauge\n")
	fmt.Fprintf(w, "lota_loaded_policies %d\n", len(stats.LoadedPolicies))
}

// writes JSON response with proper headers
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Printf("JSON encode error: %v", err)
	}
}
