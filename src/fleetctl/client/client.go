// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Fleet CLI - verifier monitoring API client
//
// Typed HTTP client for the verifier's REST monitoring API.
// CLI is pure API consumer:
// it shares no code with the verifier, so it builds and runs against any verifier
// version that speaks the documented endpoint contract.

package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// keep the error body bounded
// API never sends large error payloads
const maxErrorBodyBytes = 64 * 1024

// Config carries the connection parameters for verifier monitoring API.
type Config struct {
	// ServerURL is the API base URL,
	// e.g. http://127.0.0.1:8080 or an https:// URL
	// when the API sits behind TLS-terminating proxy.
	ServerURL string
	// APIKey is the Bearer token (reader or admin tier);
	// empty sends no Authorization header (loopback dev setups only).
	APIKey string
	// CACertPEM optionally pins the TLS roots for an https ServerURL.
	CACertPEM []byte
	// Timeout bounds each request;
	// zero means 30 seconds.
	Timeout time.Duration
}

// Client talks to one verifier monitoring API endpoint.
type Client struct {
	baseURL string
	apiKey  string
	httpc   *http.Client
}

// APIError is a non-2xx response decoded from the API's error envelope.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("API error: HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("API error: HTTP %d: %s", e.StatusCode, e.Message)
}

// New validates the configuration and returns a ready client.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL %q: %w", cfg.ServerURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("server URL %q must use http or https", cfg.ServerURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("server URL %q has no host", cfg.ServerURL)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	httpc := &http.Client{Timeout: timeout}
	if len(cfg.CACertPEM) > 0 {
		if u.Scheme != "https" {
			return nil, errors.New("a CA certificate is only meaningful with an https server URL")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CACertPEM) {
			return nil, errors.New("no certificates parsed from the CA PEM")
		}
		httpc.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}
	}

	return &Client{
		baseURL: strings.TrimRight(u.String(), "/"),
		apiKey:  cfg.APIKey,
		httpc:   httpc,
	}, nil
}

// do runs one API request.
// JSON body is sent when in is non-nil and the response is decoded into out
// when out is non-nil.
// Any status other than the listed ones surfaces as *APIError carrying the
// server's error field.
func (c *Client) do(method, path string, query url.Values, in, out any, okStatus ...int) error {
	reqURL := c.baseURL + path
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	var body io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		body = bytes.NewReader(buf)
	}

	req, err := http.NewRequest(method, reqURL, body)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	ok := false
	for _, s := range okStatus {
		if resp.StatusCode == s {
			ok = true
			break
		}
	}
	if !ok {
		return decodeAPIError(resp)
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decoding %s %s response: %w", method, path, err)
		}
	}
	return nil
}

// decodeAPIError maps a non-OK response onto *APIError,
// preserving the server's {"error": ...} message when one is present.
func decodeAPIError(resp *http.Response) error {
	apiErr := &APIError{StatusCode: resp.StatusCode}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	if err == nil {
		var envelope struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &envelope) == nil {
			apiErr.Message = envelope.Error
		}
	}
	return apiErr
}

// Health is the GET /health response;
// Status is "degraded" when the attestation TLS listener is down
// (the API then answers 503).
type Health struct {
	Status    string `json:"status"`
	Uptime    string `json:"uptime"`
	UptimeSec int64  `json:"uptime_sec"`
	TLS       struct {
		Listening bool   `json:"listening"`
		Address   string `json:"address"`
	} `json:"tls"`
}

// Health fetches the health check.
// Degraded verifier is data, not an error:
// the 503 body is returned like the 200 one.
func (c *Client) Health() (*Health, error) {
	var h Health
	err := c.do(http.MethodGet, "/health", nil, nil, &h,
		http.StatusOK, http.StatusServiceUnavailable)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// Stats is the GET /api/v1/stats response.
type Stats struct {
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
	TenantScoped      bool     `json:"tenant_scoped,omitempty"`
	Tenants           []string `json:"tenants,omitempty"`
}

// Stats fetches the verification engine statistics.
func (c *Client) Stats() (*Stats, error) {
	var s Stats
	if err := c.do(http.MethodGet, "/api/v1/stats", nil, nil, &s, http.StatusOK); err != nil {
		return nil, err
	}
	return &s, nil
}

// ClientPage is one page of the GET /api/v1/clients listing.
type ClientPage struct {
	Clients []string `json:"clients"`
	Count   int      `json:"count"`
	Total   int      `json:"total"`
	Limit   int      `json:"limit"`
	Offset  int      `json:"offset"`
}

// ListClients fetches one page of registered client IDs.
// Zero limit and offset defer to the server defaults.
func (c *Client) ListClients(limit, offset int) (*ClientPage, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}

	var page ClientPage
	if err := c.do(http.MethodGet, "/api/v1/clients", q, nil, &page, http.StatusOK); err != nil {
		return nil, err
	}
	return &page, nil
}

// ClientInfo is the GET /api/v1/clients/{id} response.
type ClientInfo struct {
	ClientID          string `json:"client_id"`
	Tenant            string `json:"tenant,omitempty"`
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

// ClientInfo fetches the per-client attestation details.
func (c *Client) ClientInfo(clientID string) (*ClientInfo, error) {
	var info ClientInfo
	err := c.do(http.MethodGet, "/api/v1/clients/"+url.PathEscape(clientID),
		nil, nil, &info, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// actionRequest is the shared {reason, actor, note} mutation payload.
type actionRequest struct {
	Reason string `json:"reason,omitempty"`
	Actor  string `json:"actor,omitempty"`
	Note   string `json:"note,omitempty"`
}

// banRequest adds the hardware identity to the mutation payload.
type banRequest struct {
	HardwareID string `json:"hardware_id"`
	Tenant     string `json:"tenant,omitempty"`
	Reason     string `json:"reason"`
	Actor      string `json:"actor"`
	Note       string `json:"note,omitempty"`
}

// Revoke revokes a client's AIK.
// Reason must be one of the server's revocation reasons
// (cheating, compromised, hardware_change, admin).
func (c *Client) Revoke(clientID, reason, actor, note string) error {
	return c.do(http.MethodPost, "/api/v1/clients/"+url.PathEscape(clientID)+"/revoke",
		nil, actionRequest{Reason: reason, Actor: actor, Note: note}, nil,
		http.StatusCreated)
}

// Unrevoke lifts a client's revocation.
func (c *Client) Unrevoke(clientID string) error {
	return c.do(http.MethodDelete, "/api/v1/clients/"+url.PathEscape(clientID)+"/revoke",
		nil, nil, nil, http.StatusOK)
}

// Revocation is one entry of the GET /api/v1/revocations listing.
type Revocation struct {
	ClientID  string `json:"client_id"`
	Tenant    string `json:"tenant"`
	Reason    string `json:"reason"`
	RevokedAt string `json:"revoked_at"`
	RevokedBy string `json:"revoked_by"`
	Note      string `json:"note"`
}

// ListRevocations fetches all active revocations.
func (c *Client) ListRevocations() ([]Revocation, error) {
	var resp struct {
		Revocations []Revocation `json:"revocations"`
	}
	err := c.do(http.MethodGet, "/api/v1/revocations", nil, nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return resp.Revocations, nil
}

// Ban bans a hardware identity (hex-encoded 32 bytes) within a tenant.
// Empty tenant defaults to the server's default tenant.
func (c *Client) Ban(hardwareID, tenant, reason, actor, note string) error {
	return c.do(http.MethodPost, "/api/v1/bans", nil,
		banRequest{HardwareID: hardwareID, Tenant: tenant, Reason: reason, Actor: actor, Note: note},
		nil, http.StatusCreated)
}

// Unban lifts a hardware ban within a tenant.
// Empty tenant defaults to the server's default tenant;
// Tenant selects which (tenant, hardware) ban row is lifted.
func (c *Client) Unban(hardwareID, tenant string) error {
	q := url.Values{}
	if tenant != "" {
		q.Set("tenant", tenant)
	}
	return c.do(http.MethodDelete, "/api/v1/bans/"+url.PathEscape(hardwareID),
		q, nil, nil, http.StatusOK)
}

// Ban is one entry of the GET /api/v1/bans listing.
type Ban struct {
	HardwareID string `json:"hardware_id"`
	Tenant     string `json:"tenant"`
	Reason     string `json:"reason"`
	BannedAt   string `json:"banned_at"`
	BannedBy   string `json:"banned_by"`
	Note       string `json:"note"`
}

// BanPage is one keyset-paged GET /api/v1/bans response;
// non-empty NextID is the cursor for the following page.
type BanPage struct {
	Bans   []Ban  `json:"bans"`
	Count  int    `json:"count"`
	Total  int    `json:"total"`
	Limit  int    `json:"limit"`
	NextID string `json:"next_id,omitempty"`
}

// ListBans fetches one page of active hardware bans.
// Zero limit defers to the server default;
// nextID continues from a previous page's cursor.
func (c *Client) ListBans(limit int, nextID string) (*BanPage, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if nextID != "" {
		q.Set("next_id", nextID)
	}

	var page BanPage
	if err := c.do(http.MethodGet, "/api/v1/bans", q, nil, &page, http.StatusOK); err != nil {
		return nil, err
	}
	return &page, nil
}

// Reanchor drops a client's stored baselines so its next attestation
// re-establishes trust (the operator-forced re-baseline).
func (c *Client) Reanchor(clientID, actor, note string) error {
	return c.do(http.MethodPost, "/api/v1/clients/"+url.PathEscape(clientID)+"/reanchor",
		nil, actionRequest{Actor: actor, Note: note}, nil, http.StatusOK)
}

// DeleteClient removes a client's registration and baselines, forcing fresh enrollment.
// Revocations and hardware bans survive.
// Actor and note are optional audit metadata.
func (c *Client) DeleteClient(clientID, actor, note string) error {
	var body any
	if actor != "" || note != "" {
		body = actionRequest{Actor: actor, Note: note}
	}
	return c.do(http.MethodDelete, "/api/v1/clients/"+url.PathEscape(clientID),
		nil, body, nil, http.StatusOK)
}

// ReanchorReviewList fetches the clients that re-anchored on the
// Low-Firmware-Assurance path and still await operator review.
func (c *Client) ReanchorReviewList() ([]string, error) {
	var resp struct {
		PendingReview []string `json:"pending_review"`
	}
	err := c.do(http.MethodGet, "/api/v1/reanchor/review", nil, nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return resp.PendingReview, nil
}

// ReanchorReviewAck clears a client's pending-review flag.
func (c *Client) ReanchorReviewAck(clientID string) error {
	return c.do(http.MethodPost,
		"/api/v1/clients/"+url.PathEscape(clientID)+"/reanchor-review-ack",
		nil, nil, nil, http.StatusOK)
}

// AuditEntry is one entry of the GET /api/v1/audit listing.
type AuditEntry struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Tenant    string `json:"tenant"`
	Action    string `json:"action"`
	TargetID  string `json:"target_id"`
	Reason    string `json:"reason,omitempty"`
	Actor     string `json:"actor,omitempty"`
	Note      string `json:"note,omitempty"`
}

// Audit fetches the most recent operator audit entries.
// Zero limit defers to the server default.
func (c *Client) Audit(limit int) ([]AuditEntry, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}

	var resp struct {
		Entries []AuditEntry `json:"entries"`
	}
	if err := c.do(http.MethodGet, "/api/v1/audit", q, nil, &resp, http.StatusOK); err != nil {
		return nil, err
	}
	return resp.Entries, nil
}

// Attestation is one entry of the GET /api/v1/attestations listing.
type Attestation struct {
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

// Attestations fetches the most recent attestation decisions.
// Zero limit defers to the server default.
func (c *Client) Attestations(limit int) ([]Attestation, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}

	var resp struct {
		Attestations []Attestation `json:"attestations"`
	}
	err := c.do(http.MethodGet, "/api/v1/attestations", q, nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return resp.Attestations, nil
}

// sessionTokenRequest is the POST /api/v1/session/validate payload.
type sessionTokenRequest struct {
	SessionToken string `json:"session_token"`
	Consume      bool   `json:"consume"`
}

// SessionTokenStatus is the POST /api/v1/session/validate response.
type SessionTokenStatus struct {
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

// ValidateSessionToken checks an issued session token (64 hex characters);
// consume additionally marks it used so it cannot validate again.
func (c *Client) ValidateSessionToken(token string, consume bool) (*SessionTokenStatus, error) {
	var status SessionTokenStatus
	err := c.do(http.MethodPost, "/api/v1/session/validate", nil,
		sessionTokenRequest{SessionToken: token, Consume: consume},
		&status, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &status, nil
}
