// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

// Package client is a client of the verifier's monitoring API that imports
// no verifier code.
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

const maxErrorBodyBytes = 64 * 1024

// Config carries the connection parameters for verifier monitoring API.
type Config struct {
	ServerURL string // http or https, with a host
	APIKey    string // Bearer token; empty sends no Authorization header

	// CACertPEM, if set, replaces the system roots for an https ServerURL.
	CACertPEM []byte

	Timeout time.Duration // per request; zero means 30 seconds
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

// do sends in as JSON when non-nil and decodes into out when non-nil;
// a status not in okStatus is an *APIError.
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

// Health is the GET /health response. Status is "degraded", with HTTP 503,
// while the attestation listener is not accepting; a report-only verifier
// has none and answers "ok".
type Health struct {
	Status    string `json:"status"`
	Mode      string `json:"mode,omitempty"`
	Uptime    string `json:"uptime"`
	UptimeSec int64  `json:"uptime_sec"`
	TLS       struct {
		Listening bool   `json:"listening"`
		Address   string `json:"address"`
	} `json:"tls"`
}

// Health fetches the health check; a 503 is returned as Health,
// not as an error.
func (c *Client) Health() (*Health, error) {
	var h Health
	err := c.do(http.MethodGet, "/health", nil, nil, &h,
		http.StatusOK, http.StatusServiceUnavailable)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// Stats is the GET /api/v1/stats response. The pointer counters are nil
// when the key is tenant-scoped.
type Stats struct {
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

// Stats fetches the verification engine statistics.
func (c *Client) Stats() (*Stats, error) {
	var s Stats
	if err := c.do(http.MethodGet, "/api/v1/stats", nil, nil, &s, http.StatusOK); err != nil {
		return nil, err
	}
	return &s, nil
}

// ClientPage is one page of the GET /api/v1/clients listing. Next is the
// after cursor of the following page, empty on the last one.
type ClientPage struct {
	Clients []string `json:"clients"`
	Count   int      `json:"count"`
	Next    string   `json:"next,omitempty"`
}

// ListClients fetches up to limit client IDs that sort after after.
// A zero limit defers to the server default; an empty after starts at
// the first client.
func (c *Client) ListClients(limit int, after string) (*ClientPage, error) {
	q := url.Values{}
	if after != "" {
		q.Set("after", after)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}

	var page ClientPage
	if err := c.do(http.MethodGet, "/api/v1/clients", q, nil, &page, http.StatusOK); err != nil {
		return nil, err
	}
	return &page, nil
}

// ClientInfo is the GET /api/v1/clients/{id} response.
type ClientInfo struct {
	ClientID         string `json:"client_id"`
	Tenant           string `json:"tenant,omitempty"`
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

	MachineKeys *MachineKeys `json:"machine_keys,omitempty"`
}

// MachineKeys lists the db and MOK keys a client last reported;
// the verifier records them but no verdict depends on them.
type MachineKeys struct {
	DB       []MachineKey `json:"db"`
	MOK      []MachineKey `json:"mok"`
	MOKState string       `json:"mok_state"`
}

// MachineKey is one signature database entry.
type MachineKey struct {
	Type    string `json:"type"`
	SHA256  string `json:"sha256"`
	Subject string `json:"subject,omitempty"`
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

type actionRequest struct {
	Reason string `json:"reason,omitempty"`
	Actor  string `json:"actor,omitempty"`
	Note   string `json:"note,omitempty"`
}

type unbanRequest struct {
	Tenant string `json:"tenant,omitempty"`
	Reason string `json:"reason,omitempty"`
	Actor  string `json:"actor,omitempty"`
	Note   string `json:"note,omitempty"`
}

type banRequest struct {
	HardwareID string `json:"hardware_id"`
	Tenant     string `json:"tenant,omitempty"`
	Reason     string `json:"reason"`
	Actor      string `json:"actor"`
	Note       string `json:"note,omitempty"`
}

// Revoke revokes a client's AIK. The verifier accepts the reasons
// cheating, compromised, hardware_change and admin.
func (c *Client) Revoke(clientID, reason, actor, note string) error {
	return c.do(http.MethodPost, "/api/v1/clients/"+url.PathEscape(clientID)+"/revoke",
		nil, actionRequest{Reason: reason, Actor: actor, Note: note}, nil,
		http.StatusCreated)
}

// Unrevoke lifts a client's revocation.
func (c *Client) Unrevoke(clientID, reason, actor, note string) error {
	return c.do(http.MethodDelete, "/api/v1/clients/"+url.PathEscape(clientID)+"/revoke",
		nil, actionRequest{Reason: reason, Actor: actor, Note: note}, nil,
		http.StatusOK)
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

// Ban bans a hardware ID of 64 hex digits in tenant, the default tenant
// when empty.
func (c *Client) Ban(hardwareID, tenant, reason, actor, note string) error {
	return c.do(http.MethodPost, "/api/v1/bans", nil,
		banRequest{HardwareID: hardwareID, Tenant: tenant, Reason: reason, Actor: actor, Note: note},
		nil, http.StatusCreated)
}

// Unban lifts the ban of a hardware ID in tenant, the default tenant when
// empty.
func (c *Client) Unban(hardwareID, tenant, reason, actor, note string) error {
	return c.do(http.MethodDelete, "/api/v1/bans/"+url.PathEscape(hardwareID),
		nil, unbanRequest{Tenant: tenant, Reason: reason, Actor: actor, Note: note}, nil,
		http.StatusOK)
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

// BanPage is one page of GET /api/v1/bans; a non-empty NextID continues it.
type BanPage struct {
	Bans   []Ban  `json:"bans"`
	Count  int    `json:"count"`
	Total  int    `json:"total"`
	Limit  int    `json:"limit"`
	NextID string `json:"next_id,omitempty"`
}

// ListBans fetches one page of active hardware bans; zero limit and empty
// nextID are left to the server.
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

// Reanchor clears a client's baseline, boot baseline included,
// so its next attestation is a first use again.
func (c *Client) Reanchor(clientID, reason, actor, note string) error {
	return c.do(http.MethodPost, "/api/v1/clients/"+url.PathEscape(clientID)+"/reanchor",
		nil, actionRequest{Reason: reason, Actor: actor, Note: note}, nil,
		http.StatusOK)
}

// DeleteClient removes a client's baselines and nonce store state; its
// revocations and hardware bans stay. The verifier requires reason and actor.
func (c *Client) DeleteClient(clientID, reason, actor, note string) error {
	return c.do(http.MethodDelete, "/api/v1/clients/"+url.PathEscape(clientID),
		nil, actionRequest{Reason: reason, Actor: actor, Note: note}, nil,
		http.StatusOK)
}

// ReanchorReviewList fetches the clients whose Low-Firmware-Assurance
// re-anchor awaits review.
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

// ReanchorReviewAck clears a client's pending review.
func (c *Client) ReanchorReviewAck(clientID, reason, actor, note string) error {
	return c.do(http.MethodPost,
		"/api/v1/clients/"+url.PathEscape(clientID)+"/reanchor-review-ack",
		nil, actionRequest{Reason: reason, Actor: actor, Note: note}, nil,
		http.StatusOK)
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
