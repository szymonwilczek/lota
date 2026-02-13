// SPDX-License-Identifier: MIT
// LOTA Verifier - TLS server
//
// Handles incoming attestation requests over TLS.
// Protocol:
//   1. Client connects via TLS
//   2. Server sends Challenge (48 bytes)
//   3. Client sends AttestationReport
//   4. Server sends VerifyResult (56 bytes)

package server

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
	"github.com/szymonwilczek/lota/verifier/verify"
)

type Server struct {
	verifier   *verify.Verifier
	auditLog   store.AuditLog
	listener   net.Listener
	tlsConfig  *tls.Config
	addr       string
	shutdownCh chan struct{}
	wg         sync.WaitGroup

	// http monitoring api
	httpServer   *http.Server
	httpAddr     string
	adminAPIKey  string
	readerAPIKey string

	// structured logging and telemetry
	log     *slog.Logger
	metrics *metrics.Metrics

	// optional: attestation decision log
	attestationLog store.AttestationLog

	// timeouts
	readTimeout  time.Duration
	writeTimeout time.Duration
}

type ServerConfig struct {
	// address to listen on (binary TLS protocol)
	Address string

	// address for HTTP monitoring API (empty = disabled)
	HTTPAddress string

	// tls certificate and key paths
	CertFile string
	KeyFile  string

	// optional: audit log for revocation/ban API
	AuditLog store.AuditLog

	// optional: structured logger (nil = nop)
	Logger *slog.Logger

	// optional: shared metrics registry (nil = fresh)
	Metrics *metrics.Metrics

	// optional: attestation decision log for HTTP API
	AttestationLog store.AttestationLog

	// admin API key for mutating endpoints (empty = admin endpoints disabled)
	AdminAPIKey string

	// reader API key for sensitive read-only endpoints (empty = public)
	ReaderAPIKey string

	// timeouts
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Address:      ":8443",
		HTTPAddress:  "",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
}

func NewServer(cfg ServerConfig, verifier *verify.Verifier) (*Server, error) {
	// load tls certificate
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	logger := cfg.Logger
	if logger == nil {
		logger = logging.Nop()
	}

	m := cfg.Metrics
	if m == nil {
		m = metrics.New()
	}

	return &Server{
		verifier:       verifier,
		auditLog:       cfg.AuditLog,
		tlsConfig:      tlsConfig,
		addr:           cfg.Address,
		httpAddr:       cfg.HTTPAddress,
		adminAPIKey:    cfg.AdminAPIKey,
		readerAPIKey:   cfg.ReaderAPIKey,
		log:            logger,
		metrics:        m,
		attestationLog: cfg.AttestationLog,
		shutdownCh:     make(chan struct{}),
		readTimeout:    cfg.ReadTimeout,
		writeTimeout:   cfg.WriteTimeout,
	}, nil
}

func (s *Server) Start() error {
	listener, err := tls.Listen("tcp", s.addr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	s.listener = listener
	s.log.Info("LOTA Verifier listening", "addr", s.addr)

	go s.acceptLoop()

	if s.httpAddr != "" {
		if err := s.startHTTP(); err != nil {
			return fmt.Errorf("failed to start HTTP API: %w", err)
		}
	}

	return nil
}

// checks if the given address binds to loopback only
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// starts the HTTP monitoring API server
func (s *Server) startHTTP() error {
	mux := http.NewServeMux()
	NewAPIHandler(mux, s.verifier, s, s.auditLog, s.log, s.metrics, s.attestationLog, s.adminAPIKey, s.readerAPIKey)

	s.httpServer = &http.Server{
		Addr:         s.httpAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ln, err := net.Listen("tcp", s.httpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.httpAddr, err)
	}

	if !isLoopbackAddr(s.httpAddr) {
		if s.tlsConfig == nil {
			ln.Close()
			return fmt.Errorf("HTTP API on non-loopback address %s requires TLS; configure CertFile/KeyFile or use 127.0.0.1", s.httpAddr)
		}
		ln = tls.NewListener(ln, s.tlsConfig)
		s.log.Info("HTTP API using TLS (non-loopback address)")
	} else {
		s.log.Warn("HTTP API listening without TLS (loopback only)")
	}

	s.log.Info("LOTA Monitoring API listening",
		"addr", s.httpAddr,
		"admin_auth", s.adminAPIKey != "",
		"reader_auth", s.readerAPIKey != "",
		"endpoints", []string{
			"GET /health",
			"GET /api/v1/stats",
			"GET /api/v1/clients",
			"GET /api/v1/clients/{id}",
			"POST /api/v1/clients/{id}/revoke",
			"DELETE /api/v1/clients/{id}/revoke",
			"GET /api/v1/revocations",
			"POST /api/v1/bans",
			"DELETE /api/v1/bans/{id}",
			"GET /api/v1/bans",
			"GET /api/v1/audit",
			"GET /api/v1/attestations",
			"GET /metrics",
		})

	go func() {
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.log.Error("HTTP server error", "error", err)
		}
	}()

	return nil
}

func (s *Server) Stop() {
	close(s.shutdownCh)

	// graceful HTTP shutdown
	if s.httpServer != nil {
		s.httpServer.Close()
	}

	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdownCh:
				return
			default:
				s.log.Error("accept error", "error", err)
				s.metrics.ConnectionErrors.Inc()
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	clog := s.log.With("remote_addr", clientAddr)

	// IP without port serves as challenge binding for nonce anti-replay.
	// verifier derives persistent client identity from the TPM
	// HardwareID inside the attestation report, so clients behind NAT
	// are correctly distinguished
	clientIP, _, err := net.SplitHostPort(clientAddr)
	if err != nil {
		clientIP = clientAddr // fallback if no port
	}
	challengeID := clientIP

	challenge, err := s.verifier.GenerateChallenge(challengeID)
	if err != nil {
		clog.Error("failed to generate challenge", "error", err)
		s.metrics.ConnectionErrors.Inc()
		return
	}

	conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	challengeData := challenge.Serialize()
	if _, err := conn.Write(challengeData); err != nil {
		clog.Error("failed to send challenge", "error", err)
		s.metrics.ConnectionErrors.Inc()
		return
	}

	clog.Debug("challenge sent")

	// read attestation report
	conn.SetReadDeadline(time.Now().Add(s.readTimeout))

	// read header to get total size
	headerBuf := make([]byte, 32)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		clog.Error("failed to read report header", "error", err)
		s.metrics.ConnectionErrors.Inc()
		return
	}

	// validate magic
	magic := binary.LittleEndian.Uint32(headerBuf[0:4])
	if magic != types.ReportMagic {
		clog.Warn("invalid report magic", "magic", fmt.Sprintf("0x%08X", magic))
		s.metrics.ConnectionErrors.Inc()
		s.sendErrorResult(conn, types.VerifyOldVersion)
		return
	}

	// get total size
	totalSize := binary.LittleEndian.Uint32(headerBuf[24:28])
	if totalSize < 32 || totalSize > 64*1024 { // 64KB max
		clog.Warn("invalid report size", "size", totalSize)
		s.metrics.ConnectionErrors.Inc()
		s.sendErrorResult(conn, types.VerifyOldVersion)
		return
	}

	// read rest of report
	reportData := make([]byte, totalSize)
	copy(reportData[:32], headerBuf)

	if totalSize > 32 {
		if _, err := io.ReadFull(conn, reportData[32:]); err != nil {
			clog.Error("failed to read report body", "error", err)
			s.metrics.ConnectionErrors.Inc()
			return
		}
	}

	clog.Debug("report received", "size", totalSize)

	result, err := s.verifier.VerifyReport(challengeID, reportData)
	if err != nil {
		clog.Warn("verification failed", "error", err)
	}

	s.sendResult(conn, result)

	if result.Result == types.VerifyOK {
		clog.Info("attestation successful",
			"valid_until", time.Unix(int64(result.ValidUntil), 0).UTC())
	}
}

// sends the full verification result, preserving SessionToken and ValidUntil
func (s *Server) sendResult(conn net.Conn, result *types.VerifyResult) {
	conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	conn.Write(result.Serialize())
}

// sends an error result when no full VerifyResult is available
func (s *Server) sendErrorResult(conn net.Conn, resultCode uint32) {
	s.sendResult(conn, &types.VerifyResult{
		Magic:   types.ReportMagic,
		Version: types.ReportVersion,
		Result:  resultCode,
	})
}

type HealthStatus struct {
	Listening         bool
	Address           string
	ActiveConnections int
	Stats             verify.Stats
}

func (s *Server) HealthCheck() HealthStatus {
	return HealthStatus{
		Listening: s.listener != nil,
		Address:   s.addr,
		Stats:     s.verifier.Stats(),
	}
}
