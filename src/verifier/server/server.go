// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - TLS server

package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
	"github.com/szymonwilczek/lota/verifier/verify"
)

func newChallengeID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

func unixTimeFromUint64(ts uint64) time.Time {
	const maxInt64AsUint64 = uint64(1<<63 - 1)

	if ts > maxInt64AsUint64 {
		return time.Unix(1<<63-1, 0)
	}
	return time.Unix(int64(ts), 0)
}

// Server serves the attestation protocol over TLS and, given an HTTP
// address, the monitoring API.
type Server struct {
	verifier  *verify.Verifier
	auditLog  store.AuditLog
	listener  net.Listener
	tlsConfig *tls.Config
	addr      string

	// cleared by Stop or when the accept loop loses the listener
	serving       atomic.Bool
	shutdownDrain time.Duration

	shutdownCh chan struct{}
	wg         sync.WaitGroup
	connSem    chan struct{} // nil = no cap

	httpServer     *http.Server
	reportOnly     bool
	httpAddr       string
	adminAPIKey    string
	readerAPIKey   string
	scopedKeysFile string
	apiKeys        atomic.Pointer[APIKeySet]

	log     *slog.Logger
	metrics *metrics.Metrics

	attestationLog store.AttestationLog

	readTimeout  time.Duration
	writeTimeout time.Duration
}

// ServerConfig configures NewServer.
type ServerConfig struct {
	Address string

	HTTPAddress string // empty = no monitoring API

	// ReportOnly opens no attestation listener and refuses mutating
	// endpoints.
	ReportOnly bool

	CertFile string
	KeyFile  string

	AuditLog store.AuditLog

	Logger *slog.Logger // nil = nop

	Metrics *metrics.Metrics // nil = fresh

	AttestationLog store.AttestationLog

	AdminAPIKey string

	ReaderAPIKey string

	ScopedKeysFile string // empty = environment keys only

	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// ShutdownDrain is how long Stop keeps the monitoring API answering
	// after the attestation listener closes, while /health reads degraded.
	ShutdownDrain time.Duration

	// MaxConnections caps concurrent attestation connections; 0 means
	// DefaultMaxConnections and a negative value removes the cap.
	MaxConnections int
}

const (
	DefaultMaxConnections = 256

	UnlimitedConnections = -1
)

// connectionCap returns the semaphore size for configured; 0 means none.
func connectionCap(configured int) int {
	switch {
	case configured == 0:
		return DefaultMaxConnections
	case configured < 0:
		return 0
	default:
		return configured
	}
}

// NewServer loads the TLS certificate and the scoped key file.
// A report-only server may go without a certificate, but then refuses
// a non-loopback monitoring API.
func NewServer(cfg ServerConfig, verifier *verify.Verifier) (*Server, error) {
	var tlsConfig *tls.Config
	if cfg.CertFile != "" || cfg.KeyFile != "" || !cfg.ReportOnly {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = logging.Nop()
	}

	m := cfg.Metrics
	if m == nil {
		m = metrics.New()
	}

	s := &Server{
		verifier:       verifier,
		auditLog:       cfg.AuditLog,
		tlsConfig:      tlsConfig,
		addr:           cfg.Address,
		httpAddr:       cfg.HTTPAddress,
		adminAPIKey:    cfg.AdminAPIKey,
		readerAPIKey:   cfg.ReaderAPIKey,
		scopedKeysFile: cfg.ScopedKeysFile,
		log:            logger,
		metrics:        m,
		attestationLog: cfg.AttestationLog,
		shutdownCh:     make(chan struct{}),
		shutdownDrain:  cfg.ShutdownDrain,
		readTimeout:    cfg.ReadTimeout,
		writeTimeout:   cfg.WriteTimeout,
		reportOnly:     cfg.ReportOnly,
	}

	if cfg.ScopedKeysFile != "" {
		set, err := LoadAPIKeysFile(cfg.ScopedKeysFile)
		if err != nil {
			return nil, err
		}
		s.apiKeys.Store(set)
		logger.Info("scoped API keys loaded", "path", cfg.ScopedKeysFile, "keys", set.Len())
	}

	if n := connectionCap(cfg.MaxConnections); n > 0 {
		s.connSem = make(chan struct{}, n)
	} else {
		logger.Warn("attestation listener running without a connection cap",
			"hint", "set --max-connections to bound concurrent attestations")
	}

	return s, nil
}

// Start opens the attestation listener and, given an HTTP address,
// the monitoring API. A report-only server opens the API alone and needs
// the address.
func (s *Server) Start() error {
	if s.reportOnly {
		if s.httpAddr == "" {
			return fmt.Errorf("a reporting instance serves only the monitoring API and needs an address to serve it on")
		}
		if err := s.startHTTP(); err != nil {
			return fmt.Errorf("failed to start HTTP API: %w", err)
		}
		s.log.Info("LOTA Verifier serving reports only",
			"note", "no attestation listener; every endpoint that changes fleet state is refused")
		return nil
	}

	listener, err := tls.Listen("tcp", s.addr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	s.listener = listener
	s.serving.Store(true)
	s.log.Info("LOTA Verifier listening", "addr", s.addr)

	go s.acceptLoop()

	if s.httpAddr != "" {
		if err := s.startHTTP(); err != nil {
			return fmt.Errorf("failed to start HTTP API: %w", err)
		}
	}

	return nil
}

// isLoopbackAddr reports whether addr names a loopback IP;
// a hostname does not count.
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

// newMonitoringHTTPServer builds the monitoring API server. ReadHeaderTimeout
// caps the header read on its own, so a slow-header client cannot hold a
// connection for the full ReadTimeout.
func newMonitoringHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func (s *Server) startHTTP() error {
	mux := http.NewServeMux()
	api := NewAPIHandler(mux, s.verifier, s, s.auditLog, s.log, s.metrics, s.attestationLog, s.adminAPIKey, s.readerAPIKey)

	s.httpServer = newMonitoringHTTPServer(s.httpAddr, mux)

	ln, err := net.Listen("tcp", s.httpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.httpAddr, err)
	}

	if !isLoopbackAddr(s.httpAddr) {
		if s.tlsConfig == nil {
			ln.Close()
			return fmt.Errorf("HTTP API on non-loopback address %s requires TLS; configure CertFile/KeyFile or use 127.0.0.1", s.httpAddr)
		}
		// with no key requireReader serves its endpoints to anyone
		if s.readerAPIKey == "" && s.adminAPIKey == "" && s.apiKeys.Load().Len() == 0 {
			ln.Close()
			return fmt.Errorf("HTTP API on non-loopback address %s requires authentication; set LOTA_READER_API_KEY (and/or LOTA_ADMIN_API_KEY), provide --api-keys-file, or bind 127.0.0.1", s.httpAddr)
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
		"scoped_keys", s.apiKeys.Load().Len(),
		"endpoints", api.AdvertisedRoutes())

	go func() {
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.log.Error("HTTP server error", "error", err)
		}
	}()

	return nil
}

// Stop closes the attestation listener first, so /health turns `degraded`
// while the monitoring API still answers, then stops the API.
func (s *Server) Stop() {
	close(s.shutdownCh)

	if s.listener != nil {
		s.serving.Store(false)
		if err := s.listener.Close(); err != nil {
			s.log.Warn("listener close failed", "error", err)
		}
	}

	if s.shutdownDrain > 0 {
		s.log.Info("draining", "for", s.shutdownDrain,
			"health", "degraded while the API answers")
		time.Sleep(s.shutdownDrain)
	}

	s.verifier.Close()

	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.log.Warn("HTTP shutdown failed", "error", err)
		}
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
			}
			// a closed listener never accepts again
			if errors.Is(err, net.ErrClosed) {
				s.serving.Store(false)
				s.log.Error("attestation listener closed; this instance serves no attestations",
					"addr", s.addr, "health", "degraded")
				s.metrics.ConnectionErrors.Inc()
				return
			}
			s.log.Error("accept error", "error", err)
			s.metrics.ConnectionErrors.Inc()
			continue
		}

		if s.connSem != nil {
			select {
			case s.connSem <- struct{}{}:
			default:
				s.log.Warn("connection limit reached, rejecting",
					"remote_addr", conn.RemoteAddr())
				s.metrics.ConnectionErrors.Inc()
				conn.Close()
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// peerLeftBeforeProtocol reports whether err is the peer hanging up,
// which before the report is not counted as a connection error.
func peerLeftBeforeProtocol(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, net.ErrClosed)
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	if s.connSem != nil {
		defer func() { <-s.connSem }()
	}

	clientAddr := conn.RemoteAddr().String()

	clientIP, _, err := net.SplitHostPort(clientAddr)
	if err != nil {
		clientIP = clientAddr
	}

	// handshake first, so a silent peer leaves no challenge pending
	if tlsConn, ok := conn.(*tls.Conn); ok {
		ctx, cancel := context.WithTimeout(context.Background(), s.readTimeout)
		err := tlsConn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			if peerLeftBeforeProtocol(err) {
				s.log.Debug("connection closed before the protocol started",
					"remote_addr", clientAddr, "client_ip", clientIP)
				return
			}
			s.log.Warn("TLS handshake failed",
				"remote_addr", clientAddr, "client_ip", clientIP,
				"error", err)
			s.metrics.ConnectionErrors.Inc()
			return
		}
	}

	challengeID, err := newChallengeID()
	if err != nil {
		s.log.Error("failed to generate challenge id", "error", err)
		s.metrics.ConnectionErrors.Inc()
		return
	}

	clog := s.log.With("remote_addr", clientAddr, "client_ip", clientIP, "challenge_id", challengeID)

	challenge, err := s.verifier.GenerateChallenge(challengeID)
	if err != nil {
		clog.Error("failed to generate challenge", "error", err)
		s.metrics.ConnectionErrors.Inc()
		return
	}

	if err := conn.SetWriteDeadline(time.Now().Add(s.writeTimeout)); err != nil {
		clog.Error("failed to set write deadline", "error", err)
		s.metrics.ConnectionErrors.Inc()
		return
	}
	challengeData := challenge.Serialize()
	if _, err := conn.Write(challengeData); err != nil {
		if peerLeftBeforeProtocol(err) {
			clog.Debug("peer left before the challenge was sent")
			s.verifier.DiscardChallenge(challenge, challengeID)
			return
		}
		clog.Error("failed to send challenge", "error", err)
		s.metrics.ConnectionErrors.Inc()
		return
	}

	clog.Debug("challenge sent")

	if err := conn.SetReadDeadline(time.Now().Add(s.readTimeout)); err != nil {
		clog.Error("failed to set read deadline", "error", err)
		s.metrics.ConnectionErrors.Inc()
		return
	}

	headerBuf := make([]byte, 32)
	if n, err := io.ReadFull(conn, headerBuf); err != nil {
		if n == 0 && peerLeftBeforeProtocol(err) {
			clog.Debug("peer left without sending a report")
			s.verifier.DiscardChallenge(challenge, challengeID)
			return
		}
		clog.Error("failed to read report header", "error", err)
		s.metrics.ConnectionErrors.Inc()
		return
	}

	magic := binary.LittleEndian.Uint32(headerBuf[0:4])
	if magic != types.ReportMagic {
		clog.Warn("invalid report magic", "magic", fmt.Sprintf("0x%08X", magic))
		s.metrics.ConnectionErrors.Inc()
		// foreign magic is a damaged frame, not an old wire
		s.sendErrorResult(conn, types.VerifyReportMalformed)
		return
	}

	totalSize := binary.LittleEndian.Uint32(headerBuf[8:12])
	if totalSize < 32 || totalSize > types.MaxReportWireSize {
		clog.Warn("invalid report size", "size", totalSize)
		s.metrics.ConnectionErrors.Inc()
		s.sendErrorResult(conn, types.VerifyReportMalformed)
		return
	}

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

	result, err := s.verifier.VerifyReportFrom(challengeID, clientAddr, reportData)
	if err != nil {
		clog.Warn("verification failed", "error", err)
	}

	s.sendResult(conn, result)

	if result.Result == types.VerifyOK {
		clog.Info("attestation successful",
			"valid_until", unixTimeFromUint64(result.ValidUntil).UTC())
	}
}

func (s *Server) sendResult(conn net.Conn, result *types.VerifyResult) {
	if err := conn.SetWriteDeadline(time.Now().Add(s.writeTimeout)); err != nil {
		s.log.Warn("failed to set write deadline", "error", err)
		return
	}
	if _, err := conn.Write(result.Serialize()); err != nil {
		s.log.Warn("failed to send result",
			"remote_addr", conn.RemoteAddr(), "error", err)
	}
}

func (s *Server) sendErrorResult(conn net.Conn, resultCode uint32) {
	s.sendResult(conn, &types.VerifyResult{
		Magic:   types.ReportMagic,
		Version: types.ReportVersion,
		Result:  resultCode,
	})
}

// HealthStatus is the attestation listener state /health reports.
type HealthStatus struct {
	Listening bool
	Address   string
}

// HealthCheck reports whether the attestation listener is accepting.
func (s *Server) HealthCheck() HealthStatus {
	return HealthStatus{
		Listening: s.serving.Load(),
		Address:   s.addr,
	}
}

// apiKeySet returns the scoped key set, nil without a key file.
func (s *Server) apiKeySet() *APIKeySet {
	return s.apiKeys.Load()
}

// ReloadAPIKeys re-reads the scoped API key file and swaps in the new set;
// a file that fails to load leaves the previous set in place.
func (s *Server) ReloadAPIKeys() error {
	if s.scopedKeysFile == "" {
		return fmt.Errorf("no API keys file configured")
	}
	set, err := LoadAPIKeysFile(s.scopedKeysFile)
	if err != nil {
		return err
	}
	s.apiKeys.Store(set)
	s.log.Info("scoped API keys reloaded", "path", s.scopedKeysFile, "keys", set.Len())
	return nil
}
