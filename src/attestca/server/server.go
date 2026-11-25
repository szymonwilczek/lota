// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

// Package server serves enrollment over TLS, one enrollment per connection:
// a BeginRequest answered by a ChallengeReply, then a CompleteRequest
// answered by a ResultReply. A refused Begin or Complete is answered with
// its wire status; a frame that does not decode, and a connection beyond
// MaxConns, are closed without a reply.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/szymonwilczek/lota/attestca/ca"
	"github.com/szymonwilczek/lota/attestca/credential"
	"github.com/szymonwilczek/lota/attestca/enroll"
	"github.com/szymonwilczek/lota/attestca/wire"
	"github.com/szymonwilczek/lota/crl"
)

const (
	defaultReadTimeout  = 15 * time.Second
	defaultWriteTimeout = 15 * time.Second
	defaultMaxConns     = 256

	defaultBeginRateLimit  = 10
	defaultBeginRateWindow = time.Minute

	// source IPs with a live window; a new one beyond it is refused
	maxRateEntries = 4096
)

// Config configures a Server. Service and TLSConfig are required;
// a non-positive number or duration selects its default,
// a nil Logger discards.
type Config struct {
	Service   *enroll.Service
	TLSConfig *tls.Config
	Logger    *slog.Logger

	// deadline of each frame read and each frame write
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// a connection beyond MaxConns is closed at once
	MaxConns int

	// Begin attempts allowed per source IP per window
	BeginRateLimit  int
	BeginRateWindow time.Duration
}

// Server accepts enrollment connections.
type Server struct {
	svc          *enroll.Service
	tlsConfig    *tls.Config
	log          *slog.Logger
	readTimeout  time.Duration
	writeTimeout time.Duration
	connSem      chan struct{}

	rateLimit  int
	rateWindow time.Duration
	rateMu     sync.Mutex
	rateTable  map[string]*rateWindow

	wg sync.WaitGroup
}

// rateWindow is one source IP's fixed-window counter.
type rateWindow struct {
	count       int
	windowStart time.Time
}

// New returns a Server for cfg.
func New(cfg Config) (*Server, error) {
	if cfg.Service == nil {
		return nil, errors.New("nil enrollment service")
	}
	if cfg.TLSConfig == nil {
		return nil, errors.New("nil TLS config")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	readTimeout := cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = defaultReadTimeout
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = defaultWriteTimeout
	}
	maxConns := cfg.MaxConns
	if maxConns <= 0 {
		maxConns = defaultMaxConns
	}
	rateLimit := cfg.BeginRateLimit
	if rateLimit <= 0 {
		rateLimit = defaultBeginRateLimit
	}
	rateWin := cfg.BeginRateWindow
	if rateWin <= 0 {
		rateWin = defaultBeginRateWindow
	}
	return &Server{
		svc:          cfg.Service,
		tlsConfig:    cfg.TLSConfig,
		log:          log,
		readTimeout:  readTimeout,
		writeTimeout: writeTimeout,
		connSem:      make(chan struct{}, maxConns),
		rateLimit:    rateLimit,
		rateWindow:   rateWin,
		rateTable:    make(map[string]*rateWindow),
	}, nil
}

// Serve accepts TLS connections on ln until ctx is done, then waits for the
// open ones and returns nil. Any other Accept error is returned at once.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	tlsLn := tls.NewListener(ln, s.tlsConfig)

	go func() {
		<-ctx.Done()
		_ = tlsLn.Close()
	}()

	for {
		conn, err := tlsLn.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil
			}
			return err
		}

		select {
		case s.connSem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.connSem }()
			s.handle(conn)
		}()
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	begin, err := s.readBegin(conn)
	if err != nil {
		s.log.Warn("enroll begin read failed", "remote", remote, "error", err)
		return
	}

	if !s.allowBegin(remote) {
		s.log.Warn("enroll begin rate-limited", "remote", remote)
		if werr := s.writeChallenge(conn, &wire.ChallengeReply{Status: wire.StatusRateLimited, Version: begin.Version}); werr != nil {
			s.log.Debug("failed to write rate-limit rejection", "remote", remote, "error", werr)
		}
		return
	}

	challenge, err := s.svc.Begin(begin.EKCertDER, begin.AIKPublic, begin.Token, begin.EKChainDER)
	if err != nil {
		status := beginStatus(err)
		s.log.Warn("enroll begin rejected", "remote", remote, "status", status, "error", err)
		if werr := s.writeChallenge(conn, &wire.ChallengeReply{Status: status, Version: begin.Version}); werr != nil {
			s.log.Debug("failed to write begin rejection", "remote", remote, "error", werr)
		}
		return
	}

	if err := s.writeChallenge(conn, &wire.ChallengeReply{
		Status:          wire.StatusOK,
		SessionID:       challenge.SessionID,
		CredentialBlob:  challenge.CredentialBlob,
		EncryptedSecret: challenge.EncryptedSecret,
		Version:         begin.Version,
	}); err != nil {
		s.log.Warn("enroll challenge write failed", "remote", remote, "error", err)
		return
	}

	complete, err := s.readComplete(conn)
	if err != nil {
		s.log.Warn("enroll complete read failed", "remote", remote, "error", err)
		return
	}

	certDER, deviceID, err := s.svc.Complete(complete.SessionID, complete.Secret)
	if err != nil {
		status := completeStatus(err)
		s.log.Warn("enroll complete rejected", "remote", remote, "status", status, "error", err)
		if werr := s.writeResult(conn, &wire.ResultReply{Status: status, Version: begin.Version}); werr != nil {
			s.log.Debug("failed to write complete rejection", "remote", remote, "error", werr)
		}
		return
	}

	s.log.Info("enroll issued AIK certificate", "remote", remote, "device_id", deviceID)
	if werr := s.writeResult(conn, &wire.ResultReply{
		Status:     wire.StatusOK,
		AIKCertDER: certDER,
		DeviceID:   deviceID,
		Version:    begin.Version,
	}); werr != nil {
		s.log.Debug("failed to write enrollment result", "remote", remote, "error", werr)
	}
}

// allowBegin counts a Begin against the fixed window of remote's host and
// reports false once the window is spent or a new host finds the table
// full.
func (s *Server) allowBegin(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	now := time.Now()

	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	s.sweepRateLocked(now)

	w, ok := s.rateTable[host]
	if !ok {
		if len(s.rateTable) >= maxRateEntries {
			// evicting a live window would let IP churn reset it
			return false
		}
		s.rateTable[host] = &rateWindow{count: 1, windowStart: now}
		return true
	}
	if now.Sub(w.windowStart) >= s.rateWindow {
		w.count = 1
		w.windowStart = now
		return true
	}
	if w.count >= s.rateLimit {
		return false
	}
	w.count++
	return true
}

func (s *Server) sweepRateLocked(now time.Time) {
	for ip, w := range s.rateTable {
		if now.Sub(w.windowStart) >= s.rateWindow {
			delete(s.rateTable, ip)
		}
	}
}

func (s *Server) readBegin(conn net.Conn) (*wire.BeginRequest, error) {
	if err := conn.SetReadDeadline(time.Now().Add(s.readTimeout)); err != nil {
		return nil, err
	}
	body, err := wire.ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	return wire.DecodeBegin(body)
}

func (s *Server) readComplete(conn net.Conn) (*wire.CompleteRequest, error) {
	if err := conn.SetReadDeadline(time.Now().Add(s.readTimeout)); err != nil {
		return nil, err
	}
	body, err := wire.ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	return wire.DecodeComplete(body)
}

func (s *Server) writeChallenge(conn net.Conn, r *wire.ChallengeReply) error {
	body, err := wire.EncodeChallenge(r)
	if err != nil {
		return err
	}
	return s.writeFrame(conn, body)
}

func (s *Server) writeResult(conn net.Conn, r *wire.ResultReply) error {
	body, err := wire.EncodeResult(r)
	if err != nil {
		return err
	}
	return s.writeFrame(conn, body)
}

func (s *Server) writeFrame(conn net.Conn, body []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(s.writeTimeout)); err != nil {
		return err
	}
	return wire.WriteFrame(conn, body)
}

// beginStatus maps a Begin error to its wire status; an error with no case
// is StatusInternalError.
func beginStatus(err error) uint16 {
	switch {
	case errors.Is(err, ca.ErrEKChain), errors.Is(err, ca.ErrEKExpired),
		errors.Is(err, ca.ErrEKNotYet), errors.Is(err, ca.ErrEKMissingOID),
		errors.Is(err, ca.ErrEKParse), errors.Is(err, ca.ErrEKKeyType),
		errors.Is(err, ca.ErrEKKeySize), errors.Is(err, enroll.ErrEKKeyType),
		errors.Is(err, ca.ErrEKWeakKey), errors.Is(err, crl.ErrCertificateRevoked),
		errors.Is(err, enroll.ErrEKNotListed):
		return wire.StatusEKRejected
	case errors.Is(err, crl.ErrCRLStale):
		return wire.StatusCRLStale
	case errors.Is(err, credential.ErrAIKDecode), errors.Is(err, credential.ErrAIKTemplate),
		errors.Is(err, credential.ErrAIKName), errors.Is(err, enroll.ErrAIKKeyType):
		return wire.StatusAIKRejected
	case errors.Is(err, enroll.ErrTokenUnknown), errors.Is(err, enroll.ErrTokenRequired):
		return wire.StatusTokenRejected
	case errors.Is(err, enroll.ErrTooManyPending):
		return wire.StatusRateLimited
	default:
		return wire.StatusInternalError
	}
}

func completeStatus(err error) uint16 {
	switch {
	case errors.Is(err, enroll.ErrUnknownSession), errors.Is(err, enroll.ErrSessionExpired):
		return wire.StatusUnknownSession
	case errors.Is(err, enroll.ErrActivationMismatch):
		return wire.StatusActivationFail
	default:
		return wire.StatusInternalError
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
