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
	"log"
	"net"
	"sync"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
	"github.com/szymonwilczek/lota/verifier/verify"
)

type Server struct {
	verifier   *verify.Verifier
	listener   net.Listener
	tlsConfig  *tls.Config
	addr       string
	shutdownCh chan struct{}
	wg         sync.WaitGroup

	// timeouts
	readTimeout  time.Duration
	writeTimeout time.Duration
}

type ServerConfig struct {
	// address to listen on
	Address string

	// tls certificate and key paths
	CertFile string
	KeyFile  string

	// timeouts
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Address:      ":8443",
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

	return &Server{
		verifier:     verifier,
		tlsConfig:    tlsConfig,
		addr:         cfg.Address,
		shutdownCh:   make(chan struct{}),
		readTimeout:  cfg.ReadTimeout,
		writeTimeout: cfg.WriteTimeout,
	}, nil
}

func (s *Server) Start() error {
	listener, err := tls.Listen("tcp", s.addr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	s.listener = listener
	log.Printf("LOTA Verifier listening on %s", s.addr)

	go s.acceptLoop()

	return nil
}

func (s *Server) Stop() {
	close(s.shutdownCh)
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
				log.Printf("Accept error: %v", err)
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
	log.Printf("[%s] New connection", clientAddr)

	// IP without port ensures same client gets same baseline across connections
	clientIP, _, err := net.SplitHostPort(clientAddr)
	if err != nil {
		clientIP = clientAddr // fallback if no port
	}
	clientID := clientIP

	challenge, err := s.verifier.GenerateChallenge(clientID)
	if err != nil {
		log.Printf("[%s] Failed to generate challenge: %v", clientAddr, err)
		return
	}

	conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	challengeData := challenge.Serialize()
	if _, err := conn.Write(challengeData); err != nil {
		log.Printf("[%s] Failed to send challenge: %v", clientAddr, err)
		return
	}

	log.Printf("[%s] Challenge sent", clientAddr)

	// read attestation report
	conn.SetReadDeadline(time.Now().Add(s.readTimeout))

	// read header to get total size
	headerBuf := make([]byte, 32)
	if _, err := io.ReadFull(conn, headerBuf); err != nil {
		log.Printf("[%s] Failed to read report header: %v", clientAddr, err)
		return
	}

	// validate magic
	magic := binary.LittleEndian.Uint32(headerBuf[0:4])
	if magic != types.ReportMagic {
		log.Printf("[%s] Invalid report magic: 0x%08X", clientAddr, magic)
		s.sendResult(conn, types.VerifyOldVersion)
		return
	}

	// get total size
	totalSize := binary.LittleEndian.Uint32(headerBuf[24:28])
	if totalSize < 32 || totalSize > 64*1024 { // 64KB max
		log.Printf("[%s] Invalid report size: %d", clientAddr, totalSize)
		s.sendResult(conn, types.VerifyOldVersion)
		return
	}

	// read rest of report
	reportData := make([]byte, totalSize)
	copy(reportData[:32], headerBuf)

	if totalSize > 32 {
		if _, err := io.ReadFull(conn, reportData[32:]); err != nil {
			log.Printf("[%s] Failed to read report body: %v", clientAddr, err)
			return
		}
	}

	log.Printf("[%s] Report received (%d bytes)", clientAddr, totalSize)

	result, err := s.verifier.VerifyReport(clientID, reportData)
	if err != nil {
		log.Printf("[%s] Verification failed: %v", clientAddr, err)
	}

	s.sendResult(conn, result.Result)

	if result.Result == types.VerifyOK {
		log.Printf("[%s] Attestation successful, token valid until %s",
			clientAddr, time.Unix(int64(result.ValidUntil), 0))
	}
}

func (s *Server) sendResult(conn net.Conn, resultCode uint32) {
	result := &types.VerifyResult{
		Magic:   types.ReportMagic,
		Version: types.ReportVersion,
		Result:  resultCode,
	}

	if resultCode == types.VerifyOK {
		result.ValidUntil = uint64(time.Now().Add(time.Hour).Unix())
	}

	conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	conn.Write(result.Serialize())
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
