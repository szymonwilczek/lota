// SPDX-License-Identifier: MIT
// LOTA Verifier - Remote attestation verification service
//
// Usage:
//   lota-verifier [options]
//
// Options:
//   --addr ADDR        Listen address for TLS attestation protocol (default: :8443)
//   --http-addr ADDR   Listen address for HTTP monitoring API (default: disabled)
//   --cert FILE        TLS certificate file
//   --key FILE         TLS private key file
//   --aik-store PATH   AIK key store directory (default: /var/lib/lota/aiks)
//   --policy FILE      PCR policy file (YAML)
//   --generate-cert    Generate self-signed certificate for testing

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/szymonwilczek/lota/verifier/server"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

var (
	addr         = flag.String("addr", ":8443", "Listen address for TLS attestation protocol")
	httpAddr     = flag.String("http-addr", "", "Listen address for HTTP monitoring API (e.g. :8080)")
	certFile     = flag.String("cert", "", "TLS certificate file")
	keyFile      = flag.String("key", "", "TLS private key file")
	aikStorePath = flag.String("aik-store", "/var/lib/lota/aiks", "AIK key store directory")
	policyFile   = flag.String("policy", "", "PCR policy file (YAML)")
	generateCert = flag.Bool("generate-cert", false, "Generate self-signed certificate")
)

func main() {
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("LOTA Verifier starting...")

	if *generateCert {
		if err := generateTestCert(); err != nil {
			log.Fatalf("Failed to generate certificate: %v", err)
		}
		log.Println("Generated test certificates: lota-verifier.crt, lota-verifier.key")
		if *certFile == "" {
			*certFile = "lota-verifier.crt"
			*keyFile = "lota-verifier.key"
		}
	}

	// validate tls config
	if *certFile == "" || *keyFile == "" {
		log.Fatal("TLS certificate and key required. Use --generate-cert for testing.")
	}

	// initialize aik store
	aikStore, err := store.NewFileStore(*aikStorePath)
	if err != nil {
		log.Fatalf("Failed to initialize AIK store: %v", err)
	}
	log.Printf("AIK store: %s (%d registered clients)", *aikStorePath, len(aikStore.ListClients()))

	verifierCfg := verify.DefaultConfig()
	verifier := verify.NewVerifier(verifierCfg, aikStore)

	verifier.AddPolicy(verify.DefaultPolicy())
	log.Println("Loaded default policy (baseline security requirements)")

	// custom policy if specified
	if *policyFile != "" {
		if err := verifier.LoadPolicy(*policyFile); err != nil {
			log.Fatalf("Failed to load policy: %v", err)
		}
		log.Printf("Loaded policy from: %s", *policyFile)
	}

	// initialize tls server
	serverCfg := server.ServerConfig{
		Address:      *addr,
		HTTPAddress:  *httpAddr,
		CertFile:     *certFile,
		KeyFile:      *keyFile,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	srv, err := server.NewServer(serverCfg, verifier)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("Received signal %v, shutting down...", sig)

	srv.Stop()
	log.Println("LOTA Verifier stopped")
}

// creates a self-signed certificate for testing
func generateTestCert() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"LOTA Verifier"},
			CommonName:   "lota-verifier",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "lota-verifier"},
	}

	// self-sign
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// write certificate
	certFile, err := os.Create("lota-verifier.crt")
	if err != nil {
		return err
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	// write private key
	keyFile, err := os.Create("lota-verifier.key")
	if err != nil {
		return err
	}
	defer keyFile.Close()

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}

	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return err
	}

	return nil
}
