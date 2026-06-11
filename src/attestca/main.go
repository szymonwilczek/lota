// SPDX-License-Identifier: MIT
// LOTA Attestation CA - self-hosted enrollment service
//
// Each LOTA adopter runs their own lota-attest-ca with their own CA
// signing key and their own trusted TPM manufacturer roots. The service
// proves an AIK lives in a genuine TPM through credential activation and
// issues a short-lived AIK certificate the fleet's verifiers trust. It
// holds no TPM and stores no per-host secrets beyond the in-flight
// challenge.

package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/szymonwilczek/lota/attestca/ca"
	"github.com/szymonwilczek/lota/attestca/enroll"
	"github.com/szymonwilczek/lota/attestca/server"
)

type stringList []string

func (s *stringList) String() string { return fmt.Sprint(*s) }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	var (
		listen       = flag.String("listen", ":8444", "TLS listen address")
		caCertPath   = flag.String("ca-cert", "", "PEM CA certificate that signs AIK certificates")
		caKeyPath    = flag.String("ca-key", "", "(dev-only) PEM PKCS#8 CA private key; production holds the CA key in an HSM")
		p11Module    = flag.String("ca-key-pkcs11-module", "", "PKCS#11 module path holding the CA key (HSM/SoftHSM); requires a pkcs11-tagged build, PIN in LOTA_CA_PKCS11_PIN")
		p11Token     = flag.String("ca-key-pkcs11-token", "", "PKCS#11 token label the CA key lives on")
		p11Label     = flag.String("ca-key-pkcs11-label", "", "PKCS#11 CA key object label")
		p11ID        = flag.String("ca-key-pkcs11-id", "", "PKCS#11 CA key object id (hex); alternative to -ca-key-pkcs11-label")
		tlsCertPath  = flag.String("tls-cert", "", "PEM server TLS certificate")
		tlsKeyPath   = flag.String("tls-key", "", "PEM server TLS private key")
		ekRootBundle = flag.String("ek-root-bundle", "", "directory holding a pinned multi-vendor EK root bundle (see "+ca.EKBundleManifestName+")")
		pseudonymKey = flag.String("pseudonym-key", "", "file holding the device-pseudonym secret (>=16 bytes)")
		aikCertTTL   = flag.Duration("aik-cert-ttl", ca.DefaultAIKCertTTL, "lifetime of issued AIK certificates")
		sessionTTL   = flag.Duration("session-ttl", enroll.DefaultSessionTTL, "pending enrollment lifetime")
		maxPending   = flag.Int("max-pending", enroll.DefaultMaxPending, "max outstanding enrollments")
	)
	var ekRoots stringList
	flag.Var(&ekRoots, "ek-root", "PEM file of trusted TPM manufacturer roots (repeatable)")
	var ekCRLs stringList
	flag.Var(&ekCRLs, "ek-crl", "TPM manufacturer CRL file (PEM or DER, repeatable). Each CRL must be signed by a certificate in the EK trust bundle; enrollment rejects a revoked EK. Refresh by rewriting the file and sending SIGHUP.")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(*listen, runConfig{
		caCertPath: *caCertPath,
		caKeyPath:  *caKeyPath,
		pkcs11: pkcs11KeyConfig{
			module: *p11Module,
			token:  *p11Token,
			label:  *p11Label,
			id:     *p11ID,
			pin:    os.Getenv("LOTA_CA_PKCS11_PIN"),
		},
		tlsCertPath:  *tlsCertPath,
		tlsKeyPath:   *tlsKeyPath,
		pseudonymKey: *pseudonymKey,
		ekRootBundle: *ekRootBundle,
		ekRoots:      ekRoots,
		ekCRLs:       ekCRLs,
		aikCertTTL:   *aikCertTTL,
		sessionTTL:   *sessionTTL,
		maxPending:   *maxPending,
	}, log); err != nil {
		log.Error("lota-attest-ca failed", "error", err)
		os.Exit(1)
	}
}

type runConfig struct {
	caCertPath   string
	caKeyPath    string
	pkcs11       pkcs11KeyConfig
	tlsCertPath  string
	tlsKeyPath   string
	pseudonymKey string
	ekRootBundle string
	ekRoots      []string
	ekCRLs       []string
	aikCertTTL   time.Duration
	sessionTTL   time.Duration
	maxPending   int
}

func run(listen string, cfg runConfig, log *slog.Logger) error {
	required := map[string]string{
		"ca-cert":  cfg.caCertPath,
		"tls-cert": cfg.tlsCertPath, "tls-key": cfg.tlsKeyPath,
		"pseudonym-key": cfg.pseudonymKey,
	}

	// CA key comes from exactly one source:
	// PKCS#11 token or an on-disk PEM
	// -ca-key is required only when no token is configured
	if cfg.pkcs11.requested() {
		if cfg.caKeyPath != "" {
			return fmt.Errorf("specify either -ca-key or -ca-key-pkcs11-*, not both")
		}
	} else {
		required["ca-key"] = cfg.caKeyPath
	}
	for name, path := range required {
		if path == "" {
			return fmt.Errorf("missing required -%s", name)
		}
	}
	if cfg.ekRootBundle == "" && len(cfg.ekRoots) == 0 {
		return fmt.Errorf("at least one of -ek-root-bundle or -ek-root is required")
	}

	caCertPEM, err := os.ReadFile(cfg.caCertPath)
	if err != nil {
		return fmt.Errorf("read ca-cert: %w", err)
	}

	// CA signing key anchors the whole fleet's trust.
	// Load it either from a PKCS#11 token (production) or an on-disk PEM (dev-only)
	var (
		caKeyPEM []byte
		caSigner crypto.Signer
	)
	if cfg.pkcs11.requested() {
		var closeToken func() error
		caSigner, closeToken, err = newPKCS11Signer(cfg.pkcs11)
		if err != nil {
			return fmt.Errorf("CA PKCS#11 key: %w", err)
		}
		defer func() {
			if cerr := closeToken(); cerr != nil {
				log.Warn("closing PKCS#11 token", "error", cerr)
			}
		}()
		log.Info("using PKCS#11 CA signing key",
			"module", cfg.pkcs11.module, "token", cfg.pkcs11.token)
	} else {
		caKeyPEM, err = os.ReadFile(cfg.caKeyPath)
		if err != nil {
			return fmt.Errorf("read ca-key: %w", err)
		}

		// On-disk key is a development convenience only;
		// Production holds it in an HSM.
		// Warn loudly so it is never mistaken for a default.
		log.Warn("using on-disk CA signing key -- development-only fallback; "+
			"hold the CA key in an HSM in production",
			"flag", "-ca-key", "doc", "docs/PRODUCTION_BRINGUP.md")
	}

	var ekRootPEMs [][]byte
	// operator-provisioned, pin-enforced bundle is the trust baseline
	// -ek-root adds operator-supplied roots (e.g. a swtpm CA in the demo tor) on top
	if cfg.ekRootBundle != "" {
		bundlePEMs, err := ca.LoadEKRootBundle(cfg.ekRootBundle)
		if err != nil {
			return fmt.Errorf("load ek-root-bundle %s: %w", cfg.ekRootBundle, err)
		}
		ekRootPEMs = append(ekRootPEMs, bundlePEMs...)
	}
	for _, path := range cfg.ekRoots {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read ek-root %s: %w", path, err)
		}
		ekRootPEMs = append(ekRootPEMs, splitPEMCerts(data)...)
	}

	pseudonymKey, err := os.ReadFile(cfg.pseudonymKey)
	if err != nil {
		return fmt.Errorf("read pseudonym-key: %w", err)
	}

	issuer, err := ca.NewIssuer(ca.IssuerConfig{
		CACertPEM:  caCertPEM,
		CAKeyPEM:   caKeyPEM,
		CASigner:   caSigner,
		EKRootPEMs: ekRootPEMs,
		EKCRLPaths: cfg.ekCRLs,
		AIKCertTTL: cfg.aikCertTTL,
	})
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}

	svc, err := enroll.NewService(issuer, pseudonymKey,
		enroll.WithSessionTTL(cfg.sessionTTL),
		enroll.WithMaxPending(cfg.maxPending))
	if err != nil {
		return fmt.Errorf("enrollment service: %w", err)
	}

	tlsCert, err := tls.LoadX509KeyPair(cfg.tlsCertPath, cfg.tlsKeyPath)
	if err != nil {
		return fmt.Errorf("server TLS keypair: %w", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	srv, err := server.New(server.Config{
		Service:   svc,
		TLSConfig: tlsConfig,
		Logger:    log,
	})
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listen, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// SIGHUP refreshes the manufacturer EK CRL feed in place:
	// operator rewrites the configured file(s) atomically and signals
	// the daemon.
	// Failed reload keeps the previous set active.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if err := issuer.ReloadEKCRLs(); err != nil {
					log.Error("SIGHUP: EK CRL reload failed; keeping previous set", "error", err)
					continue
				}
				log.Info("SIGHUP: EK CRL feed reloaded", "loaded_crls", issuer.EKCRLCount())
			}
		}
	}()

	log.Info("lota-attest-ca listening", "address", ln.Addr().String(),
		"ek_roots", len(ekRootPEMs), "ek_crls", issuer.EKCRLCount(),
		"aik_cert_ttl", cfg.aikCertTTL.String())
	return srv.Serve(ctx, ln)
}

// splitPEMCerts expands a PEM bundle into one []byte per CERTIFICATE block
// so a manufacturer root file holding several roots is fully loaded
func splitPEMCerts(data []byte) [][]byte {
	var out [][]byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, pem.EncodeToMemory(block))
		}
	}
	return out
}
