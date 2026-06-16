module github.com/szymonwilczek/lota/attestca

go 1.25.8

require (
	github.com/ThalesGroup/crypto11 v1.6.1
	github.com/google/go-tpm v0.9.8
)

require (
	github.com/miekg/pkcs11 v1.1.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/szymonwilczek/lota/crl v0.0.0
	github.com/thales-e-security/pool v0.0.2 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

replace github.com/szymonwilczek/lota/crl => ../crl
