// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

// Package credential checks an AIK template and builds the
// TPM2_MakeCredential challenge for an RSA EK, without a TPM.
package credential

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
)

const (
	// SymBlockSize is the size in bytes of the seed and of the
	// credential's AES key.
	SymBlockSize = 16

	// SecretSize is the length of the activation secret.
	SecretSize = 32

	// MinEKKeyBits is the smallest EK modulus and AIK KeyBits accepted.
	MinEKKeyBits = 2048
)

const requiredAIKAttrs = tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
	tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
	tpm2.FlagRestricted | tpm2.FlagSign

// Errors returned by ValidateAIK and GenerateChallenge.
var (
	ErrEKKeyType   = errors.New("EK public key is not RSA; credential activation requires an RSA endorsement key (TCG EK template H-1)")
	ErrEKKeySize   = errors.New("EK RSA key too small")
	ErrAIKDecode   = errors.New("failed to decode AIK TPMT_PUBLIC")
	ErrAIKTemplate = errors.New("AIK template is not a restricted RSA signing key")
	ErrAIKName     = errors.New("failed to compute AIK name")
)

// Challenge is the TPM2_MakeCredential output: CredentialBlob and
// EncryptedSecret go to the agent, Secret is what it must send back.
type Challenge struct {
	CredentialBlob  []byte
	EncryptedSecret []byte
	Secret          []byte
}

// ValidateAIK decodes an AIK TPMT_PUBLIC and returns it with its Name.
// The template must be RSA with KeyBits of at least MinEKKeyBits, a SHA-256
// name, every requiredAIKAttrs attribute, no decrypt and the RSASSA scheme.
func ValidateAIK(tpmtPublic []byte) (tpm2.Public, tpm2.Name, error) {
	pub, err := tpm2.DecodePublic(tpmtPublic)
	if err != nil {
		return tpm2.Public{}, tpm2.Name{}, fmt.Errorf("%w: %v", ErrAIKDecode, err)
	}

	if err := validateAIKTemplate(pub); err != nil {
		return tpm2.Public{}, tpm2.Name{}, err
	}

	name, err := pub.Name()
	if err != nil {
		return tpm2.Public{}, tpm2.Name{}, fmt.Errorf("%w: %v", ErrAIKName, err)
	}
	if name.Digest == nil {
		return tpm2.Public{}, tpm2.Name{}, ErrAIKName
	}

	return pub, name, nil
}

func validateAIKTemplate(pub tpm2.Public) error {
	if pub.Type != tpm2.AlgRSA {
		return fmt.Errorf("%w: type 0x%04x (enrollment requires an RSA AIK)", ErrAIKTemplate, pub.Type)
	}
	if pub.NameAlg != tpm2.AlgSHA256 {
		return fmt.Errorf("%w: name algorithm 0x%04x", ErrAIKTemplate, pub.NameAlg)
	}
	if pub.Attributes&requiredAIKAttrs != requiredAIKAttrs {
		return fmt.Errorf("%w: attributes 0x%08x missing required 0x%08x",
			ErrAIKTemplate, pub.Attributes, requiredAIKAttrs)
	}
	if pub.Attributes&tpm2.FlagDecrypt != 0 {
		return fmt.Errorf("%w: decrypt attribute set", ErrAIKTemplate)
	}
	if pub.RSAParameters == nil {
		return fmt.Errorf("%w: missing RSA parameters", ErrAIKTemplate)
	}
	if pub.RSAParameters.KeyBits < MinEKKeyBits {
		return fmt.Errorf("%w: %d-bit key", ErrAIKTemplate, pub.RSAParameters.KeyBits)
	}
	if n := pub.RSAParameters.Modulus().BitLen(); n < MinEKKeyBits {
		return fmt.Errorf("%w: %d-bit modulus", ErrAIKTemplate, n)
	}
	if pub.RSAParameters.Sign == nil || pub.RSAParameters.Sign.Alg != tpm2.AlgRSASSA {
		return fmt.Errorf("%w: signing scheme is not RSASSA", ErrAIKTemplate)
	}
	return nil
}

// GenerateChallenge wraps a fresh SecretSize secret to ekPub for an object
// named aikName.
func GenerateChallenge(ekPub *rsa.PublicKey, aikName tpm2.Name) (*Challenge, error) {
	return generateChallenge(ekPub, aikName, rand.Reader)
}

func generateChallenge(ekPub *rsa.PublicKey, aikName tpm2.Name, rnd io.Reader) (*Challenge, error) {
	if ekPub == nil {
		return nil, ErrEKKeyType
	}
	if ekPub.N.BitLen() < MinEKKeyBits {
		return nil, fmt.Errorf("%w: %d bits", ErrEKKeySize, ekPub.N.BitLen())
	}
	if aikName.Digest == nil {
		return nil, ErrAIKName
	}

	secret := make([]byte, SecretSize)
	if _, err := io.ReadFull(rnd, secret); err != nil {
		return nil, fmt.Errorf("generating activation secret: %w", err)
	}

	credBlob, encSecret, err := credactivation.Generate(aikName.Digest, ekPub, SymBlockSize, secret)
	if err != nil {
		return nil, fmt.Errorf("MakeCredential failed: %w", err)
	}

	return &Challenge{
		CredentialBlob:  credBlob,
		EncryptedSecret: encSecret,
		Secret:          secret,
	}, nil
}
