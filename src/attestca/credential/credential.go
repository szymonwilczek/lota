// SPDX-License-Identifier: MIT
// LOTA Attestation CA - TPM 2.0 credential-activation primitive
//
// Verifier side of the TCG credential-activation ceremony
// (TPM 2.0 Library Specification, Part 1, Section 24).
// The CA proves that an Attestation Identity Key resides in the same
// TPM as a manufacturer-certified Endorsement Key without ever holding
// a TPM itself: TPM2_MakeCredential is a public-key operation.
// The agent's TPM2_ActivateCredential can only recover the secret when
// the AIK and EK share a hardware root, which is the binding the EK
// certificate alone does not provide.

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
	// SymBlockSize is the AES key size of the seed wrapped to the EK.
	// The TCG EK Credential Profile (rev 14, 2.1.5.1) fixes the default
	// RSA EK symmetric cipher at AES-128-CFB, so the seed is 16 bytes
	SymBlockSize = 16

	// SecretSize is the length of the activation secret the agent must
	// recover. 32 bytes is the longest digest the TPM supports here and
	// leaves no room for a brute-force window
	SecretSize = 32

	// MinEKKeyBits rejects undersized EK moduli before any OAEP wrap
	MinEKKeyBits = 2048
)

// requiredAIKAttrs are the object attributes an AIK template must carry.
// Restricted signing key cannot sign caller-supplied data, only
// TPM-internal structures such as quotes, and fixedTPM/fixedParent keep
// it non-duplicable
const requiredAIKAttrs = tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
	tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
	tpm2.FlagRestricted | tpm2.FlagSign

var (
	ErrEKKeyType   = errors.New("EK public key is not RSA; credential activation requires an RSA endorsement key (TCG EK template H-1)")
	ErrEKKeySize   = errors.New("EK RSA key too small")
	ErrAIKDecode   = errors.New("failed to decode AIK TPMT_PUBLIC")
	ErrAIKTemplate = errors.New("AIK template is not a restricted RSA signing key")
	ErrAIKName     = errors.New("failed to compute AIK name")
)

// Challenge is the output of MakeCredential.
// CredentialBlob and EncryptedSecret are handed to the agent for
// TPM2_ActivateCredential.
// Secret is the value the agent must return and never leaves the CA
type Challenge struct {
	CredentialBlob  []byte
	EncryptedSecret []byte
	Secret          []byte
}

// ValidateAIK decodes an AIK TPMT_PUBLIC, enforces the restricted-signing
// template, and returns the parsed public area together with its TPM
// Name.
// Name is what binds the credential: the agent's TPM recomputes
// it from the loaded object during activation, so a mismatched template
// cannot recover the secret
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
		// AIK must be an RSA key: the verifier authenticates quotes
		// with an RSA public key and the AIK store holds *rsa.PublicKey
		// ECC AIK is refused here instead failing later
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
	if pub.RSAParameters.Sign == nil || pub.RSAParameters.Sign.Alg != tpm2.AlgRSASSA {
		return fmt.Errorf("%w: signing scheme is not RSASSA", ErrAIKTemplate)
	}
	return nil
}

// GenerateChallenge wraps a fresh 32-byte secret for the given EK public
// key and AIK name. Only a TPM holding both keys can activate it.
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
