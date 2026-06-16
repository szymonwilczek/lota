// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package credential

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
)

// aikTemplate builds a TPMT_PUBLIC matching the restricted RSA signing key
// the agent creates in create_aik_primary(). The modulus need not back a
// real private key: activation unwraps the seed with the EK private key
// and binds to the AIK name, never the AIK private key.
func aikTemplate(modulus []byte) tpm2.Public {
	return tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: requiredAIKAttrs,
		RSAParameters: &tpm2.RSAParams{
			Symmetric:  &tpm2.SymScheme{Alg: tpm2.AlgNull},
			Sign:       &tpm2.SigScheme{Alg: tpm2.AlgRSASSA, Hash: tpm2.AlgSHA256},
			KeyBits:    2048,
			ModulusRaw: modulus,
		},
	}
}

func mustEncodeAIK(t *testing.T, pub tpm2.Public) []byte {
	t.Helper()
	enc, err := pub.Encode()
	if err != nil {
		t.Fatalf("encode AIK public: %v", err)
	}
	return enc
}

func testModulus(t *testing.T) []byte {
	t.Helper()
	mod := make([]byte, 256)
	if _, err := rand.Read(mod); err != nil {
		t.Fatalf("modulus: %v", err)
	}
	mod[0] |= 0x80
	return mod
}

// softwareActivateCredential reverses credactivation.Generate the way a
// real TPM2_ActivateCredential does: decrypt the seed with the EK private
// key, re-derive the integrity and storage keys via KDFa, verify the
// outer HMAC, and recover the wrapped secret. It is the unit-test oracle
// that proves a CA-issued challenge is recoverable end to end without a
// TPM.
func softwareActivateCredential(t *testing.T, ekPriv *rsa.PrivateKey, aikName tpm2.Name,
	credBlob, encSecret []byte,
) []byte {
	t.Helper()

	if len(encSecret) < 2 {
		t.Fatalf("encSecret too short: %d", len(encSecret))
	}
	seedLen := int(binary.BigEndian.Uint16(encSecret[:2]))
	if 2+seedLen > len(encSecret) {
		t.Fatalf("encSecret truncated: need %d, have %d", 2+seedLen, len(encSecret))
	}
	label := append([]byte("IDENTITY"), 0)
	seed, err := rsa.DecryptOAEP(sha256.New(), nil, ekPriv, encSecret[2:2+seedLen], label)
	if err != nil {
		t.Fatalf("OAEP decrypt seed: %v", err)
	}

	if len(credBlob) < 2 {
		t.Fatalf("credBlob too short: %d", len(credBlob))
	}
	idLen := int(binary.BigEndian.Uint16(credBlob[:2]))
	if 2+idLen > len(credBlob) {
		t.Fatalf("credBlob truncated: need %d, have %d", 2+idLen, len(credBlob))
	}
	id := credBlob[2 : 2+idLen]
	if len(id) < 2 {
		t.Fatalf("IDObject too short: %d", len(id))
	}
	hmacLen := int(binary.BigEndian.Uint16(id[:2]))
	if 2+hmacLen > len(id) {
		t.Fatalf("IDObject HMAC truncated: need %d, have %d", 2+hmacLen, len(id))
	}
	mac := id[2 : 2+hmacLen]
	encIdentity := id[2+hmacLen:]

	aikEnc, err := aikName.Digest.Encode()
	if err != nil {
		t.Fatalf("encode AIK name: %v", err)
	}

	macKey, err := tpm2.KDFa(tpm2.AlgSHA256, seed, "INTEGRITY", nil, nil, sha256.Size*8)
	if err != nil {
		t.Fatalf("KDFa integrity: %v", err)
	}
	m := hmac.New(sha256.New, macKey)
	m.Write(encIdentity)
	m.Write(aikEnc)
	if !hmac.Equal(m.Sum(nil), mac) {
		t.Fatal("integrity HMAC mismatch: credential not activatable")
	}

	symKey, err := tpm2.KDFa(tpm2.AlgSHA256, seed, "STORAGE", aikEnc, nil, SymBlockSize*8)
	if err != nil {
		t.Fatalf("KDFa storage: %v", err)
	}
	block, err := aes.NewCipher(symKey)
	if err != nil {
		t.Fatalf("aes cipher: %v", err)
	}
	cv := make([]byte, len(encIdentity))
	// CFB is mandated by TPM 2.0 credential protection (spec part 1, p24)
	// this oracle mirrors the TPM, it does not choose the cipher mode
	cipher.NewCFBDecrypter(block, make([]byte, SymBlockSize)).XORKeyStream(cv, encIdentity) //nolint:staticcheck

	if len(cv) < 2 {
		t.Fatalf("decrypted credential too short: %d", len(cv))
	}
	secLen := int(binary.BigEndian.Uint16(cv[:2]))
	if 2+secLen > len(cv) {
		t.Fatalf("decrypted secret truncated: need %d, have %d", 2+secLen, len(cv))
	}
	return cv[2 : 2+secLen]
}

func TestGenerateChallengeRoundTrip(t *testing.T) {
	ekPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("EK key: %v", err)
	}

	tpmtPublic := mustEncodeAIK(t, aikTemplate(testModulus(t)))
	_, aikName, err := ValidateAIK(tpmtPublic)
	if err != nil {
		t.Fatalf("ValidateAIK: %v", err)
	}

	ch, err := GenerateChallenge(&ekPriv.PublicKey, aikName)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	if len(ch.Secret) != SecretSize {
		t.Fatalf("secret size %d, want %d", len(ch.Secret), SecretSize)
	}

	recovered := softwareActivateCredential(t, ekPriv, aikName, ch.CredentialBlob, ch.EncryptedSecret)
	if !hmac.Equal(recovered, ch.Secret) {
		t.Fatalf("recovered secret does not match issued secret")
	}
}

func TestGenerateChallengeWrongEKFails(t *testing.T) {
	issueEK, _ := rsa.GenerateKey(rand.Reader, 2048)
	attackerEK, _ := rsa.GenerateKey(rand.Reader, 2048)

	_, aikName, err := ValidateAIK(mustEncodeAIK(t, aikTemplate(testModulus(t))))
	if err != nil {
		t.Fatalf("ValidateAIK: %v", err)
	}

	ch, err := GenerateChallenge(&issueEK.PublicKey, aikName)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	// TPM holding a different EK cannot decrypt the OAEP seed
	if _, err := rsa.DecryptOAEP(sha256.New(), nil, attackerEK,
		ch.EncryptedSecret[2:], append([]byte("IDENTITY"), 0)); err == nil {
		t.Fatal("seed decrypted under the wrong EK key")
	}
}

func TestGenerateChallengeRejectsBadEK(t *testing.T) {
	_, aikName, err := ValidateAIK(mustEncodeAIK(t, aikTemplate(testModulus(t))))
	if err != nil {
		t.Fatalf("ValidateAIK: %v", err)
	}

	if _, err := GenerateChallenge(nil, aikName); err == nil {
		t.Fatal("accepted nil EK")
	}

	smallEK, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := GenerateChallenge(&smallEK.PublicKey, aikName); err == nil {
		t.Fatal("accepted 1024-bit EK")
	}
}

func TestValidateAIKRejectsBadTemplates(t *testing.T) {
	tests := []struct {
		name  string
		mutic func(p *tpm2.Public)
	}{
		{"decrypt set", func(p *tpm2.Public) { p.Attributes |= tpm2.FlagDecrypt }},
		{"not restricted", func(p *tpm2.Public) { p.Attributes &^= tpm2.FlagRestricted }},
		{"not signing", func(p *tpm2.Public) { p.Attributes &^= tpm2.FlagSign }},
		{"not fixedTPM", func(p *tpm2.Public) { p.Attributes &^= tpm2.FlagFixedTPM }},
		{"wrong name alg", func(p *tpm2.Public) { p.NameAlg = tpm2.AlgSHA1 }},
		{"small key", func(p *tpm2.Public) { p.RSAParameters.KeyBits = 1024 }},
		{"not rsassa", func(p *tpm2.Public) { p.RSAParameters.Sign.Alg = tpm2.AlgRSAPSS }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub := aikTemplate(testModulus(t))
			tc.mutic(&pub)
			if _, _, err := ValidateAIK(mustEncodeAIK(t, pub)); err == nil {
				t.Fatalf("accepted invalid AIK template: %s", tc.name)
			}
		})
	}
}

func TestValidateAIKRejectsGarbage(t *testing.T) {
	if _, _, err := ValidateAIK([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Fatal("accepted garbage TPMT_PUBLIC")
	}
	if _, _, err := ValidateAIK(nil); err == nil {
		t.Fatal("accepted nil TPMT_PUBLIC")
	}
}
