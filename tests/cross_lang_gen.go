// SPDX-License-Identifier: MIT
//
// # Cross-language wire format compatibility test
//
// Generates a serialized token with Go SDK, writes to file,
// then a C program reads it and verifies with lota_server_verify_token.
// Also exports the AIK public key for C verification.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	server "github.com/szymonwilczek/lota/sdk/server"
)

func main() {
	fmt.Println("=== Go -> C Cross-Language Wire Format Test ===")

	// generate RSA-2048 key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[Go] Generated RSA-2048 key")

	// build token
	nonce := [32]byte{0xCA, 0xFE, 0xBA, 0xBE}
	now := uint64(time.Now().Unix())
	issuedAt := now
	validUntil := now + 3600
	flags := uint32(0x07)
	pcrDigest := make([]byte, 32)
	for i := range pcrDigest {
		pcrDigest[i] = byte(i)
	}

	// compute expected nonce = SHA256(issued_at||valid_until||flags||nonce) in LE
	var buf [52]byte
	binary.LittleEndian.PutUint64(buf[0:8], issuedAt)
	binary.LittleEndian.PutUint64(buf[8:16], validUntil)
	binary.LittleEndian.PutUint32(buf[16:20], flags)
	copy(buf[20:52], nonce[:])
	expectedNonce := sha256.Sum256(buf[:])

	// fake TPMS_ATTEST
	attestData := buildFakeTPMSAttest(expectedNonce[:], pcrDigest)
	fmt.Printf("[Go] TPMS_ATTEST: %d bytes\n", len(attestData))

	// sign with RSASSA-PKCS1v15
	hash := sha256.Sum256(attestData)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[Go] Signature: %d bytes\n", len(sig))

	// serialize token
	tokBytes, err := server.SerializeToken(issuedAt, validUntil, flags, nonce,
		0x0014, 0x000B, 0x4001, attestData, sig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serialize: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[Go] Serialized token: %d bytes\n", len(tokBytes))

	// write token to file
	if err := os.WriteFile("/tmp/lota_cross_token.bin", tokBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write token: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[Go] Written /tmp/lota_cross_token.bin")

	// export AIK public key as DER
	aikDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal key: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile("/tmp/lota_cross_aik.der", aikDER, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[Go] Written /tmp/lota_cross_aik.der (%d bytes)\n", len(aikDER))

	// verify with Go SDK (sanity check)
	claims, err := server.VerifyToken(tokBytes, &key.PublicKey, nonce[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Go verify failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[Go] VerifyToken OK - flags=0x%X, pcr_digest_len=%d\n",
		claims.Flags, len(claims.PCRDigest))

	// write expected nonce for C to verify
	if err := os.WriteFile("/tmp/lota_cross_nonce.bin", nonce[:], 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write nonce: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[Go] Written /tmp/lota_cross_nonce.bin")
	fmt.Println("[Go] Done - run C verifier next")
}

func buildFakeTPMSAttest(extraData []byte, pcrDigest []byte) []byte {
	var b []byte

	// magic (4 bytes, big-endian): TPM_GENERATED_VALUE
	b = binary.BigEndian.AppendUint32(b, 0xff544347)

	// type (2 bytes): TPM_ST_ATTEST_QUOTE
	b = binary.BigEndian.AppendUint16(b, 0x8018)

	// qualifiedSigner: TPM2B_NAME (size=4)
	b = binary.BigEndian.AppendUint16(b, 4)
	b = append(b, 0x00, 0x0B, 0xAA, 0xBB)

	// extraData: TPM2B_DATA
	b = binary.BigEndian.AppendUint16(b, uint16(len(extraData)))
	b = append(b, extraData...)

	// clockInfo: 17 zero bytes
	b = append(b, make([]byte, 17)...)

	// firmwareVersion: 8 zero bytes
	b = append(b, make([]byte, 8)...)

	// TPML_PCR_SELECTION: count=1
	b = binary.BigEndian.AppendUint32(b, 1)
	b = binary.BigEndian.AppendUint16(b, 0x000B)
	b = append(b, 3)
	b = append(b, 0x01, 0x00, 0x40) // PCR 0, PCR 14

	// pcrDigest: TPM2B_DIGEST
	b = binary.BigEndian.AppendUint16(b, uint16(len(pcrDigest)))
	b = append(b, pcrDigest...)

	return b
}
