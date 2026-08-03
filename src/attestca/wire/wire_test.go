// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBeginRoundTrip(t *testing.T) {
	in := &BeginRequest{
		EKCertDER: bytes.Repeat([]byte{0xAB}, 900),
		AIKPublic: bytes.Repeat([]byte{0xCD}, 120),
	}
	enc, err := EncodeBegin(in)
	if err != nil {
		t.Fatalf("EncodeBegin: %v", err)
	}
	out, err := DecodeBegin(enc)
	if err != nil {
		t.Fatalf("DecodeBegin: %v", err)
	}
	if !bytes.Equal(in.EKCertDER, out.EKCertDER) || !bytes.Equal(in.AIKPublic, out.AIKPublic) {
		t.Fatal("begin round trip mismatch")
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	in := &ChallengeReply{
		Status:          StatusOK,
		SessionID:       "abc123",
		CredentialBlob:  bytes.Repeat([]byte{0x01}, 200),
		EncryptedSecret: bytes.Repeat([]byte{0x02}, 256),
		Version:         Version1,
	}
	enc, err := EncodeChallenge(in)
	if err != nil {
		t.Fatalf("EncodeChallenge: %v", err)
	}
	out, err := DecodeChallenge(enc)
	if err != nil {
		t.Fatalf("DecodeChallenge: %v", err)
	}
	if out.Status != in.Status || out.SessionID != in.SessionID ||
		!bytes.Equal(out.CredentialBlob, in.CredentialBlob) ||
		!bytes.Equal(out.EncryptedSecret, in.EncryptedSecret) {
		t.Fatal("challenge round trip mismatch")
	}
}

func TestCompleteRoundTrip(t *testing.T) {
	in := &CompleteRequest{
		SessionID: "session-xyz",
		Secret:    bytes.Repeat([]byte{0x09}, 32),
		Version:   Version1,
	}
	enc, err := EncodeComplete(in)
	if err != nil {
		t.Fatalf("EncodeComplete: %v", err)
	}
	out, err := DecodeComplete(enc)
	if err != nil {
		t.Fatalf("DecodeComplete: %v", err)
	}
	if out.SessionID != in.SessionID || !bytes.Equal(out.Secret, in.Secret) {
		t.Fatal("complete round trip mismatch")
	}
}

func TestResultRoundTrip(t *testing.T) {
	in := &ResultReply{
		Status:     StatusOK,
		AIKCertDER: bytes.Repeat([]byte{0x77}, 1500),
		DeviceID:   "device-deadbeef",
		Version:    Version1,
	}
	enc, err := EncodeResult(in)
	if err != nil {
		t.Fatalf("EncodeResult: %v", err)
	}
	out, err := DecodeResult(enc)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if out.Status != in.Status || out.DeviceID != in.DeviceID ||
		!bytes.Equal(out.AIKCertDER, in.AIKCertDER) {
		t.Fatal("result round trip mismatch")
	}
}

// TestEncodeRejectsUnsetVersion covers the reply encoders:
// version selects the frame layout, so an unset field is refused rather
// than resolved to Version1 on the caller's behalf.
func TestEncodeRejectsUnsetVersion(t *testing.T) {
	if _, err := EncodeChallenge(&ChallengeReply{SessionID: "s"}); err != ErrBadVersion {
		t.Fatalf("EncodeChallenge with no version: want ErrBadVersion, got %v", err)
	}
	if _, err := EncodeComplete(&CompleteRequest{SessionID: "s"}); err != ErrBadVersion {
		t.Fatalf("EncodeComplete with no version: want ErrBadVersion, got %v", err)
	}
	if _, err := EncodeResult(&ResultReply{DeviceID: "d"}); err != ErrBadVersion {
		t.Fatalf("EncodeResult with no version: want ErrBadVersion, got %v", err)
	}

	// out-of-range version is refused the same way
	if _, err := EncodeResult(&ResultReply{DeviceID: "d", Version: 9}); err != ErrBadVersion {
		t.Fatalf("EncodeResult with version 9: want ErrBadVersion, got %v", err)
	}
}

func TestDecodeRejectsBadMagic(t *testing.T) {
	enc, _ := EncodeBegin(&BeginRequest{})
	enc[0] ^= 0xFF
	if _, err := DecodeBegin(enc); err != ErrBadMagic {
		t.Fatalf("want ErrBadMagic, got %v", err)
	}
}

func TestDecodeRejectsBadVersion(t *testing.T) {
	enc, _ := EncodeBegin(&BeginRequest{})
	enc[5] = 0xFF
	if _, err := DecodeBegin(enc); err != ErrBadVersion {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
}

func TestDecodeRejectsTruncated(t *testing.T) {
	enc, _ := EncodeChallenge(&ChallengeReply{SessionID: "x", CredentialBlob: []byte{1, 2}, Version: Version1})
	if _, err := DecodeChallenge(enc[:len(enc)-1]); err == nil {
		t.Fatal("accepted truncated frame")
	}
	if _, err := DecodeBegin([]byte{0x01, 0x02}); err == nil {
		t.Fatal("accepted runt frame")
	}
}

func TestDecodeRejectsOversizeField(t *testing.T) {
	// hand-craft a Begin frame whose declared EK cert length exceeds the
	// bound so the decoder rejects it before allocating
	e := newEncoder(Version1)
	e.u16(MaxEKCertSize + 1)
	if _, err := DecodeBegin(e.buf); err != ErrTooLarge {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestEncodeRejectsOversize(t *testing.T) {
	_, err := EncodeBegin(&BeginRequest{EKCertDER: make([]byte, MaxEKCertSize+1)})
	if err != ErrTooLarge {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	body := bytes.Repeat([]byte{0x5A}, 1234)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, body); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("frame round trip mismatch")
	}
}

func TestReadFrameRejectsOversize(t *testing.T) {
	var buf bytes.Buffer
	// length prefix far over the cap
	buf.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	if _, err := ReadFrame(&buf); err == nil {
		t.Fatal("accepted oversize frame length")
	}
}

func TestBeginWithoutTokenStaysVersion1(t *testing.T) {
	enc, err := EncodeBegin(&BeginRequest{EKCertDER: []byte{0xAA}, AIKPublic: []byte{0xBB}})
	if err != nil {
		t.Fatalf("EncodeBegin: %v", err)
	}
	if got := binary.BigEndian.Uint16(enc[4:6]); got != Version1 {
		t.Fatalf("token-less begin frame version = %d, want %d", got, Version1)
	}
	out, err := DecodeBegin(enc)
	if err != nil {
		t.Fatalf("DecodeBegin: %v", err)
	}
	if out.Version != Version1 || out.Token != nil {
		t.Fatalf("decoded version=%d token=%v, want version 1 and no token", out.Version, out.Token)
	}
}

func TestBeginTokenRoundTrip(t *testing.T) {
	in := &BeginRequest{
		EKCertDER: bytes.Repeat([]byte{0xAB}, 900),
		AIKPublic: bytes.Repeat([]byte{0xCD}, 120),
		Token:     []byte("tenant-alpha-enroll-token"),
	}
	enc, err := EncodeBegin(in)
	if err != nil {
		t.Fatalf("EncodeBegin: %v", err)
	}
	if got := binary.BigEndian.Uint16(enc[4:6]); got != Version2 {
		t.Fatalf("token begin frame version = %d, want %d", got, Version2)
	}
	out, err := DecodeBegin(enc)
	if err != nil {
		t.Fatalf("DecodeBegin: %v", err)
	}
	if out.Version != Version2 || !bytes.Equal(out.Token, in.Token) ||
		!bytes.Equal(out.EKCertDER, in.EKCertDER) || !bytes.Equal(out.AIKPublic, in.AIKPublic) {
		t.Fatal("begin token round trip mismatch")
	}
}

func TestBeginVersion2ByteLayout(t *testing.T) {
	// pin the version-2 layout the C agent mirrors:
	// magic, version 2, then length-prefixed EK cert, AIK public, and token
	enc, err := EncodeBegin(&BeginRequest{
		EKCertDER: []byte{0xAA, 0xBB},
		AIKPublic: []byte{0xCC},
		Token:     []byte{'t', 'k'},
	})
	if err != nil {
		t.Fatalf("EncodeBegin: %v", err)
	}
	want := []byte{
		0x4C, 0x43, 0x41, 0x45, 0x00, 0x02,
		0x00, 0x02, 0xAA, 0xBB,
		0x00, 0x01, 0xCC,
		0x00, 0x02, 't', 'k',
	}
	if !bytes.Equal(enc, want) {
		t.Fatalf("version-2 begin layout = %x, want %x", enc, want)
	}
}

func TestBeginVersion2RequiresTokenField(t *testing.T) {
	// version-2 preamble on token-less body is truncated,
	// not silently token-free request
	enc, err := EncodeBegin(&BeginRequest{EKCertDER: []byte{0xAA}, AIKPublic: []byte{0xBB}})
	if err != nil {
		t.Fatalf("EncodeBegin: %v", err)
	}
	enc[5] = byte(Version2)
	if _, err := DecodeBegin(enc); err == nil {
		t.Fatal("accepted a version-2 begin frame without a token field")
	}
}

func TestEncodeBeginRejectsOversizeToken(t *testing.T) {
	_, err := EncodeBegin(&BeginRequest{Token: make([]byte, MaxEnrollTokenSize+1)})
	if err != ErrTooLarge {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestRepliesMirrorRequestVersion(t *testing.T) {
	for _, version := range []uint16{Version1, Version2} {
		ch, err := EncodeChallenge(&ChallengeReply{SessionID: "s", Version: version})
		if err != nil {
			t.Fatalf("EncodeChallenge v%d: %v", version, err)
		}
		if got := binary.BigEndian.Uint16(ch[4:6]); got != version {
			t.Fatalf("challenge frame version = %d, want %d", got, version)
		}
		res, err := EncodeResult(&ResultReply{DeviceID: "d", Version: version})
		if err != nil {
			t.Fatalf("EncodeResult v%d: %v", version, err)
		}
		out, err := DecodeResult(res)
		if err != nil {
			t.Fatalf("DecodeResult v%d: %v", version, err)
		}
		if out.Version != version {
			t.Fatalf("decoded result version = %d, want %d", out.Version, version)
		}
	}
}

func TestEncodeRejectsUnknownVersion(t *testing.T) {
	if _, err := EncodeChallenge(&ChallengeReply{Version: 3}); err != ErrBadVersion {
		t.Fatalf("EncodeChallenge: want ErrBadVersion, got %v", err)
	}
	if _, err := EncodeComplete(&CompleteRequest{Version: 3}); err != ErrBadVersion {
		t.Fatalf("EncodeComplete: want ErrBadVersion, got %v", err)
	}
	if _, err := EncodeResult(&ResultReply{Version: 3}); err != ErrBadVersion {
		t.Fatalf("EncodeResult: want ErrBadVersion, got %v", err)
	}
}
