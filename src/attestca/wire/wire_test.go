// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package wire

import (
	"bytes"
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
	in := &CompleteRequest{SessionID: "session-xyz", Secret: bytes.Repeat([]byte{0x09}, 32)}
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
	enc, _ := EncodeChallenge(&ChallengeReply{SessionID: "x", CredentialBlob: []byte{1, 2}})
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
	e := newEncoder()
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
