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

// replies mirror their request, so an unset version is refused
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

// absent token and chain still occupy their length and count
func TestBeginWithoutTokenOrChainWritesBothFields(t *testing.T) {
	enc, err := EncodeBegin(&BeginRequest{EKCertDER: []byte{0xAA}, AIKPublic: []byte{0xBB}})
	if err != nil {
		t.Fatalf("EncodeBegin: %v", err)
	}

	// preamble, EK, AIK, empty token, zero count
	if len(enc) != 6+3+3+2+2 {
		t.Fatalf("token-less begin frame is %d bytes, want %d", len(enc), 6+3+3+2+2)
	}
	if got := binary.BigEndian.Uint16(enc[4:6]); got != Version {
		t.Fatalf("token-less begin frame version = %d, want %d", got, Version)
	}
	out, err := DecodeBegin(enc)
	if err != nil {
		t.Fatalf("DecodeBegin: %v", err)
	}
	if out.Version != Version || len(out.Token) != 0 || len(out.EKChainDER) != 0 {
		t.Fatalf("decoded version=%d token=%v chain=%d, want version %d, no token and no chain",
			out.Version, out.Token, len(out.EKChainDER), Version)
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
	if got := binary.BigEndian.Uint16(enc[4:6]); got != Version {
		t.Fatalf("token begin frame version = %d, want %d", got, Version)
	}
	out, err := DecodeBegin(enc)
	if err != nil {
		t.Fatalf("DecodeBegin: %v", err)
	}
	if out.Version != Version || !bytes.Equal(out.Token, in.Token) ||
		!bytes.Equal(out.EKCertDER, in.EKCertDER) || !bytes.Equal(out.AIKPublic, in.AIKPublic) {
		t.Fatal("begin token round trip mismatch")
	}
}

func TestBeginTokenByteLayout(t *testing.T) {
	// pinned for the C agent: magic, version, EK, AIK, token, chain count
	enc, err := EncodeBegin(&BeginRequest{
		EKCertDER: []byte{0xAA, 0xBB},
		AIKPublic: []byte{0xCC},
		Token:     []byte{'t', 'k'},
	})
	if err != nil {
		t.Fatalf("EncodeBegin: %v", err)
	}
	want := []byte{
		0x4C, 0x43, 0x41, 0x45, 0x00, 0x01,
		0x00, 0x02, 0xAA, 0xBB,
		0x00, 0x01, 0xCC,
		0x00, 0x02, 't', 'k',
		0x00, 0x00, // no intermediates
	}
	if !bytes.Equal(enc, want) {
		t.Fatalf("begin token layout = %x, want %x", enc, want)
	}
}

// a body stopping before a field is truncated, not a field absent
func TestDecodeBeginRequiresEveryField(t *testing.T) {
	preamble := []byte{0x4C, 0x43, 0x41, 0x45, 0x00, 0x01}
	body := append(preamble, 0x00, 0x01, 0xAA, 0x00, 0x01, 0xBB)

	if _, err := DecodeBegin(body); err != ErrShort {
		t.Fatalf("body stopping before the token field: want ErrShort, got %v", err)
	}
	if _, err := DecodeBegin(append(body, 0x00, 0x00)); err != ErrShort {
		t.Fatalf("body stopping before the chain count: want ErrShort, got %v", err)
	}
	if _, err := DecodeBegin(append(body, 0x00, 0x00, 0x00, 0x00)); err != nil {
		t.Fatalf("a whole body with both fields empty: %v", err)
	}
}

func TestEncodeBeginRejectsOversizeToken(t *testing.T) {
	_, err := EncodeBegin(&BeginRequest{Token: make([]byte, MaxEnrollTokenSize+1)})
	if err != ErrTooLarge {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestRepliesMirrorRequestVersion(t *testing.T) {
	for _, version := range []uint16{Version1} {
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

// numbers above Version1, including the old shape selectors,
// are refused both ways
func TestEncodeRejectsUnknownVersion(t *testing.T) {
	for _, version := range []uint16{2, 3, 4} {
		if _, err := EncodeChallenge(&ChallengeReply{Version: version}); err != ErrBadVersion {
			t.Fatalf("EncodeChallenge v%d: want ErrBadVersion, got %v", version, err)
		}
		if _, err := EncodeComplete(&CompleteRequest{Version: version}); err != ErrBadVersion {
			t.Fatalf("EncodeComplete v%d: want ErrBadVersion, got %v", version, err)
		}
		if _, err := EncodeResult(&ResultReply{Version: version}); err != ErrBadVersion {
			t.Fatalf("EncodeResult v%d: want ErrBadVersion, got %v", version, err)
		}
	}
}

func TestDecodeRejectsRetiredVersions(t *testing.T) {
	for _, version := range []uint16{0, 2, 3, 4, 0xFFFF} {
		enc, err := EncodeBegin(&BeginRequest{EKCertDER: []byte{0xAA}, AIKPublic: []byte{0xBB}})
		if err != nil {
			t.Fatalf("EncodeBegin: %v", err)
		}
		binary.BigEndian.PutUint16(enc[4:6], version)
		if _, err := DecodeBegin(enc); err != ErrBadVersion {
			t.Fatalf("DecodeBegin v%d: want ErrBadVersion, got %v", version, err)
		}
	}
}

// trailing bytes are refused, or a begin with a token could enroll untenanted
func TestDecodeRejectsTrailingBytes(t *testing.T) {
	begin, err := EncodeBegin(&BeginRequest{EKCertDER: []byte{0xAA}, AIKPublic: []byte{0xBB}, Token: []byte("t")})
	if err != nil {
		t.Fatalf("EncodeBegin: %v", err)
	}
	challenge, err := EncodeChallenge(&ChallengeReply{SessionID: "s", Version: Version1})
	if err != nil {
		t.Fatalf("EncodeChallenge: %v", err)
	}
	complete, err := EncodeComplete(&CompleteRequest{SessionID: "s", Secret: []byte{1}, Version: Version1})
	if err != nil {
		t.Fatalf("EncodeComplete: %v", err)
	}
	result, err := EncodeResult(&ResultReply{DeviceID: "d", Version: Version1})
	if err != nil {
		t.Fatalf("EncodeResult: %v", err)
	}

	for _, tc := range []struct {
		name   string
		body   []byte
		decode func([]byte) error
	}{
		{"begin", begin, func(b []byte) error { _, err := DecodeBegin(b); return err }},
		{"challenge", challenge, func(b []byte) error { _, err := DecodeChallenge(b); return err }},
		{"complete", complete, func(b []byte) error { _, err := DecodeComplete(b); return err }},
		{"result", result, func(b []byte) error { _, err := DecodeResult(b); return err }},
	} {
		if err := tc.decode(tc.body); err != nil {
			t.Fatalf("%s: whole body: %v", tc.name, err)
		}
		// one byte too many is a different frame, not this one
		if err := tc.decode(append(tc.body, 0x00)); err != ErrTrailing {
			t.Fatalf("%s with a trailing byte: want ErrTrailing, got %v", tc.name, err)
		}
		// and so is a whole appended field
		if err := tc.decode(append(tc.body, 0x00, 0x01, 0xFF)); err != ErrTrailing {
			t.Fatalf("%s with an appended field: want ErrTrailing, got %v", tc.name, err)
		}
	}
}

// chain closes the frame: a count, then length-prefixed certificates;
// pinned byte for byte against tests/test_enroll_wire.c
func TestBeginChainByteLayout(t *testing.T) {
	enc, err := EncodeBegin(&BeginRequest{
		EKCertDER: []byte{0xAA, 0xBB},
		AIKPublic: []byte{0xCC},
		EKChainDER: [][]byte{
			{0x30, 0x01, 0xDD},
			{0x30, 0x01, 0xEE},
		},
	})
	if err != nil {
		t.Fatalf("EncodeBegin: %v", err)
	}
	want := []byte{
		0x4C, 0x43, 0x41, 0x45, 0x00, 0x01,
		0x00, 0x02, 0xAA, 0xBB,
		0x00, 0x01, 0xCC,
		0x00, 0x00, // token field present and empty
		0x00, 0x02, // two intermediates
		0x00, 0x03, 0x30, 0x01, 0xDD,
		0x00, 0x03, 0x30, 0x01, 0xEE,
	}
	if !bytes.Equal(enc, want) {
		t.Fatalf("begin chain layout = %x, want %x", enc, want)
	}
}

func TestBeginChainRoundTrip(t *testing.T) {
	in := &BeginRequest{
		EKCertDER:  bytes.Repeat([]byte{0xAB}, 900),
		AIKPublic:  bytes.Repeat([]byte{0xCD}, 120),
		Token:      []byte("tenant-alpha-enroll-token"),
		EKChainDER: [][]byte{bytes.Repeat([]byte{0x01}, 700), bytes.Repeat([]byte{0x02}, 640)},
	}
	enc, err := EncodeBegin(in)
	if err != nil {
		t.Fatalf("EncodeBegin: %v", err)
	}
	if got := binary.BigEndian.Uint16(enc[4:6]); got != Version {
		t.Fatalf("chain begin frame version = %d, want %d", got, Version)
	}
	out, err := DecodeBegin(enc)
	if err != nil {
		t.Fatalf("DecodeBegin: %v", err)
	}
	if out.Version != Version || !bytes.Equal(out.Token, in.Token) ||
		!bytes.Equal(out.EKCertDER, in.EKCertDER) || !bytes.Equal(out.AIKPublic, in.AIKPublic) {
		t.Fatal("begin chain round trip mismatch")
	}
	if len(out.EKChainDER) != len(in.EKChainDER) {
		t.Fatalf("decoded %d intermediates, want %d", len(out.EKChainDER), len(in.EKChainDER))
	}
	for i := range in.EKChainDER {
		if !bytes.Equal(out.EKChainDER[i], in.EKChainDER[i]) {
			t.Fatalf("intermediate %d round trip mismatch", i)
		}
	}
}

// no intermediates: count zero, decoded as an empty chain
func TestBeginWithoutChainWritesAZeroCount(t *testing.T) {
	enc, err := EncodeBegin(&BeginRequest{EKCertDER: []byte{0xAA}, AIKPublic: []byte{0xBB}, Token: []byte("t")})
	if err != nil {
		t.Fatalf("EncodeBegin: %v", err)
	}
	if got := binary.BigEndian.Uint16(enc[len(enc)-2:]); got != 0 {
		t.Fatalf("chainless begin chain count = %d, want 0", got)
	}
	out, err := DecodeBegin(enc)
	if err != nil {
		t.Fatalf("DecodeBegin: %v", err)
	}
	if len(out.EKChainDER) != 0 {
		t.Fatalf("decoded %d intermediates, want none", len(out.EKChainDER))
	}
}

// The chain is data the CA takes from an unauthenticated peer before it has
// verified anything, so every bound on it is load-bearing
func TestEncodeBeginRejectsOversizeChain(t *testing.T) {
	tooMany := make([][]byte, MaxEKChainCerts+1)
	for i := range tooMany {
		tooMany[i] = []byte{0x30, 0x00}
	}
	if _, err := EncodeBegin(&BeginRequest{EKChainDER: tooMany}); err != ErrTooLarge {
		t.Fatalf("too many intermediates: want ErrTooLarge, got %v", err)
	}

	oversize := [][]byte{make([]byte, MaxEKCertSize+1)}
	if _, err := EncodeBegin(&BeginRequest{EKChainDER: oversize}); err != ErrTooLarge {
		t.Fatalf("oversize intermediate: want ErrTooLarge, got %v", err)
	}

	bulk := make([][]byte, MaxEKChainCerts)
	for i := range bulk {
		bulk[i] = make([]byte, MaxEKCertSize)
	}
	if _, err := EncodeBegin(&BeginRequest{EKChainDER: bulk}); err != ErrTooLarge {
		t.Fatalf("chain past the byte budget: want ErrTooLarge, got %v", err)
	}
}

func TestDecodeBeginRejectsOversizeChain(t *testing.T) {
	// count above MaxEKChainCerts
	body := []byte{0x4C, 0x43, 0x41, 0x45, 0x00, 0x01, 0x00, 0x01, 0xAA, 0x00, 0x01, 0xBB, 0x00, 0x00}
	body = append(body, byte((MaxEKChainCerts+1)>>8), byte(MaxEKChainCerts+1))
	if _, err := DecodeBegin(body); err != ErrTooLarge {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}

	// count the body does not deliver: truncated
	body[len(body)-2], body[len(body)-1] = 0x00, 0x02
	body = append(body, 0x00, 0x01, 0xCC)
	if _, err := DecodeBegin(body); err != ErrShort {
		t.Fatalf("count of two with one certificate: want ErrShort, got %v", err)
	}
}
