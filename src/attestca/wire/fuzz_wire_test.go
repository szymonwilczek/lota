// SPDX-License-Identifier: MIT
// LOTA attest-CA - Fuzz tests for the enrollment wire decoders.

package wire

import (
	"bytes"
	"testing"
)

// every decoder must answer (nil, err) on malformed input and a non-nil
// message on success; it must never panic on attacker-controlled bytes.

func FuzzDecodeBegin(f *testing.F) {
	valid, _ := EncodeBegin(&BeginRequest{
		EKCertDER: []byte("ek-cert"),
		AIKPublic: []byte("aik-pub"),
	})
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0x00})       // length prefix cut short
	f.Add([]byte{0xFF, 0xFF}) // length larger than the buffer

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := DecodeBegin(data)
		if err != nil {
			if msg != nil {
				t.Error("DecodeBegin returned non-nil message with error")
			}
			return
		}
		if msg == nil {
			t.Error("DecodeBegin returned nil message without error")
		}
	})
}

func FuzzDecodeChallenge(f *testing.F) {
	valid, _ := EncodeChallenge(&ChallengeReply{
		Status:          0,
		SessionID:       "sid",
		CredentialBlob:  []byte("cred"),
		EncryptedSecret: []byte("secret"),
	})
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := DecodeChallenge(data)
		if err != nil {
			if msg != nil {
				t.Error("DecodeChallenge returned non-nil message with error")
			}
			return
		}
		if msg == nil {
			t.Error("DecodeChallenge returned nil message without error")
		}
	})
}

func FuzzDecodeComplete(f *testing.F) {
	valid, _ := EncodeComplete(&CompleteRequest{
		SessionID: "sid",
		Secret:    []byte("secret"),
	})
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := DecodeComplete(data)
		if err != nil {
			if msg != nil {
				t.Error("DecodeComplete returned non-nil message with error")
			}
			return
		}
		if msg == nil {
			t.Error("DecodeComplete returned nil message without error")
		}
	})
}

func FuzzDecodeResult(f *testing.F) {
	valid, _ := EncodeResult(&ResultReply{
		Status:     0,
		AIKCertDER: []byte("aik-cert"),
		DeviceID:   "dev",
	})
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := DecodeResult(data)
		if err != nil {
			if msg != nil {
				t.Error("DecodeResult returned non-nil message with error")
			}
			return
		}
		if msg == nil {
			t.Error("DecodeResult returned nil message without error")
		}
	})
}

// ReadFrame parses an attacker-supplied u32 length prefix; a hostile prefix
// must yield an error, never an over-allocation panic or a hang.
func FuzzReadFrame(f *testing.F) {
	var framed bytes.Buffer
	_ = WriteFrame(&framed, []byte("body"))
	f.Add(framed.Bytes())
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00})             // header truncated
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})       // huge length, no body
	f.Add([]byte{0x00, 0x00, 0x00, 0x04, 0x41}) // body shorter than length

	f.Fuzz(func(t *testing.T, data []byte) {
		body, err := ReadFrame(bytes.NewReader(data))
		if err != nil {
			if body != nil {
				t.Error("ReadFrame returned non-nil body with error")
			}
			return
		}
		if body == nil {
			t.Error("ReadFrame returned nil body without error")
		}
	})
}
