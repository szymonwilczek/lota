// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Attestation CA - enrollment wire protocol
//
// Four length-prefixed, big-endian messages carry one enrollment over a
// TLS connection:
//
//	agent -> CA : BeginRequest    (EK cert + AIK TPMT_PUBLIC)
//	CA -> agent : ChallengeReply  (session id + credential blob + secret)
//	agent -> CA : CompleteRequest (session id + activated secret)
//	CA -> agent : ResultReply     (AIK certificate + device id)
//
// Every variable field is bounded so a peer cannot force an unbounded
// allocation.
// C agent mirrors this layout in include/lota_enroll.h

package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	// Magic identifies an enrollment frame
	// ("LCAE", little-endian read in C, encoded
	// big-endian here for a stable on-wire byte order)
	Magic uint32 = 0x4C434145

	// Version is the enrollment protocol version.
	Version uint16 = 1

	MaxEKCertSize    = 2048
	MaxAIKPublicSize = 1024
	MaxCredBlobSize  = 1024
	MaxEncSecretSize = 512
	MaxSecretSize    = 64
	MaxSessionIDSize = 64
	MaxAIKCertSize   = 4096
	MaxDeviceIDSize  = 128

	// MaxFrameSize bounds a single decoded message body.
	MaxFrameSize = 16 * 1024
)

// Status codes returned by the CA in reply messages.
const (
	StatusOK             uint16 = 0
	StatusBadRequest     uint16 = 1
	StatusEKRejected     uint16 = 2
	StatusAIKRejected    uint16 = 3
	StatusActivationFail uint16 = 4
	StatusUnknownSession uint16 = 5
	StatusInternalError  uint16 = 6
	StatusRateLimited    uint16 = 7
)

var (
	ErrBadMagic   = errors.New("enroll: bad frame magic")
	ErrBadVersion = errors.New("enroll: unsupported protocol version")
	ErrTooLarge   = errors.New("enroll: field exceeds bound")
	ErrShort      = errors.New("enroll: frame truncated")
)

// BeginRequest is the agent's opening message.
type BeginRequest struct {
	EKCertDER []byte
	AIKPublic []byte // marshaled TPMT_PUBLIC
}

// ChallengeReply carries the activation material back to the agent.
type ChallengeReply struct {
	Status          uint16
	SessionID       string
	CredentialBlob  []byte
	EncryptedSecret []byte
}

// CompleteRequest returns the activated secret.
type CompleteRequest struct {
	SessionID string
	Secret    []byte
}

// ResultReply carries the issued certificate or a failure status.
type ResultReply struct {
	Status     uint16
	AIKCertDER []byte
	DeviceID   string
}

type encoder struct {
	buf []byte
	err error
}

func newEncoder() *encoder {
	e := &encoder{}
	e.u32(Magic)
	e.u16(Version)
	return e
}

func (e *encoder) u16(v uint16) {
	e.buf = binary.BigEndian.AppendUint16(e.buf, v)
}

func (e *encoder) u32(v uint32) {
	e.buf = binary.BigEndian.AppendUint32(e.buf, v)
}

func (e *encoder) bytes16(b []byte) {
	if e.err != nil {
		return
	}
	n := len(b)
	// every caller validates its fields against the Max* limits above, all far below 65535
	// guard the length prefix so the conversion cannot overflow
	if n < 0 || n > math.MaxUint16 {
		e.err = ErrTooLarge
		return
	}
	e.u16(uint16(n))
	e.buf = append(e.buf, b...)
}

// result returns the encoded bytes, or the first error a bytes16 hit.
func (e *encoder) result() ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	return e.buf, nil
}

// EncodeBegin serializes a BeginRequest.
func EncodeBegin(r *BeginRequest) ([]byte, error) {
	if len(r.EKCertDER) > MaxEKCertSize || len(r.AIKPublic) > MaxAIKPublicSize {
		return nil, ErrTooLarge
	}
	e := newEncoder()
	e.bytes16(r.EKCertDER)
	e.bytes16(r.AIKPublic)
	return e.result()
}

// EncodeChallenge serializes a ChallengeReply.
func EncodeChallenge(r *ChallengeReply) ([]byte, error) {
	if len(r.SessionID) > MaxSessionIDSize ||
		len(r.CredentialBlob) > MaxCredBlobSize ||
		len(r.EncryptedSecret) > MaxEncSecretSize {
		return nil, ErrTooLarge
	}
	e := newEncoder()
	e.u16(r.Status)
	e.bytes16([]byte(r.SessionID))
	e.bytes16(r.CredentialBlob)
	e.bytes16(r.EncryptedSecret)
	return e.result()
}

// EncodeComplete serializes a CompleteRequest.
func EncodeComplete(r *CompleteRequest) ([]byte, error) {
	if len(r.SessionID) > MaxSessionIDSize || len(r.Secret) > MaxSecretSize {
		return nil, ErrTooLarge
	}
	e := newEncoder()
	e.bytes16([]byte(r.SessionID))
	e.bytes16(r.Secret)
	return e.result()
}

// EncodeResult serializes a ResultReply.
func EncodeResult(r *ResultReply) ([]byte, error) {
	if len(r.AIKCertDER) > MaxAIKCertSize || len(r.DeviceID) > MaxDeviceIDSize {
		return nil, ErrTooLarge
	}
	e := newEncoder()
	e.u16(r.Status)
	e.bytes16(r.AIKCertDER)
	e.bytes16([]byte(r.DeviceID))
	return e.result()
}

type decoder struct {
	buf []byte
	off int
}

func newDecoder(b []byte) (*decoder, error) {
	if len(b) < 6 {
		return nil, ErrShort
	}
	if binary.BigEndian.Uint32(b[0:4]) != Magic {
		return nil, ErrBadMagic
	}
	if binary.BigEndian.Uint16(b[4:6]) != Version {
		return nil, ErrBadVersion
	}
	return &decoder{buf: b, off: 6}, nil
}

func (d *decoder) u16() (uint16, error) {
	if d.off+2 > len(d.buf) {
		return 0, ErrShort
	}
	v := binary.BigEndian.Uint16(d.buf[d.off : d.off+2])
	d.off += 2
	return v, nil
}

func (d *decoder) bytes16(maxLen int) ([]byte, error) {
	n, err := d.u16()
	if err != nil {
		return nil, err
	}
	if int(n) > maxLen {
		return nil, ErrTooLarge
	}
	if d.off+int(n) > len(d.buf) {
		return nil, ErrShort
	}
	out := make([]byte, n)
	copy(out, d.buf[d.off:d.off+int(n)])
	d.off += int(n)
	return out, nil
}

// DecodeBegin parses a BeginRequest.
func DecodeBegin(b []byte) (*BeginRequest, error) {
	d, err := newDecoder(b)
	if err != nil {
		return nil, err
	}
	ekCert, err := d.bytes16(MaxEKCertSize)
	if err != nil {
		return nil, err
	}
	aikPub, err := d.bytes16(MaxAIKPublicSize)
	if err != nil {
		return nil, err
	}
	return &BeginRequest{EKCertDER: ekCert, AIKPublic: aikPub}, nil
}

// DecodeChallenge parses a ChallengeReply.
func DecodeChallenge(b []byte) (*ChallengeReply, error) {
	d, err := newDecoder(b)
	if err != nil {
		return nil, err
	}
	status, err := d.u16()
	if err != nil {
		return nil, err
	}
	sid, err := d.bytes16(MaxSessionIDSize)
	if err != nil {
		return nil, err
	}
	cred, err := d.bytes16(MaxCredBlobSize)
	if err != nil {
		return nil, err
	}
	secret, err := d.bytes16(MaxEncSecretSize)
	if err != nil {
		return nil, err
	}
	return &ChallengeReply{
		Status:          status,
		SessionID:       string(sid),
		CredentialBlob:  cred,
		EncryptedSecret: secret,
	}, nil
}

// DecodeComplete parses a CompleteRequest.
func DecodeComplete(b []byte) (*CompleteRequest, error) {
	d, err := newDecoder(b)
	if err != nil {
		return nil, err
	}
	sid, err := d.bytes16(MaxSessionIDSize)
	if err != nil {
		return nil, err
	}
	secret, err := d.bytes16(MaxSecretSize)
	if err != nil {
		return nil, err
	}
	return &CompleteRequest{SessionID: string(sid), Secret: secret}, nil
}

// DecodeResult parses a ResultReply.
func DecodeResult(b []byte) (*ResultReply, error) {
	d, err := newDecoder(b)
	if err != nil {
		return nil, err
	}
	status, err := d.u16()
	if err != nil {
		return nil, err
	}
	cert, err := d.bytes16(MaxAIKCertSize)
	if err != nil {
		return nil, err
	}
	dev, err := d.bytes16(MaxDeviceIDSize)
	if err != nil {
		return nil, err
	}
	return &ResultReply{Status: status, AIKCertDER: cert, DeviceID: string(dev)}, nil
}

// WriteFrame writes a length-prefixed frame: u32 body length then body.
func WriteFrame(w io.Writer, body []byte) error {
	if len(body) > MaxFrameSize {
		return ErrTooLarge
	}
	n := len(body)
	// MaxFrameSize already bounds body well within uint32
	// keep the explicit guard so the length-prefix conversion is provably safe
	if n < 0 || n > math.MaxUint32 {
		return ErrTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(n))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// ReadFrame reads a length-prefixed frame written by WriteFrame.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameSize {
		return nil, fmt.Errorf("%w: frame length %d", ErrTooLarge, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}
