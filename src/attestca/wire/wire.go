// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Attestation CA - enrollment wire protocol
//
// Four length-prefixed, big-endian messages carry one enrollment over a
// TLS connection:
//
//	agent -> CA : BeginRequest    (EK cert + AIK TPMT_PUBLIC + token, v2)
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

	// Version1 frames carry no enrollment token.
	// Version2 appends one to BeginRequest.
	// Version3 appends the manufacturer intermediates the device holds and
	// carries the token field even when it is empty.
	// All three are current modes: untenanted enrollment is Version1,
	// tenant enrollment presents its token and is Version2,
	// and a device presenting an EK certificate chain is Version3.
	// Agent picks by what it holds;
	// CA mirrors the version of the request in its replies.
	Version1 uint16 = 1
	Version2 uint16 = 2
	Version3 uint16 = 3

	// Version is the newest protocol version this package speaks.
	Version = Version3

	MaxEKCertSize      = 2048
	MaxAIKPublicSize   = 1024
	MaxCredBlobSize    = 1024
	MaxEncSecretSize   = 512
	MaxSecretSize      = 64
	MaxSessionIDSize   = 64
	MaxAIKCertSize     = 4096
	MaxDeviceIDSize    = 128
	MaxEnrollTokenSize = 128

	// MaxEKChainCerts and MaxEKChainBytes bound the manufacturer
	// intermediates a device presents with its EK leaf.
	// Both are frame budget: eight certificates and 8 KB of them still leave
	// the leaf, the AIK template and the token inside MaxFrameSize.
	MaxEKChainCerts = 8
	MaxEKChainBytes = 8192

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
	StatusTokenRejected  uint16 = 8
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

	// Token is the optional enrollment token, carried by Version2 frames
	// and later. EncodeBegin derives the frame version from its presence;
	// DecodeBegin leaves it nil on a Version1 frame.
	Token []byte

	// EKChainDER holds the manufacturer intermediates the device read out
	// of its own TPM, leaf-ward first, carried by Version3 frames only.
	// They are untrusted path material: they may complete a route to a
	// pinned root, never widen the set of roots.
	EKChainDER [][]byte

	// Version is set by DecodeBegin to the version of the received frame
	// so the server can mirror it in the replies.
	Version uint16
}

// ChallengeReply carries the activation material back to the agent.
type ChallengeReply struct {
	Status          uint16
	SessionID       string
	CredentialBlob  []byte
	EncryptedSecret []byte

	// Version selects the version of the encoded frame and must be set:
	// encoder refuses an unset field rather than guessing version.
	// Server sets it to the version of the request it answers,
	// so reply never carries a version the requesting agent did not use.
	Version uint16
}

// CompleteRequest returns the activated secret.
type CompleteRequest struct {
	SessionID string
	Secret    []byte

	// Version selects the version of the encoded frame and must be set
	// (see ChallengeReply.Version)
	// Agent keeps one version for whole exchange.
	Version uint16
}

// ResultReply carries the issued certificate or a failure status.
type ResultReply struct {
	Status     uint16
	AIKCertDER []byte
	DeviceID   string

	// Version selects the version of the encoded frame and must be set
	// (see ChallengeReply.Version)
	Version uint16
}

type encoder struct {
	buf []byte
	err error
}

// frameVersion validates a message's Version field.
// Unset field is refused: the version selects the frame layout, so guessing one
// for a caller that never set it would encode a frame the caller did not ask for.
// Every server reply mirrors the version of the request it answers, so real encode
// path always has one to pass.
func frameVersion(v uint16) (uint16, error) {
	switch v {
	case Version1:
		return Version1, nil
	case Version2:
		return Version2, nil
	case Version3:
		return Version3, nil
	default:
		return 0, ErrBadVersion
	}
}

func newEncoder(version uint16) *encoder {
	e := &encoder{}
	e.u32(Magic)
	e.u16(version)
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
// Frame version follows what the request carries, because that is what the
// versions differ by: an untenanted request has neither field and is Version1,
// a tenant request carries a token and is Version2, and a device presenting
// its manufacturer intermediates is Version3.
func EncodeBegin(r *BeginRequest) ([]byte, error) {
	if len(r.EKCertDER) > MaxEKCertSize || len(r.AIKPublic) > MaxAIKPublicSize ||
		len(r.Token) > MaxEnrollTokenSize || len(r.EKChainDER) > MaxEKChainCerts {
		return nil, ErrTooLarge
	}
	chainBytes := 0
	for _, c := range r.EKChainDER {
		if len(c) > MaxEKCertSize {
			return nil, ErrTooLarge
		}
		chainBytes += len(c)
	}
	if chainBytes > MaxEKChainBytes {
		return nil, ErrTooLarge
	}
	version := Version1
	switch {
	case len(r.EKChainDER) > 0:
		version = Version3
	case len(r.Token) > 0:
		version = Version2
	}
	e := newEncoder(version)
	e.bytes16(r.EKCertDER)
	e.bytes16(r.AIKPublic)
	// Version3 carries the token field whether or not it holds one
	if version >= Version2 {
		e.bytes16(r.Token)
	}
	if version >= Version3 {
		e.u16(uint16(len(r.EKChainDER)))
		for _, c := range r.EKChainDER {
			e.bytes16(c)
		}
	}
	return e.result()
}

// EncodeChallenge serializes a ChallengeReply.
func EncodeChallenge(r *ChallengeReply) ([]byte, error) {
	version, err := frameVersion(r.Version)
	if err != nil {
		return nil, err
	}
	if len(r.SessionID) > MaxSessionIDSize ||
		len(r.CredentialBlob) > MaxCredBlobSize ||
		len(r.EncryptedSecret) > MaxEncSecretSize {
		return nil, ErrTooLarge
	}
	e := newEncoder(version)
	e.u16(r.Status)
	e.bytes16([]byte(r.SessionID))
	e.bytes16(r.CredentialBlob)
	e.bytes16(r.EncryptedSecret)
	return e.result()
}

// EncodeComplete serializes a CompleteRequest.
func EncodeComplete(r *CompleteRequest) ([]byte, error) {
	version, err := frameVersion(r.Version)
	if err != nil {
		return nil, err
	}
	if len(r.SessionID) > MaxSessionIDSize || len(r.Secret) > MaxSecretSize {
		return nil, ErrTooLarge
	}
	e := newEncoder(version)
	e.bytes16([]byte(r.SessionID))
	e.bytes16(r.Secret)
	return e.result()
}

// EncodeResult serializes a ResultReply.
func EncodeResult(r *ResultReply) ([]byte, error) {
	version, err := frameVersion(r.Version)
	if err != nil {
		return nil, err
	}
	if len(r.AIKCertDER) > MaxAIKCertSize || len(r.DeviceID) > MaxDeviceIDSize {
		return nil, ErrTooLarge
	}
	e := newEncoder(version)
	e.u16(r.Status)
	e.bytes16(r.AIKCertDER)
	e.bytes16([]byte(r.DeviceID))
	return e.result()
}

type decoder struct {
	buf     []byte
	off     int
	version uint16
}

func newDecoder(b []byte) (*decoder, error) {
	if len(b) < 6 {
		return nil, ErrShort
	}
	if binary.BigEndian.Uint32(b[0:4]) != Magic {
		return nil, ErrBadMagic
	}
	v := binary.BigEndian.Uint16(b[4:6])
	if v != Version1 && v != Version2 && v != Version3 {
		return nil, ErrBadVersion
	}
	return &decoder{buf: b, off: 6, version: v}, nil
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
	req := &BeginRequest{EKCertDER: ekCert, AIKPublic: aikPub, Version: d.version}
	if d.version >= Version2 {
		req.Token, err = d.bytes16(MaxEnrollTokenSize)
		if err != nil {
			return nil, err
		}
	}
	if d.version >= Version3 {
		req.EKChainDER, err = d.chain()
		if err != nil {
			return nil, err
		}
	}
	return req, nil
}

// chain reads the count-prefixed list of manufacturer intermediates.
// The peer is unauthenticated at this point and stays so: the count is
// checked before a single element is allocated, and the elements are bounded
// individually and in total.
func (d *decoder) chain() ([][]byte, error) {
	n, err := d.u16()
	if err != nil {
		return nil, err
	}
	if int(n) > MaxEKChainCerts {
		return nil, ErrTooLarge
	}
	total := 0
	out := make([][]byte, 0, n)
	for i := 0; i < int(n); i++ {
		cert, err := d.bytes16(MaxEKCertSize)
		if err != nil {
			return nil, err
		}
		total += len(cert)
		if total > MaxEKChainBytes {
			return nil, ErrTooLarge
		}
		out = append(out, cert)
	}
	return out, nil
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
		Version:         d.version,
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
	return &CompleteRequest{SessionID: string(sid), Secret: secret, Version: d.version}, nil
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
	return &ResultReply{Status: status, AIKCertDER: cert, DeviceID: string(dev), Version: d.version}, nil
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
