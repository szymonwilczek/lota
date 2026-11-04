// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - PCR 14 re-pin after a MOK change

package verify

import (
	"errors"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// ErrPCR14RepinRaced is returned by RepinPCR14 when the pinned register is no
// longer the one the decision was made against.
var ErrPCR14RepinRaced = errors.New("PCR 14 re-pin: pinned register moved")

// PCR14RepinStorer is optionally implemented by baseline stores that can move
// a client's pinned PCR 14 after its MOK state changed.
//
// RepinPCR14 replaces the pinned register from -> to and stores eventLog as the
// client's boot evidence in one write, so the next diff runs against the boot
// that produced the new pin. It returns ErrPCR14RepinRaced when the row no
// longer holds from.
type PCR14RepinStorer interface {
	RepinPCR14(clientID string, from, to [types.HashSize]byte,
		eventLog []byte, now time.Time) error
}
