// SPDX-License-Identifier: MIT

package store

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// identifies a deterministic position in the bans stream
// serialized as "<unix_nano>:<hardware_id_hex>"
type BanCursor struct {
	BannedAt   time.Time
	HardwareID [32]byte
}

func EncodeBanCursor(e BanEntry) string {
	return fmt.Sprintf("%d:%s", e.BannedAt.UTC().UnixNano(), FormatHardwareID(e.HardwareID))
}

func DecodeBanCursor(nextID string) (BanCursor, error) {
	var cur BanCursor
	parts := strings.Split(nextID, ":")
	if len(parts) != 2 {
		return cur, errors.New("invalid next_id format")
	}

	nanos, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || nanos <= 0 {
		return cur, errors.New("invalid next_id timestamp")
	}

	hwid, err := ParseHardwareID(parts[1])
	if err != nil {
		return cur, errors.New("invalid next_id hardware ID")
	}

	cur.BannedAt = time.Unix(0, nanos).UTC()
	cur.HardwareID = hwid
	return cur, nil
}
