// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"strconv"
)

// Hashed before comparing so the comparison is over two equal-length values:
// ConstantTimeCompare returns 0 immediately for different lengths, which leaks
// the length of the password.
func constantTimeEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

func itoa(n int) string { return strconv.Itoa(n) }
