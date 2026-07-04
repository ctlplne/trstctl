// SPDX-License-Identifier: MPL-2.0

// Package secrettext contains tiny edge helpers for authority-bearing bytes that
// must cross APIs requiring string values, such as net/http headers.
package secrettext

import "trstctl.com/trstctl/internal/crypto/secret"

// Clone returns an owned copy of material for long-lived provider structs.
func Clone(material []byte) []byte {
	if material == nil {
		return nil
	}
	return append([]byte(nil), material...)
}

// Prefixed builds prefix+material as a Go string for APIs that force string
// values. The temporary byte assembly buffer is wiped immediately after the
// edge string is created.
func Prefixed(prefix string, material []byte) string {
	buf := make([]byte, 0, len(prefix)+len(material))
	buf = append(buf, prefix...)
	buf = append(buf, material...)
	out := string(buf)
	secret.Wipe(buf)
	return out
}

// String builds material as a Go string for APIs that force string values.
func String(material []byte) string {
	return Prefixed("", material)
}
