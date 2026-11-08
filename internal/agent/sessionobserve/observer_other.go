// SPDX-License-Identifier: BUSL-1.1

//go:build !linux || !(amd64 || arm64)

package sessionobserve

import "errors"

// Libraries names the OpenSSL 3 libraries the probes attach to.
type Libraries struct {
	SSL    string
	Crypto string
}

// Observer is unavailable here.
type Observer struct{}

var errUnsupported = errors.New("the TLS session observer needs Linux on x86-64 or arm64 (eBPF uprobes)")

// DefaultLibraries is unavailable here.
func DefaultLibraries() (Libraries, error) { return Libraries{}, errUnsupported }

// Open is unavailable here: it never returns an observer that sees nothing.
func Open(Libraries, *Assembler) (*Observer, error) { return nil, errUnsupported }

// RingDrops is zero.
func (*Observer) RingDrops() uint64 { return 0 }

// Close does nothing.
func (*Observer) Close() error { return nil }
