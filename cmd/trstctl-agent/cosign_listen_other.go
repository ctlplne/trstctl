// SPDX-License-Identifier: BUSL-1.1

//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris)

package main

import (
	"errors"
	"net"
)

// listenPrivateUnixSocket refuses on platforms that cannot create an owner-only
// socket and report the peer's uid; use a pinned-mTLS host:port listener there.
func listenPrivateUnixSocket(string) (net.Listener, error) {
	return nil, errors.New("an owner-only unix co-sign socket is not supported on this platform; use a host:port listener with pinned mutual TLS")
}
