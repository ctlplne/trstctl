// SPDX-License-Identifier: BUSL-1.1

//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package main

import (
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

var coSignUmaskMu sync.Mutex

// listenPrivateUnixSocket creates the co-sign socket with mode 0600 at bind time.
// The umask is process-wide, so the short change is serialized and restored.
func listenPrivateUnixSocket(path string) (net.Listener, error) {
	coSignUmaskMu.Lock()
	old := unix.Umask(0o177)
	defer func() {
		unix.Umask(old)
		coSignUmaskMu.Unlock()
	}()
	return net.Listen("unix", path)
}
