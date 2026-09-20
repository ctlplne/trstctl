// SPDX-License-Identifier: BUSL-1.1

//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package signing

import (
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

var socketUmaskMu sync.Mutex

// listenPrivateUnixSocket applies the restrictive mode at bind time. Umask is
// process-wide, so serialize the short change and restore the caller's value
// before returning. The temporary mask can only make an unrelated concurrent
// creation more restrictive, never expose it; the mutex also makes every signer
// listener creation deterministic.
func listenPrivateUnixSocket(socketPath string) (net.Listener, error) {
	socketUmaskMu.Lock()
	oldMask := unix.Umask(0o177)
	defer func() {
		unix.Umask(oldMask)
		socketUmaskMu.Unlock()
	}()
	return net.Listen("unix", socketPath)
}
