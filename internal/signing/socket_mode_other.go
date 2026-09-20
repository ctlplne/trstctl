// SPDX-License-Identifier: BUSL-1.1

//go:build js || plan9 || wasip1 || windows

package signing

import "net"

// Non-POSIX platforms have no process umask. The explicit development-only
// non-Linux serving path still performs and verifies chmod in listenUDS; the
// production path fails closed earlier when peer credentials are unavailable.
func listenPrivateUnixSocket(socketPath string) (net.Listener, error) {
	return net.Listen("unix", socketPath)
}
