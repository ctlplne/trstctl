// SPDX-License-Identifier: MPL-2.0

//go:build !linux

package signing

import "net"

// peerUID cannot determine the peer uid on non-Linux platforms; callers must fail
// closed unless an explicit local-development override accepts the
// filesystem-permissions-only fallback.
func peerUID(net.Conn) (int, bool) { return 0, false }

func peerCredentialsSupported() bool { return false }
