// SPDX-License-Identifier: MPL-2.0

//go:build !linux

package signing

// Harden fails closed on non-Linux platforms. The signer cannot claim AN-4/AN-8
// production hardening without process dump/ptrace controls, UDS peer-UID
// binding, and locked/no-dump secret memory.
func Harden() error { return ErrUnsupportedHardening }
