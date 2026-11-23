// SPDX-License-Identifier: BUSL-1.1
//go:build !linux && !windows && !darwin

package secret

func allocProtected(int) ([]byte, error) { return nil, ErrProtectedMemory }
func freeProtected([]byte) error         { return nil }
