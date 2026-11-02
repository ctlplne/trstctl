// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package secretrender

// allowReplace is a no-op where a rename replaces a file whatever its mode.
func allowReplace(string) error { return nil }
