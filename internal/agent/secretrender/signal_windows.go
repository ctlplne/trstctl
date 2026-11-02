// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package secretrender

import "errors"

// signalProcess: Windows has no reload signals; configure a reload command.
func signalProcess(int, string) error {
	return errors.New("secretrender: signals are not available on Windows; use a reload command")
}
