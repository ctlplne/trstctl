// SPDX-License-Identifier: BUSL-1.1
//go:build !linux

package rdp

import (
	"context"
	"errors"
)

func startNative(context.Context, string, Target, []byte) (*Stream, error) {
	return nil, errors.New("rdp: desktop credential helper requires a Linux gateway")
}

// CheckHelper reports that native desktop authentication needs Linux.
func CheckHelper(string) error { return errors.New("rdp: desktop credential helper requires Linux") }
