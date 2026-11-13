// SPDX-License-Identifier: BUSL-1.1

//go:build !linux

package netconfine

import (
	"io"
	"os/exec"
)

// Supported reports whether this platform can confine a command's network.
const Supported = false

// Isolate is not available here: callers check Supported first.
func Isolate(*exec.Cmd) error { return ErrUnsupported }

// RunHelper is not available here.
func RunHelper(_ []string, _ io.Reader, _, stderr io.Writer) int {
	_, _ = io.WriteString(stderr, ErrUnsupported.Error()+"\n")
	return 125
}
