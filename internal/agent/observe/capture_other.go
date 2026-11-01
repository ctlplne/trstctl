// SPDX-License-Identifier: BUSL-1.1

//go:build !linux

package observe

import (
	"context"
	"errors"
)

// Capture needs Linux AF_PACKET. On any other platform the observer reports
// an error, never an empty observation set.
func Capture(context.Context, string, []uint16, int, *Assembler) error {
	return errors.New("observe: passive observation needs a Linux agent (AF_PACKET); this build cannot observe")
}

// Footprint reports nothing where the observer cannot run.
func Footprint() (float64, uint64) { return 0, 0 }
