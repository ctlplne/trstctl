// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package privatesocket

import (
	"errors"
	"os"
)

func ownerUID(os.FileInfo) (int, error) {
	return 0, errors.New("unix socket owner validation is unavailable on Windows")
}
