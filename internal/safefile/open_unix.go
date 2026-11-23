// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package safefile

import (
	"os"

	"golang.org/x/sys/unix"
)

const readOnlyNonblocking = os.O_RDONLY | unix.O_NONBLOCK
const readOnlyNonblockingNoFollow = readOnlyNonblocking | unix.O_NOFOLLOW
