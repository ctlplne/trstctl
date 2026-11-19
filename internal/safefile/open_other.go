// SPDX-License-Identifier: BUSL-1.1

//go:build !unix

package safefile

import "os"

const readOnlyNonblocking = os.O_RDONLY
