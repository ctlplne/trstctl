// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package secretrender

import "os"

// restrictPath is the file mode itself on Unix, which writeAtomic applies.
func restrictPath(string, os.FileMode) error { return nil }
