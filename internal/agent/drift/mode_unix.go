//go:build unix

package drift

import (
	"fmt"
	"os"
)

// permissionDetectionSupported is true on POSIX: the file mode bits are the
// access-control mechanism.
const permissionDetectionSupported = true

// permissionDrifted reports whether the file's POSIX permissions diverged from
// what was declared. An exact declared Mode must match; independently, a
// Restricted credential must not grant any group or other access (the
// world-readable-key regression).
func permissionDrifted(_ string, info os.FileInfo, w Watched) (bool, string) {
	perm := info.Mode().Perm()
	if w.Mode != 0 && perm != w.Mode.Perm() {
		return true, fmt.Sprintf("mode is %v, declared %v", perm, w.Mode.Perm())
	}
	if w.Restricted && perm&0o077 != 0 {
		return true, fmt.Sprintf("mode %v grants group/other access to a restricted credential", perm)
	}
	return false, ""
}
