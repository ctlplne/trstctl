//go:build !unix && !windows

package drift

import "os"

// permissionDetectionSupported is false on platforms that are neither POSIX nor
// Windows: there is no mechanism here to read access controls, so permission
// drift cannot be detected. SupportsPermissionDetection surfaces this so an
// operator is not lulled into assuming coverage.
const permissionDetectionSupported = false

// permissionDrifted is a no-op where access-control detection is unsupported.
func permissionDrifted(_ string, _ os.FileInfo, _ Watched) (bool, string) {
	return false, ""
}
