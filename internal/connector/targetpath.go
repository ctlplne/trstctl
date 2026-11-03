// SPDX-License-Identifier: BUSL-1.1

package connector

import (
	"path"
	"strings"
)

// TargetDir is path.Dir for a target file's path on the host the connector
// serves. Connectors are host-neutral (they also run as WebAssembly), so they
// cannot ask path/filepath which host that is: a Windows drive path (C:\...
// or C:/...) is cut at its last separator of either kind, keeping the drive
// root, and any other path is a POSIX path. Their file grants name this
// directory, which the agent's local boundary then resolves with its own
// operating system's rules (owner decision 2026-11-02, item 2g a).
func TargetDir(p string) string {
	if !windowsDrivePath(p) {
		return path.Dir(p)
	}
	cut := strings.LastIndexAny(p, `\/`)
	if dir := strings.TrimRight(p[:cut], `\/`); len(dir) > 2 {
		return dir
	}
	return p[:3]
}

func windowsDrivePath(p string) bool {
	if len(p) < 3 || p[1] != ':' || (p[2] != '\\' && p[2] != '/') {
		return false
	}
	letter := p[0] | 0x20
	return letter >= 'a' && letter <= 'z'
}
