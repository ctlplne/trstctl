// SPDX-License-Identifier: BUSL-1.1

// Package localexec decides whether an operator-pinned local command may run
// directly, for the connector's local actions and the native TLS probe: an
// absolute local path to a regular program file that is not a symbolic link.
// It sits inside the crypto boundary, like secretfile, so tlsprobe there can
// share it with the connector (AN-3).
package localexec

import (
	"io/fs"
	"runtime"
	"strings"
)

// IsAbsolute reports whether path is an absolute local path. On Windows only
// a drive-letter path (C:\...) counts: UNC and device paths
// (\\server\share\..., \\?\..., \\.\...), which filepath.IsAbs also accepts,
// are refused, since a binary on a network share is not a local action.
func IsAbsolute(path string) bool { return isAbsolute(runtime.GOOS, path) }

// IsProgram reports whether info, from os.Lstat(path), is a program the agent
// may run directly: a regular file, not a symbolic link, with an execute bit
// on Unix, or on Windows (which reports no execute bits) a .exe. Never .bat,
// .cmd, .ps1 or .com: cmd.exe's argument quoting or a script host makes those
// injection paths.
func IsProgram(path string, info fs.FileInfo) bool { return isProgram(runtime.GOOS, path, info) }

func isAbsolute(goos, path string) bool {
	if goos != "windows" {
		// filepath.IsAbs on Unix, spelled out so the rule reads the same on
		// every host that evaluates it.
		return strings.HasPrefix(path, "/")
	}
	if len(path) < 3 || path[1] != ':' || (path[2] != '\\' && path[2] != '/') {
		return false
	}
	letter := path[0] | 0x20
	return letter >= 'a' && letter <= 'z'
}

func isProgram(goos, path string, info fs.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 {
		return false
	}
	if goos == "windows" {
		name := path[strings.LastIndexAny(path, `\/`)+1:]
		dot := strings.LastIndexByte(name, '.')
		return dot > 0 && strings.EqualFold(name[dot:], ".exe")
	}
	return info.Mode()&0o111 != 0
}
