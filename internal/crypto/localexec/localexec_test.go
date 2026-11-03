// SPDX-License-Identifier: BUSL-1.1

package localexec

import (
	"io/fs"
	"testing"
	"time"
)

type fileInfo struct{ mode fs.FileMode }

func (f fileInfo) Name() string       { return "" }
func (f fileInfo) Size() int64        { return 0 }
func (f fileInfo) Mode() fs.FileMode  { return f.mode }
func (f fileInfo) ModTime() time.Time { return time.Time{} }
func (f fileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fileInfo) Sys() any           { return nil }

// Owner decision 2026-11-02 (item 2g a, b): on Windows only a drive-letter
// path is a local absolute command; UNC and device paths are refused.
func TestWindowsAcceptsOnlyDriveLetterPaths(t *testing.T) {
	for path, want := range map[string]bool{
		`C:\Windows\System32\inetsrv\appcmd.exe`: true,
		`d:/tools/openssl.exe`:                   true,
		`\\server\share\deploy.exe`:              false,
		`\\?\C:\tools\deploy.exe`:                false,
		`\\.\pipe\deploy`:                        false,
		`//server/share/deploy.exe`:              false,
		`C:deploy.exe`:                           false,
		`tools\deploy.exe`:                       false,
		`/usr/bin/true`:                          false,
		`1:\deploy.exe`:                          false,
	} {
		if got := isAbsolute("windows", path); got != want {
			t.Errorf("windows %q = %v, want %v", path, got, want)
		}
	}
	if !isAbsolute("linux", "/usr/sbin/nginx") || isAbsolute("linux", "usr/sbin/nginx") {
		t.Fatal("the Unix rule is filepath.IsAbs")
	}
}

// Owner decision 2026-11-02 (item 2g a): Windows reports no execute bits, so a
// program there is a regular .exe; scripts cmd.exe or a script host would run
// are never programs, and neither is a symbolic link or a directory anywhere.
func TestProgramIsARegularExeOnWindowsAndAnExecutableFileElsewhere(t *testing.T) {
	regular, executable := fileInfo{mode: 0o644}, fileInfo{mode: 0o755}
	for _, tc := range []struct {
		goos, path string
		info       fs.FileInfo
		want       bool
	}{
		{"windows", `C:\tools\openssl.exe`, regular, true},
		{"windows", `C:\tools\OPENSSL.EXE`, regular, true},
		{"windows", `C:\tools\deploy.bat`, regular, false},
		{"windows", `C:\tools\deploy.cmd`, regular, false},
		{"windows", `C:\tools\deploy.ps1`, regular, false},
		{"windows", `C:\tools\deploy.com`, regular, false},
		{"windows", `C:\tools\deploy`, executable, false},
		{"windows", `C:\tools.exe\deploy`, regular, false},
		{"windows", `C:\tools\.exe`, regular, false},
		{"windows", `C:\tools\link.exe`, fileInfo{mode: fs.ModeSymlink | 0o755}, false},
		{"windows", `C:\tools\dir.exe`, fileInfo{mode: fs.ModeDir | 0o755}, false},
		{"linux", "/usr/sbin/nginx", executable, true},
		{"linux", "/usr/sbin/nginx", regular, false},
		{"linux", "/usr/sbin/nginx.exe", regular, false},
		{"darwin", "/opt/homebrew/bin/openssl", fileInfo{mode: fs.ModeSymlink | 0o755}, false},
		{"linux", "/usr/sbin/nginx", nil, false},
	} {
		if got := isProgram(tc.goos, tc.path, tc.info); got != tc.want {
			t.Errorf("%s %q (%v) = %v, want %v", tc.goos, tc.path, tc.info, got, tc.want)
		}
	}
}
