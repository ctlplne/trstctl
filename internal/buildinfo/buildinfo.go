// Package buildinfo exposes build and version metadata shared by every certctl
// binary (certctl, certctl-signer, certctl-agent).
//
// The unexported variables below are populated at link time via
//
//	-ldflags "-X certctl.io/certctl/internal/buildinfo.version=..."
//
// (see the Makefile). When a binary is built without those flags — for example
// under "go run" or "go test" — the accessors fall back to the VCS metadata the
// Go toolchain embeds in the binary's build info, and finally to stable
// "dev"/"none"/"unknown" sentinels. The accessors therefore never return an
// empty string, which the --version flag relies on.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Linker-injected build metadata. Read these through the accessors below, which
// apply fallbacks; do not read the variables directly.
var (
	version string
	commit  string
	date    string
)

// Version returns the release or `git describe` version of the build.
func Version() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

// Commit returns the VCS revision the build was produced from, truncated to a
// short hash when sourced from embedded build info.
func Commit() string {
	if commit != "" {
		return commit
	}
	if rev := vcsSetting("vcs.revision"); rev != "" {
		if len(rev) > 12 {
			return rev[:12]
		}
		return rev
	}
	return "none"
}

// Date returns the build/commit timestamp (RFC 3339) when known.
func Date() string {
	if date != "" {
		return date
	}
	if t := vcsSetting("vcs.time"); t != "" {
		return t
	}
	return "unknown"
}

// String returns a single-line, human-readable version banner for the named
// binary, including the platform and Go toolchain to aid support diagnostics.
func String(name string) string {
	return fmt.Sprintf("%s %s (commit %s, built %s, %s/%s, %s)",
		name, Version(), Commit(), Date(), runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// vcsSetting returns the value of a build-info VCS setting, or "" if absent.
func vcsSetting(key string) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}
