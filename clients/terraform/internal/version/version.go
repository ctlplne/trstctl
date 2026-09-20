// SPDX-License-Identifier: MPL-2.0

// Package version exposes the provider's build version, injected at release
// time with
//
//	-ldflags "-X trstctl.com/terraform-provider/internal/version.version=..."
//
// and empty for a plain `go build`.
package version

var version string

// Version returns the release version of the build, or "" for a dev build.
func Version() string { return version }
