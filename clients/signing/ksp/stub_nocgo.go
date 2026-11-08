// SPDX-License-Identifier: MPL-2.0

//go:build !cgo

// trstctl-ksp needs cgo: build it with CGO_ENABLED=1 and -buildmode=c-shared
// (for Windows, with a MinGW-w64 compiler). Without cgo this package is an
// empty program.
package main

func main() {}
