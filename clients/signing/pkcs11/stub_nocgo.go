// SPDX-License-Identifier: MPL-2.0

//go:build !cgo

// libtrstctl-pkcs11 needs cgo: build it with CGO_ENABLED=1 and
// -buildmode=c-shared. Without cgo this package is an empty program.
package main

func main() {}
