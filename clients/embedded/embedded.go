// SPDX-License-Identifier: MPL-2.0

// Package embedded documents and tests the lightweight POSIX EST enrollment client for
// constrained devices (S8.6). The client itself is C (est_client.c) so it runs on devices
// without a Go runtime or heavy TLS stack; it depends only on libc and the openssl CLI.
// This package carries no Go runtime code — est_client_test.go compiles the C client with
// cc and drives it against the EST server to prove an end-to-end enrollment.
package embedded
