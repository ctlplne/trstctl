// SPDX-License-Identifier: BUSL-1.1

//go:build linux && amd64

package sessionobserve

import _ "embed"

// programObject is bpf/sessionobserve.bpf.c compiled for x86-64
// (scripts/gen-sessionobserve-bpf.sh).
//
//go:embed bpf/sessionobserve_x86_bpfel.o
var programObject []byte
