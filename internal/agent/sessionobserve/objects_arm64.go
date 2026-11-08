// SPDX-License-Identifier: BUSL-1.1

//go:build linux && arm64

package sessionobserve

import _ "embed"

// programObject is bpf/sessionobserve.bpf.c compiled for arm64
// (scripts/gen-sessionobserve-bpf.sh).
//
//go:embed bpf/sessionobserve_arm64_bpfel.o
var programObject []byte
