// SPDX-License-Identifier: BUSL-1.1

package signing_test

// Intentionally empty. The real OS-level fault injection for OPS-CHAOS-REAL-001
// lives in chaos_real_test.go (SIGKILL + RLIMIT_AS + control). This placeholder
// remains only because the sandbox filesystem is unlink-restricted; it compiles
// to nothing and adds no tests.
