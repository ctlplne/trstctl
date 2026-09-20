// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package signing

import "golang.org/x/sys/unix"

// Harden applies process-level memory protections for the signer: it disables
// core dumps (RLIMIT_CORE=0) and denies ptrace and /proc/<pid>/mem access from
// non-root peers (PR_SET_DUMPABLE=0). Combined with the secret package's
// per-buffer mlock + MADV_DONTDUMP, this closes the main key-disclosure vectors
// (AN-8). It is called once at signer startup.
func Harden() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	return nil
}
