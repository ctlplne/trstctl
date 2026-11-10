// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package workloadapi

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// peerCredentialsFD reads SO_PEERCRED, which carries pid, uid and gid together,
// and the connecting executable through the connecting process's own pidfd.
func peerCredentialsFD(fd uintptr) (PeerIdentity, error) {
	cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("workloadapi: read peer credentials: %w", err)
	}
	id := PeerIdentity{PID: int(cred.Pid), UID: int(cred.Uid), GID: int(cred.Gid)}
	id.Path = linuxExecutablePath(fd, id.PID)
	return id, nil
}

// linuxExecutablePath is the connecting process's executable, or "" when that
// cannot be known exactly (A203-L3).
//
// SO_PEERCRED's pid is a number, and /proc/<pid>/exe names whichever process
// holds that number when it is read. A process that connects, hands its socket
// on and exits frees its pid; if another binary is given that pid before the
// read, the reused pid's binary would be attested as the caller. SO_PEERPIDFD
// (Linux 6.5) is a pidfd for the connecting process itself, so the path is kept
// only when that process still holds the pid after the read: a process that is
// alive after the read was alive during it, and a live process keeps its pid.
// A kernel without SO_PEERPIDFD, or a caller that has exited, yields no path
// selector — never a guess.
func linuxExecutablePath(fd uintptr, pid int) string {
	if pid <= 0 {
		return ""
	}
	pidfd, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	if err != nil || pidfd < 0 {
		return ""
	}
	defer func() { _ = unix.Close(pidfd) }()
	if pidfdPID(pidfd) != pid {
		return ""
	}
	resolved, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return ""
	}
	if unix.PidfdSendSignal(pidfd, 0, nil, 0) != nil || pidfdPID(pidfd) != pid {
		return ""
	}
	return resolved
}

// pidfdPID is the pid a pidfd names in this process's pid namespace, read from
// /proc/self/fdinfo; -1 once that process has exited, 0 when it is outside the
// namespace, and -1 when the fdinfo cannot be read.
func pidfdPID(pidfd int) int {
	raw, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", strconv.Itoa(pidfd)))
	if err != nil {
		return -1
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Bytes()
		if value, ok := bytes.CutPrefix(line, []byte("Pid:")); ok {
			pid, err := strconv.Atoi(string(bytes.TrimSpace(value)))
			if err != nil {
				return -1
			}
			return pid
		}
	}
	return -1
}
