// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package workloadapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// peerCredentialsFD reads the peer's credentials on darwin.
//
// LOCAL_PEERCRED gives uid and the group set. The pid comes from the peer's
// audit token (LOCAL_PEERTOKEN), which also carries the pid VERSION: darwin
// gives every process a pid version alongside its pid, so a pid that is reused
// by a later process does not keep the version. The path selector is resolved
// for the pid only while that version still matches, checked before and after
// the path is read, so the path is the connecting process's own and never that
// of a process that took over its pid. LOCAL_PEERPID must agree with the token.
// When any of that fails the path is left empty and only uid and gid selectors
// are offered: an entry requiring unix:path then does not match, which is the
// refusal, never a guessed path.
func peerCredentialsFD(fd uintptr) (PeerIdentity, error) {
	cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("workloadapi: read peer credentials: %w", err)
	}
	id := PeerIdentity{UID: int(cred.Uid)}
	if len(cred.Groups) > 0 {
		id.GID = int(cred.Groups[0])
	}
	token, err := peerAuditToken(fd)
	if err != nil {
		return id, nil
	}
	pid, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil || pid <= 0 || pid > math.MaxInt32 || uint32(pid) != token.pid() {
		return id, nil
	}
	id.PID = pid
	id.Path = darwinExecutablePath(token)
	return id, nil
}

// auditToken is darwin's audit_token_t: auid, euid, egid, ruid, rgid, pid,
// asid and pid version, in that order.
type auditToken [8]uint32

func (t auditToken) pid() uint32        { return t[5] }
func (t auditToken) pidVersion() uint32 { return t[7] }

// peerAuditToken reads LOCAL_PEERTOKEN, the connecting process's audit token
// as the kernel recorded it at connect time.
func peerAuditToken(fd uintptr) (auditToken, error) {
	var token auditToken
	size := uint32(unsafe.Sizeof(token))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(unix.SOL_LOCAL), uintptr(unix.LOCAL_PEERTOKEN),
		uintptr(unsafe.Pointer(&token)), uintptr(unsafe.Pointer(&size)), 0) // #nosec G103 -- getsockopt fills a fixed-size audit token (CWE-242)
	if errno != 0 {
		return auditToken{}, errno
	}
	if size != uint32(unsafe.Sizeof(token)) {
		return auditToken{}, fmt.Errorf("workloadapi: peer audit token is %d bytes", size)
	}
	return token, nil
}

// proc_info call and flavors (sys/proc_info.h).
const (
	procInfoCallPIDInfo         = 2
	procPIDPathInfo             = 11
	procPIDUniqIdentifierInfo   = 17
	procPIDPathInfoMaxSize      = 4096
	procUniqIdentifierInfoSize  = 56
	procUniqIdentifierVersionAt = 32
)

// darwinExecutablePath is the executable of the process the token names, or
// empty when the pid now belongs to a different process or cannot be read.
func darwinExecutablePath(token auditToken) string {
	pid := token.pid()
	if pid == 0 || pid > math.MaxInt32 || !samePIDVersion(pid, token.pidVersion()) {
		return ""
	}
	buf := make([]byte, procPIDPathInfoMaxSize)
	if _, err := procInfo(pid, procPIDPathInfo, buf); err != nil {
		return ""
	}
	path := buf
	if end := bytes.IndexByte(buf, 0); end >= 0 {
		path = buf[:end]
	}
	if len(path) == 0 || path[0] != '/' || !samePIDVersion(pid, token.pidVersion()) {
		return ""
	}
	return string(path)
}

// samePIDVersion reports whether pid still belongs to the process with this
// pid version (proc_uniqidentifierinfo.p_idversion).
func samePIDVersion(pid, version uint32) bool {
	buf := make([]byte, procUniqIdentifierInfoSize)
	n, err := procInfo(pid, procPIDUniqIdentifierInfo, buf)
	if err != nil || n < procUniqIdentifierVersionAt+4 {
		return false
	}
	return binary.LittleEndian.Uint32(buf[procUniqIdentifierVersionAt:]) == version
}

// procInfo calls proc_info(PROC_INFO_CALL_PIDINFO, pid, flavor, 0, buf, len).
// Path and identifier information is readable for any process.
func procInfo(pid uint32, flavor uintptr, buf []byte) (int, error) {
	n, _, errno := syscall.Syscall6(syscall.SYS_PROC_INFO, procInfoCallPIDInfo, uintptr(pid), flavor, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))) // #nosec G103 -- proc_info fills the caller's buffer (CWE-242)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}
