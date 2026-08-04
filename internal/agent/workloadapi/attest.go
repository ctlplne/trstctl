// SPDX-License-Identifier: MPL-2.0

// Package workloadapi serves the SPIFFE Workload API on the host that runs the
// workloads (epic B3).
//
// Before this the Workload API lived on the control plane. That has two
// consequences an operator feels immediately and a third they feel later:
//
//  1. It can only serve workloads on the control plane's own machine, which in
//     any real deployment is none of them.
//  2. It mints SVID private keys server-side and returns them over the wire, so
//     every workload's identity key exists on a machine the workload does not
//     run on.
//  3. It cannot attest anything. "Which process is asking" is a question only
//     answerable on the machine the process runs on.
//
// Moving it here fixes all three at once, and the third is what makes the first
// two worth doing: a socket on the workload's own host can ask the kernel who
// connected to it.
package workloadapi

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// PeerIdentity is what the kernel says about the process on the other end of a
// UDS connection.
//
// It is the only trustworthy input to attestation. Everything a workload could
// tell us about itself is a claim; this is an observation the kernel made, and
// the workload cannot influence it without already being the process it claims
// to be.
type PeerIdentity struct {
	PID int
	UID int
	GID int
	// Path is the executable behind PID, when the platform can resolve it.
	// Empty is normal and honest — a process can exit between connecting and
	// being looked up, and on some platforms the mapping is unavailable
	// entirely. An empty path yields no path selector rather than a guessed one.
	Path string
}

// ErrAttestationUnsupported is returned on platforms where the kernel does not
// expose peer credentials over a UDS.
//
// A distinct error because the right response is to refuse to serve, not to
// serve with weaker attestation. A Workload API that cannot tell callers apart
// hands any local process every identity it can reach, which is worse than
// having no Workload API on that host at all.
var ErrAttestationUnsupported = errors.New("workloadapi: this platform does not expose UDS peer credentials")

// Selectors renders a peer identity as the selector strings a registration entry
// matches against.
//
// The vocabulary is SPIRE's, deliberately: an operator who knows how to write a
// SPIRE registration entry should not have to learn a second syntax to write one
// here, and a shop migrating from SPIRE should be able to bring their entries.
//
// Sorted, because selectors are compared as a set and an unstable order would
// make otherwise-identical requests look different in the audit log.
func (p PeerIdentity) Selectors() []string {
	out := []string{
		"unix",
		"unix:uid:" + strconv.Itoa(p.UID),
		"unix:gid:" + strconv.Itoa(p.GID),
	}
	if p.Path != "" {
		out = append(out, "unix:path:"+p.Path)
	}
	sort.Strings(out)
	return out
}

// AttestPeer reports the identity of the process on the other end of conn.
func AttestPeer(conn net.Conn) (PeerIdentity, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		// Only a UDS peer is host-local, and only a host-local peer can be
		// attested. Refusing a TCP caller here is the reason the socket is a
		// UDS in the first place.
		return PeerIdentity{}, errors.New("workloadapi: workload connections must arrive over a unix socket")
	}
	id, err := peerCredentials(unixConn)
	if err != nil {
		return PeerIdentity{}, err
	}
	id.Path = executablePath(id.PID)
	return id, nil
}

// executablePath best-effort resolves the binary behind a pid.
//
// Best-effort on purpose, and the failure is silent by design: a process that
// exited between connecting and being looked up is an ordinary race, not an
// error, and an empty path simply yields one fewer selector. What it must never
// do is guess — a wrong path selector would match an entry the caller is not
// entitled to.
func executablePath(pid int) string {
	if pid <= 0 {
		return ""
	}
	// Linux exposes it directly. Other platforms fall through to empty, which
	// costs a selector rather than correctness.
	if resolved, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe")); err == nil {
		return resolved
	}
	return ""
}

// SocketPath is the default per-host Workload API socket.
//
// A path under the agent's own runtime directory, not /tmp: a socket in a
// world-writable directory can be replaced by any local user, and a workload
// that dials a replaced socket hands its identity request to whoever placed it.
func SocketPath(runtimeDir string) string {
	if runtimeDir == "" {
		runtimeDir = "/var/run/trstctl"
	}
	return filepath.Join(runtimeDir, "workload.sock")
}

// PrepareSocket removes a stale socket and creates its directory with an
// owner-only mode.
//
// The directory mode is the actual access control on this socket. A Workload API
// endpoint is an identity oracle for every workload on the host, so the fact
// that it is 0700 and owned by the agent's user is not hygiene — it is the
// boundary that keeps an unprivileged local process from asking it questions.
func PrepareSocket(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("workloadapi: create socket directory: %w", err)
	}
	// #nosec G302 -- a DIRECTORY, not a file. 0700 is the tightest mode that
	// still works: the execute bit is what lets the agent traverse into its own
	// runtime directory, and 0600 would make the socket unreachable by the
	// process that created it. Owner-only is the access control on this
	// endpoint (CWE-276).
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("workloadapi: restrict socket directory: %w", err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("workloadapi: remove stale socket: %w", err)
	}
	return nil
}
