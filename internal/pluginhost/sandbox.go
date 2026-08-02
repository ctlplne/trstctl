// SPDX-License-Identifier: MPL-2.0

package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"time"
)

// Status codes returned to the guest by every capability function. They are part
// of the plugin ABI: a guest branches on them, so they must not be renumbered.
const (
	statusOK uint32 = 0
	// denyCode is returned when the plugin's grant does not permit the operation
	// on that resource. It is deliberately distinct from statusError so a guest can
	// tell "you may not" from "it went wrong".
	denyCode  uint32 = 1
	statusErr uint32 = 2
)

// Bounds on guest-supplied sizes. A guest controls these numbers, so every one of
// them is capped before it becomes an allocation or a read.
const (
	maxPathBytes  = 4096
	maxWriteBytes = 1 << 20
	maxReadBytes  = 1 << 20
	dialTimeout   = 5 * time.Second
)

// errDenied marks a grant refusal, as opposed to an operational failure.
var errDenied = errors.New("pluginhost: denied by capability grant")

// errBadGuestPointer marks a guest-supplied pointer/length pair that is out of
// bounds or exceeds the ABI's size caps. It is an error, not a denial: the grant
// had nothing to say about it.
var errBadGuestPointer = errors.New("pluginhost: guest pointer out of bounds")

// fsRoot is one granted path prefix and the directory handle the sandbox performs
// all I/O through.
//
// The handle is the whole point. Grant.Allows is a purely lexical predicate, so a
// symlink INSIDE a granted prefix that points outside it satisfies it — that was a
// real escape from the capability model. os.Root resolves every path component
// against the open directory (openat with the escape check), so a symlink or ".."
// that leaves the root is refused by the kernel-facing layer no matter what the
// lexical check concluded. It is also TOCTOU-safe in a way a stat-then-open check
// is not: the containment travels with the handle rather than with a path string.
type fsRoot struct {
	prefix string
	root   *os.Root
	err    error // why this prefix is unusable; returned when an operation needs it
}

// sandbox is the enforcing half of the capability model: one per loaded plugin,
// holding that plugin's grant, its open directory handles, and its counters.
type sandbox struct {
	grant Grant
	stats *Stats
	fs    map[Capability][]*fsRoot
}

// newSandbox opens a directory handle for every path prefix the grant constrains.
//
// A prefix that cannot be opened does NOT fail the load: the plugin may never
// touch that prefix, and refusing to load an otherwise-fine plugin because one
// configured directory is missing is a worse failure mode than refusing the
// operation. The error is kept and returned from the host function that needs it,
// so the refusal is loud at the point of use instead of silent.
func newSandbox(grant Grant, stats *Stats) *sandbox {
	s := &sandbox{grant: grant, stats: stats, fs: map[Capability][]*fsRoot{}}
	for _, cap := range []Capability{CapFSRead, CapFSWrite} {
		if !grant.Has(cap) {
			continue
		}
		for _, prefix := range grant.PathPrefixes(cap) {
			fr := &fsRoot{prefix: prefix}
			root, err := os.OpenRoot(prefix)
			if err != nil {
				fr.err = fmt.Errorf("pluginhost: open grant root %q for %s: %w", prefix, cap, err)
			} else {
				fr.root = root
			}
			s.fs[cap] = append(s.fs[cap], fr)
		}
	}
	return s
}

// close releases every open directory handle.
func (s *sandbox) close() {
	for _, roots := range s.fs {
		for _, fr := range roots {
			if fr.root != nil {
				_ = fr.root.Close()
			}
		}
	}
}

// resolve turns a guest-supplied absolute path into a directory handle and a path
// relative to it, after the grant permits the operation.
//
// Both halves are required. Grant.Allows decides policy ("is this path inside a
// prefix you were granted?"); the returned root enforces it against the actual
// filesystem, which is what stops a symlink inside the prefix from reaching out.
func (s *sandbox) resolve(cap Capability, p string) (*os.Root, string, error) {
	if !s.grant.Allows(cap, p) {
		return nil, "", errDenied
	}
	if len(s.grant.PathPrefixes(cap)) == 0 {
		// An unconstrained filesystem grant would mean "anywhere", which leaves the
		// sandbox no root to contain the operation under and therefore no way to
		// apply the symlink discipline. Unbounded filesystem access for third-party
		// guest code is not something a capability sandbox should offer, so this
		// fails closed and says why.
		return nil, "", fmt.Errorf("pluginhost: %s is granted without a path prefix; "+
			"the WASM sandbox requires a prefix to contain the operation under (see WithPathPrefix)", cap)
	}
	clean := path.Clean(p)
	for _, fr := range s.fs[cap] {
		if !pathPrefixAllows(fr.prefix, clean) {
			continue
		}
		if fr.err != nil {
			return nil, "", fr.err
		}
		pc := path.Clean(fr.prefix)
		var rel string
		if pc == "/" {
			rel = strings.TrimPrefix(clean, "/")
		} else {
			rel = strings.TrimPrefix(strings.TrimPrefix(clean, pc), "/")
		}
		if rel == "" {
			return nil, "", fmt.Errorf("pluginhost: %q is the grant root itself, not a file within it", p)
		}
		return fr.root, rel, nil
	}
	return nil, "", errDenied
}

// writeFile performs a granted write. It returns an ABI status code and records
// the outcome in the plugin's counters.
func (s *sandbox) writeFile(p string, data []byte) uint32 {
	root, rel, err := s.resolve(CapFSWrite, p)
	if err != nil {
		return s.refuse(err)
	}
	// os.Root resolves rel against the open directory and refuses any component
	// that leaves it, so a symlink pointing outside the grant fails here. A symlink
	// that stays INSIDE the grant is followed, which is correct: the grant covers
	// the whole subtree, so reaching another file in it is within policy.
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return s.refuse(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(data); err != nil {
		return s.refuse(err)
	}
	atomic.AddInt64(&s.stats.writes, 1)
	return statusOK
}

// readFile performs a granted read, returning at most limit bytes.
func (s *sandbox) readFile(p string, limit int) ([]byte, uint32) {
	root, rel, err := s.resolve(CapFSRead, p)
	if err != nil {
		return nil, s.refuse(err)
	}
	f, err := root.OpenFile(rel, os.O_RDONLY, 0)
	if err != nil {
		return nil, s.refuse(err)
	}
	defer func() { _ = f.Close() }()
	if limit <= 0 || limit > maxReadBytes {
		limit = maxReadBytes
	}
	buf := make([]byte, limit)
	// ReadFull rather than Read: a short Read is not an error, and distinguishing
	// "the file is smaller than the buffer" (EOF / ErrUnexpectedEOF, both fine)
	// from a real I/O failure is exactly what it does.
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, s.refuse(err)
	}
	atomic.AddInt64(&s.stats.reads, 1)
	return buf[:n], statusOK
}

// dial performs a granted outbound connection. The grant's authority constraints
// ARE the allowlist here: the plugin may reach exactly the hosts it was granted
// and nothing else, which is a stronger guarantee than an SSRF heuristic because
// it is a positive list rather than a set of refused destinations.
func (s *sandbox) dial(ctx context.Context, addr string) uint32 {
	if !s.grant.Allows(CapNetDial, addr) {
		return s.refuse(errDenied)
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return s.refuse(fmt.Errorf("pluginhost: dial %q: address must be host:port: %w", addr, err))
	}
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return s.refuse(err)
	}
	_ = conn.Close()
	atomic.AddInt64(&s.stats.dials, 1)
	return statusOK
}

// refuse records a refusal and maps it to the ABI status the guest sees. A grant
// refusal counts as a denial; anything else is an operational error, and neither
// is reported to the guest in more detail than a status code — an error string
// would leak host filesystem structure into guest memory.
func (s *sandbox) refuse(err error) uint32 {
	atomic.AddInt64(&s.stats.denied, 1)
	if errors.Is(err, errDenied) {
		return denyCode
	}
	return statusErr
}
