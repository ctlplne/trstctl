// SPDX-License-Identifier: BUSL-1.1

package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"trstctl.com/trstctl/internal/netsec"
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
	clean := filepath.Clean(p)
	for _, fr := range s.fs[cap] {
		if !pathPrefixAllows(fr.prefix, clean) {
			continue
		}
		if fr.err != nil {
			return nil, "", fr.err
		}
		rel, err := filepath.Rel(filepath.Clean(fr.prefix), clean)
		if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if rel == "." {
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

// dial performs a granted outbound connection.
//
// The grant's authority constraints are a positive allowlist of NAMES, and that
// is not the same thing as an allowlist of destinations. Allows() matches the
// string the plugin passed; DialContext then resolves that name at connect time.
// A plugin author who controls the DNS for a granted hostname simply points it at
// 169.254.169.254 and the grant that reads "may reach my vendor API" delivers the
// cloud metadata service. No rebinding race is even needed — one A record does
// it. The comment here used to claim this was stronger than an SSRF check for
// being a positive list, which had it backwards.
//
// pluginDialControl closes that: it runs after resolution and immediately before
// connect, on the actual IP the socket will use, for every attempt. Both checks
// apply — the grant decides which names a plugin may name, and this decides which
// addresses those names are allowed to resolve to.
//
// It refuses the reserved ranges no legitimate grant targets — cloud metadata at
// 169.254.169.254 above all, plus link-local, CGNAT, multicast and unspecified —
// while still permitting loopback and RFC1918/ULA. That asymmetry is deliberate:
// granting a plugin 10.0.0.5:8200 to reach an internal Vault is an explicit
// operator decision this must not override, whereas nothing an operator writes in
// a grant is a decision to hand a third-party plugin the instance credentials.
func (s *sandbox) dial(ctx context.Context, addr string) uint32 {
	if !s.grant.Allows(CapNetDial, addr) {
		return s.refuse(errDenied)
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return s.refuse(fmt.Errorf("pluginhost: dial %q: address must be host:port: %w", addr, err))
	}
	d := net.Dialer{Timeout: dialTimeout, Control: pluginDialControl}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return s.refuse(err)
	}
	_ = conn.Close()
	atomic.AddInt64(&s.stats.dials, 1)
	return statusOK
}

// errDialAddressBlocked is returned for a resolved address a plugin may not reach
// regardless of what its grant names.
var errDialAddressBlocked = errors.New("pluginhost: refusing to connect to a reserved address")

// pluginDialControl validates the resolved address of a granted dial.
//
// This deliberately reimplements the small predicate rather than calling
// internal/netsec, which owns the same logic. internal/connector must stay
// host-neutral — crypto boundary, pluginhost and stdlib only, enforced by
// TestConnectorCoreStaysHostNeutral — and connector reaches pluginhost, so an
// import of netsec here drags host networking policy into the agent's portable
// core. Fifteen lines of net.IP predicates is the cheaper price.
// TestPluginDialControlAgreesWithNetsec pins the two against each other so they
// cannot drift.
//
// Loopback and RFC1918/ULA are permitted: granting a plugin 10.0.0.5:8200 to
// reach an internal Vault is an explicit operator decision this must not
// override. The reserved ranges below are refused unconditionally, because
// nothing an operator writes in a grant is a decision to hand third-party code
// the instance credentials.
func pluginDialControl(_ string, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", errDialAddressBlocked, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: %q is not an IP address", errDialAddressBlocked, host)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	// One reserved-address predicate for the whole codebase (J3/V25):
	// link-local incl. cloud metadata, unspecified, multicast, CGNAT, and
	// EC2's IPv6 metadata address, exactly as the netsec SSRF guard blocks.
	if netsec.HardBlockedIP(ip) {
		return fmt.Errorf("%w: %s", errDialAddressBlocked, host)
	}
	return nil
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
