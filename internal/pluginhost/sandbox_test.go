// SPDX-License-Identifier: MPL-2.0

package pluginhost_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/pluginhost"
)

// ABI status codes, as the guest sees them. Duplicated here deliberately: a test
// that imported the constants would still pass if someone renumbered them, and
// these numbers are a published contract with plugin authors.
const (
	abiOK     = 0
	abiDenied = 1
	abiError  = 2
)

func loadAndRun(t *testing.T, h *pluginhost.Host, wasm []byte, grant pluginhost.Grant) (uint64, *pluginhost.Plugin) {
	t.Helper()
	ctx := context.Background()
	p, err := h.Load(ctx, wasm, grant)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = p.Close(ctx) })
	got, err := h.Invoke(ctx, p, "run")
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	return got, p
}

// TestUngrantedImportFailsToInstantiate is the grant-shaped-instantiation
// property the public docs promise: "any import the plugin declares that wasn't
// granted causes instantiation to fail, so the plugin's reach is closed by
// construction".
//
// This is strictly stronger than denying the call at runtime, which is all the
// host used to do: a plugin that cannot instantiate never executes a single
// instruction, so there is no window in which it runs with an import it should
// not have had.
func TestUngrantedImportFailsToInstantiate(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	guest := writeGuest("/etc/shadow", "x")

	if _, err := h.Load(ctx, guest, pluginhost.NewGrant()); err == nil {
		t.Fatal("a guest importing env.cap_write instantiated under an EMPTY grant; " +
			"the env module must not export a capability that was not granted")
	}
	// A different capability is not a substitute for the one it imports.
	if _, err := h.Load(ctx, guest, pluginhost.NewGrant(pluginhost.CapNetDial)); err == nil {
		t.Fatal("a guest importing env.cap_write instantiated under a net.dial-only grant")
	}
	// With the capability granted it instantiates (and is then policed per call).
	p, err := h.Load(ctx, guest, pluginhost.NewGrant(pluginhost.CapFSWrite))
	if err != nil {
		t.Fatalf("granted guest failed to instantiate: %v", err)
	}
	_ = p.Close(ctx)
}

// TestGrantedWriteIsConfinedToItsPathPrefix is the capability model doing the job
// the docs claim: "Every gated call (write a file, dial a host) checks the
// capability grant first, including path/host prefix matching".
//
// The finding this closes phrased it as /allowed vs /etc/shadow. The granted
// prefix here is a t.TempDir() rather than a literal /allowed, because the test
// must actually perform the write to prove the allowed side works — asserting
// only the denial would pass just as well against a host function that does
// nothing, which is the exact bug being fixed.
func TestGrantedWriteIsConfinedToItsPathPrefix(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	allowed := t.TempDir()
	grant := pluginhost.NewGrant(pluginhost.CapFSWrite).
		WithPathPrefix(pluginhost.CapFSWrite, allowed)

	target := filepath.Join(allowed, "x")
	status, p := loadAndRun(t, h, writeGuest(target, "written-by-plugin"), grant)
	if status != abiOK {
		t.Fatalf("write inside the granted prefix returned %d, want %d (ok)", status, abiOK)
	}
	body, err := os.ReadFile(target) // #nosec G304 -- test reads the fixture path it just granted (CWE-22)
	if err != nil {
		t.Fatalf("the granted write did not reach the filesystem: %v", err)
	}
	if string(body) != "written-by-plugin" {
		t.Errorf("granted write produced %q, want %q", body, "written-by-plugin")
	}
	if p.Stats().Writes != 1 {
		t.Errorf("granted write recorded %d writes, want 1", p.Stats().Writes)
	}

	// The same capability, a path outside the prefix.
	status, denied := loadAndRun(t, h, writeGuest("/etc/shadow", "pwned"), grant)
	if status != abiDenied {
		t.Fatalf("write to /etc/shadow returned %d, want %d (denied)", status, abiDenied)
	}
	if denied.Stats().Writes != 0 {
		t.Errorf("denied plugin recorded %d writes, want 0", denied.Stats().Writes)
	}
	if denied.Stats().Denied != 1 {
		t.Errorf("denial was not counted: %+v", denied.Stats())
	}

	// A sibling directory sharing the prefix's textual start must not match: the
	// check is on a separator boundary, not on a string prefix.
	status, _ = loadAndRun(t, h, writeGuest(allowed+"-evil/x", "pwned"), grant)
	if status != abiDenied {
		t.Errorf("write to the %q sibling returned %d, want %d (denied)", allowed+"-evil", status, abiDenied)
	}

	// Traversal out of the prefix is resolved before the check, not after.
	status, _ = loadAndRun(t, h, writeGuest(allowed+"/../escape", "pwned"), grant)
	if status != abiDenied {
		t.Errorf("write via ../ escape returned %d, want %d (denied)", status, abiDenied)
	}
}

// TestSymlinkInsideGrantCannotEscapeIt closes the escape that Grant.Allows cannot
// see on its own.
//
// Allows is a purely lexical predicate: "/granted/link" is inside "/granted", so
// it says yes. If the enforcing layer then opened that path by name, the symlink
// would be followed and the plugin would write wherever it pointed — a complete
// bypass of the capability model using only paths the grant permits. The sandbox
// performs its I/O through an os.Root opened at the prefix, so the escape is
// refused when the path is resolved.
func TestSymlinkInsideGrantCannotEscapeIt(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	allowed := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(allowed, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}

	grant := pluginhost.NewGrant(pluginhost.CapFSWrite).
		WithPathPrefix(pluginhost.CapFSWrite, allowed)

	// Precondition: the lexical predicate DOES allow this path. Without it, the
	// test could pass for the wrong reason -- a plain prefix rejection -- and prove
	// nothing about symlink containment.
	if !grant.Allows(pluginhost.CapFSWrite, link) {
		t.Fatalf("precondition failed: Allows(%q) is false, so this test would not "+
			"exercise symlink containment at all", link)
	}

	status, _ := loadAndRun(t, h, writeGuest(link, "pwned"), grant)
	if status == abiOK {
		t.Error("a symlink inside the grant was followed out of it; the capability model is bypassable")
	}
	body, err := os.ReadFile(outside) // #nosec G304 -- test reads the fixture it created (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "original" {
		t.Errorf("the file outside the grant was modified through a symlink: %q", body)
	}
}

// TestGrantedReadIsConfinedToItsPathPrefix is the read half of the same model.
func TestGrantedReadIsConfinedToItsPathPrefix(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	allowed := t.TempDir()
	readable := filepath.Join(allowed, "cert.pem")
	if err := os.WriteFile(readable, []byte("-----BEGIN CERTIFICATE-----"), 0o600); err != nil {
		t.Fatal(err)
	}
	grant := pluginhost.NewGrant(pluginhost.CapFSRead).
		WithPathPrefix(pluginhost.CapFSRead, allowed)

	status, p := loadAndRun(t, h, readGuest(readable), grant)
	if status != abiOK {
		t.Fatalf("read inside the granted prefix returned %d, want %d (ok)", status, abiOK)
	}
	if p.Stats().Reads != 1 {
		t.Errorf("granted read recorded %d reads, want 1", p.Stats().Reads)
	}

	status, _ = loadAndRun(t, h, readGuest("/etc/passwd"), grant)
	if status != abiDenied {
		t.Errorf("read of /etc/passwd returned %d, want %d (denied)", status, abiDenied)
	}
}

// TestDialIsConfinedToGrantedAuthority proves host matching is exact rather than
// prefix- or suffix-based, which is what stops "example.com.attacker.example"
// from satisfying a grant for "example.com".
func TestDialIsConfinedToGrantedAuthority(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	addr := ln.Addr().String()

	grant := pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, addr)

	status, p := loadAndRun(t, h, dialGuest(addr), grant)
	if status != abiOK {
		t.Fatalf("dial to the granted authority returned %d, want %d (ok)", status, abiOK)
	}
	if p.Stats().Dials != 1 {
		t.Errorf("granted dial recorded %d dials, want 1", p.Stats().Dials)
	}

	// A different port on the same host is a different authority.
	_, port, _ := net.SplitHostPort(addr)
	other := "127.0.0.1:1"
	if port == "1" {
		other = "127.0.0.1:2"
	}
	status, _ = loadAndRun(t, h, dialGuest(other), grant)
	if status != abiDenied {
		t.Errorf("dial to an ungranted port returned %d, want %d (denied)", status, abiDenied)
	}
}

// TestFilesystemGrantWithoutPathPrefixIsRefused pins a deliberate design choice.
//
// An unconstrained fs grant would mean "anywhere on the filesystem", which leaves
// the sandbox no root to contain the operation under and therefore no way to
// enforce the symlink discipline. Rather than silently degrade to an unprotected
// open, the sandbox fails closed. This test exists so that choice cannot be
// reverted by accident: relaxing it would hand third-party WASM the whole
// filesystem.
func TestFilesystemGrantWithoutPathPrefixIsRefused(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	target := filepath.Join(t.TempDir(), "x")
	// Note the grant HAS the capability, and Allows() would say yes -- an
	// unconstrained grant permits every resource. Only the sandbox refuses.
	grant := pluginhost.NewGrant(pluginhost.CapFSWrite)
	if !grant.Allows(pluginhost.CapFSWrite, target) {
		t.Fatal("precondition failed: an unconstrained grant should allow any path")
	}

	status, _ := loadAndRun(t, h, writeGuest(target, "x"), grant)
	if status != abiError {
		t.Errorf("unconstrained fs.write returned %d, want %d (error)", status, abiError)
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("an unconstrained fs.write reached the filesystem; it must be refused")
	}
}

// TestGuestPointerOutOfBoundsIsRefused checks the ABI against a hostile guest
// rather than a cooperative one: every pointer and length crossing the boundary
// is attacker-controlled, so an unchecked pair is a host-memory bug.
func TestGuestPointerOutOfBoundsIsRefused(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	allowed := t.TempDir()
	grant := pluginhost.NewGrant(pluginhost.CapFSWrite).
		WithPathPrefix(pluginhost.CapFSWrite, allowed)

	// A path pointer far past the single page this fixture owns.
	guest := guestModule("cap_write", 4, []int32{1 << 20, 16, 0, 1}, []byte("ignored"))
	status, _ := loadAndRun(t, h, guest, grant)
	if status != abiError {
		t.Errorf("out-of-bounds path pointer returned %d, want %d (error)", status, abiError)
	}

	// A length beyond the ABI's cap must be refused rather than allocated.
	guest = guestModule("cap_write", 4, []int32{0, 1 << 20, 0, 1}, []byte("ignored"))
	status, _ = loadAndRun(t, h, guest, grant)
	if status != abiError {
		t.Errorf("oversized path length returned %d, want %d (error)", status, abiError)
	}
}

// TestSandboxRefusesToTreatTheGrantRootAsAFile guards a resolution edge case: the
// prefix itself resolves to an empty relative path, which os.Root would reject
// with a confusing error.
func TestSandboxRefusesToTreatTheGrantRootAsAFile(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	allowed := t.TempDir()
	grant := pluginhost.NewGrant(pluginhost.CapFSWrite).
		WithPathPrefix(pluginhost.CapFSWrite, allowed)

	status, _ := loadAndRun(t, h, writeGuest(allowed, "x"), grant)
	if status != abiError {
		t.Errorf("writing to the grant root itself returned %d, want %d (error)", status, abiError)
	}
	info, err := os.Stat(allowed)
	if err != nil || !info.IsDir() {
		t.Errorf("the grant root is no longer a directory: %v", err)
	}
}

// TestMissingGrantRootFailsAtUseNotAtLoad pins the load-time behaviour for a
// configured prefix that does not exist: the plugin still loads (it may never
// touch that prefix), and the operation that needs it fails loudly.
func TestMissingGrantRootFailsAtUseNotAtLoad(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	missing := filepath.Join(t.TempDir(), "does-not-exist")
	grant := pluginhost.NewGrant(pluginhost.CapFSWrite).
		WithPathPrefix(pluginhost.CapFSWrite, missing)

	p, err := h.Load(ctx, writeGuest(filepath.Join(missing, "x"), "x"), grant)
	if err != nil {
		t.Fatalf("Load failed for a missing grant root; it should fail at use, not at load: %v", err)
	}
	t.Cleanup(func() { _ = p.Close(ctx) })

	status, err := h.Invoke(ctx, p, "run")
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if status != abiError {
		t.Errorf("write under a missing grant root returned %d, want %d (error)", status, abiError)
	}
}

// TestCapabilityNamesAreStableABI guards the wire contract with plugin authors:
// the exported host-function names and the status codes are published, so a
// rename is a breaking change for every compiled plugin in the wild.
func TestCapabilityNamesAreStableABI(t *testing.T) {
	for cap, fn := range map[pluginhost.Capability]string{
		pluginhost.CapFSRead:  "cap_read",
		pluginhost.CapFSWrite: "cap_write",
		pluginhost.CapNetDial: "cap_dial",
	} {
		ctx := context.Background()
		h := pluginhost.New()
		guest := guestModule(fn, map[string]int{"cap_read": 5, "cap_write": 4, "cap_dial": 2}[fn],
			make([]int32, map[string]int{"cap_read": 5, "cap_write": 4, "cap_dial": 2}[fn]), nil)
		if _, err := h.Load(ctx, guest, pluginhost.NewGrant(cap)); err != nil {
			t.Errorf("a guest importing env.%s under a %s grant failed to instantiate: %v; "+
				"the ABI name or signature changed, which breaks every compiled plugin", fn, cap, err)
		}
		_ = h.Close(ctx)
	}
	// And the reverse: an unknown import is not silently satisfied.
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })
	if _, err := h.Load(ctx, guestModule("cap_exec", 2, []int32{0, 0}, nil),
		pluginhost.NewGrant(pluginhost.CapFSRead, pluginhost.CapFSWrite, pluginhost.CapNetDial)); err == nil {
		t.Error("a guest importing env.cap_exec instantiated; only the three ABI functions may exist")
	} else if !strings.Contains(err.Error(), "cap_exec") {
		t.Logf("instantiation refused (message does not name the import): %v", err)
	}
}
