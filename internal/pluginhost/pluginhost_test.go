// SPDX-License-Identifier: BUSL-1.1

package pluginhost_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/pluginhost"
)

// helloWASM exports run() i32 returning 42, with no imports — the simplest fully
// sandboxed plugin.
var helloWASM = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, // type: () -> i32
	0x03, 0x02, 0x01, 0x00, // func 0 : type 0
	0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00, // export "run" func 0
	0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b, // code: i32.const 42; end
}

// capWASM imports env.cap_write and exports run() i32 that calls it, targeting a
// path no grant in these tests permits. It is the "declares a privileged import"
// fixture: it instantiates only under an fs.write grant, and is denied at the call
// unless that grant also covers /denied/by/default.
var capWASM = writeGuest("/denied/by/default", "x")

// TestGrantAllows is the capability model: a plugin cannot exceed its grant.
func TestGrantAllows(t *testing.T) {
	g := pluginhost.NewGrant(pluginhost.CapFSWrite).WithPathPrefix(pluginhost.CapFSWrite, "/data")

	if !g.Has(pluginhost.CapFSWrite) {
		t.Error("granted capability must be present")
	}
	if g.Has(pluginhost.CapNetDial) {
		t.Error("un-granted capability must be absent")
	}
	if !g.Allows(pluginhost.CapFSWrite, "/data/certs/leaf.pem") {
		t.Error("write within the granted prefix must be allowed")
	}
	if g.Allows(pluginhost.CapFSWrite, "/etc/passwd") {
		t.Error("write outside the granted prefix must be denied")
	}
	if g.Allows(pluginhost.CapNetDial, "example.com:443") {
		t.Error("un-granted capability must be denied regardless of resource")
	}
}

// TestHelloPluginRunsSandboxed is the acceptance: a hello-world plugin runs
// sandboxed.
func TestHelloPluginRunsSandboxed(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	p, err := h.Load(ctx, helloWASM, pluginhost.NewGrant())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = p.Close(ctx) })

	got, err := h.Invoke(ctx, p, "run")
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if got != 42 {
		t.Errorf("run() = %d, want 42", got)
	}
}

// TestUngrantedOperationDenied is the acceptance for the RUNTIME half of the
// capability model: a plugin holding a capability is still denied the resources
// its grant does not cover.
//
// The other half — a plugin that was never granted the capability at all — is no
// longer a runtime deny. It cannot instantiate, which is stronger and is covered
// by TestUngrantedImportFailsToInstantiate.
func TestUngrantedOperationDenied(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	allowed := t.TempDir()
	grant := pluginhost.NewGrant(pluginhost.CapFSWrite).
		WithPathPrefix(pluginhost.CapFSWrite, allowed)

	// capWASM targets /denied/by/default, outside the granted prefix.
	denied, err := h.Load(ctx, capWASM, grant)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = denied.Close(ctx) })
	res, err := h.Invoke(ctx, denied, "run")
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if res == 0 {
		t.Error("a write outside the granted prefix returned success; it must be denied")
	}
	if denied.Stats().Writes != 0 {
		t.Errorf("denied plugin performed %d writes, want 0", denied.Stats().Writes)
	}
	if denied.Stats().Denied == 0 {
		t.Error("denial was not recorded at runtime")
	}

	// The same capability, a path the grant does cover.
	granted, err := h.Load(ctx, writeGuest(allowed+"/ok", "x"), grant)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = granted.Close(ctx) })
	res, err = h.Invoke(ctx, granted, "run")
	if err != nil {
		t.Fatalf("Invoke (granted): %v", err)
	}
	if res != 0 {
		t.Errorf("granted cap_write returned %d, want 0 (success)", res)
	}
	if granted.Stats().Writes != 1 {
		t.Errorf("granted plugin performed %d writes, want 1", granted.Stats().Writes)
	}
}

// TestHostIsBulkheaded is the acceptance: the host is bulkheaded per AN-7 — a
// saturated host rejects further invocations fast.
func TestHostIsBulkheaded(t *testing.T) {
	ctx := context.Background()
	pool := bulkhead.New(bulkhead.Config{Name: "plugins", Workers: 1, Queue: 1})
	h := pluginhost.New(pluginhost.WithPool(pool))
	t.Cleanup(func() { _ = h.Close(ctx) })

	p, err := h.Load(ctx, helloWASM, pluginhost.NewGrant())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close(ctx) })

	// Saturate the host's pool: occupy the worker, then fill the queue.
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	if err := pool.Submit(func() { started <- struct{}{}; <-release }); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := pool.Submit(func() { <-release }); err != nil {
		t.Fatal(err)
	}

	_, err = h.Invoke(ctx, p, "run")
	if !errors.Is(err, bulkhead.ErrRejected) {
		t.Errorf("Invoke on a saturated host = %v, want ErrRejected", err)
	}
	close(release)
}

// TestPluginInvokeReturnsOnContextTimeoutWhileQueued proves a queued plugin call
// observes its caller's deadline while waiting for the worker result. Without this
// select on ctx.Done, a plugin/outbox delivery can keep the caller blocked until
// the worker eventually runs or returns.
func TestPluginInvokeReturnsOnContextTimeoutWhileQueued(t *testing.T) {
	ctx := context.Background()
	pool := bulkhead.New(bulkhead.Config{Name: "plugins", Workers: 1, Queue: 1})
	h := pluginhost.New(pluginhost.WithPool(pool))
	t.Cleanup(func() { _ = h.Close(ctx) })

	p, err := h.Load(ctx, helloWASM, pluginhost.NewGrant())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close(ctx) })

	started := make(chan struct{})
	release := make(chan struct{})
	if err := pool.Submit(func() { close(started); <-release }); err != nil {
		t.Fatal(err)
	}
	<-started

	callCtx, cancel := context.WithTimeout(ctx, 25*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = h.Invoke(callCtx, p, "run")
	if !errors.Is(err, context.DeadlineExceeded) {
		close(release)
		t.Fatalf("Invoke err = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		close(release)
		t.Fatalf("Invoke returned after %v, want it bounded by the caller deadline", elapsed)
	}

	close(release)
}

// TestConformanceValidatesSamplePlugin is the acceptance: the conformance suite
// validates a sample plugin.
func TestConformanceValidatesSamplePlugin(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	report := h.Conformance(ctx, helloWASM)
	if !report.OK() {
		t.Errorf("sample plugin failed conformance: %+v", report.Checks)
	}
	if len(report.Checks) == 0 {
		t.Error("conformance produced no checks")
	}

	// A plugin that DECLARES a privileged import is not conformant at zero
	// capabilities: with a grant-shaped environment it cannot even instantiate.
	// That is the containment proof, so it must be reported as a failure rather
	// than quietly passing.
	if h.Conformance(ctx, capWASM).OK() {
		t.Error("a plugin importing env.cap_write passed conformance under an empty grant")
	}

	// It is conformant under the grant it actually needs: the capability AND a
	// prefix covering the path it writes.
	workdir := t.TempDir()
	needsWrite := writeGuest(workdir+"/out", "x")
	underGrant := h.ConformanceUnderGrant(ctx, needsWrite,
		pluginhost.NewGrant(pluginhost.CapFSWrite).WithPathPrefix(pluginhost.CapFSWrite, workdir))
	if !underGrant.OK() {
		t.Errorf("capability plugin failed conformance under its own grant: %+v", underGrant.Checks)
	}

	// The same plugin under a grant that does NOT cover the path it writes is
	// reported as reaching past its grant — the signal an operator needs before
	// admitting it, even though the sandbox itself held.
	tooNarrow := h.ConformanceUnderGrant(ctx, needsWrite,
		pluginhost.NewGrant(pluginhost.CapFSWrite).WithPathPrefix(pluginhost.CapFSWrite, t.TempDir()))
	if tooNarrow.OK() {
		t.Error("a plugin writing outside its granted prefix passed conformance")
	}

	// A non-module is not conformant.
	if h.Conformance(ctx, []byte("not wasm")).OK() {
		t.Error("garbage passed conformance")
	}
}
