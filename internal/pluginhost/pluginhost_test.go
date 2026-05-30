package pluginhost_test

import (
	"context"
	"errors"
	"testing"

	"certctl.io/certctl/internal/bulkhead"
	"certctl.io/certctl/internal/pluginhost"
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

// capWASM imports env.cap_write(i32) i32 and exports run() i32 that calls it with
// arg 1 and returns the result — used to exercise capability gating.
var capWASM = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x0a, 0x02, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x00, 0x01, 0x7f, // types: (i32)->i32, ()->i32
	0x02, 0x11, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x09, 0x63, 0x61, 0x70, 0x5f, 0x77, 0x72, 0x69, 0x74, 0x65, 0x00, 0x00, // import env.cap_write : type 0
	0x03, 0x02, 0x01, 0x01, // func 1 (run) : type 1
	0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x01, // export "run" func 1
	0x0a, 0x08, 0x01, 0x06, 0x00, 0x41, 0x01, 0x10, 0x00, 0x0b, // code: i32.const 1; call 0; end
}

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

// TestUngrantedOperationDenied is the acceptance: a plugin attempting an
// un-granted operation is denied at runtime.
func TestUngrantedOperationDenied(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	// Without the fs.write capability, cap_write is denied and performs nothing.
	denied, err := h.Load(ctx, capWASM, pluginhost.NewGrant())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = denied.Close(ctx) })
	res, err := h.Invoke(ctx, denied, "run")
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if res == 0 {
		t.Error("un-granted cap_write returned success; it must be denied")
	}
	if denied.Stats().Writes != 0 {
		t.Errorf("un-granted plugin performed %d writes, want 0", denied.Stats().Writes)
	}
	if denied.Stats().Denied == 0 {
		t.Error("denial was not recorded at runtime")
	}

	// With the capability granted, the same plugin succeeds.
	granted, err := h.Load(ctx, capWASM, pluginhost.NewGrant(pluginhost.CapFSWrite))
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

// TestConformanceValidatesSamplePlugin is the acceptance: the conformance suite
// validates a sample plugin.
func TestConformanceValidatesSamplePlugin(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	report := h.Conformance(ctx, capWASM)
	if !report.OK() {
		t.Errorf("sample plugin failed conformance: %+v", report.Checks)
	}
	if len(report.Checks) == 0 {
		t.Error("conformance produced no checks")
	}

	// A non-module is not conformant.
	if h.Conformance(ctx, []byte("not wasm")).OK() {
		t.Error("garbage passed conformance")
	}
}
