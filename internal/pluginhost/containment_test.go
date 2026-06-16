package pluginhost_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/pluginhost"
)

// trapWASM exports boom() i32 whose body is the `unreachable` trap — a plugin
// that faults the instant it runs.
var trapWASM = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, // type: () -> i32
	0x03, 0x02, 0x01, 0x00, // func 0 : type 0
	0x07, 0x08, 0x01, 0x04, 0x62, 0x6f, 0x6f, 0x6d, 0x00, 0x00, // export "boom" func 0
	0x0a, 0x05, 0x01, 0x03, 0x00, 0x00, 0x0b, // code: unreachable; end
}

// smuggleWASM imports env.evil() — a host function the host never registers — so
// it must fail to instantiate: a plugin cannot conjure a capability its grant did
// not give it.
var smuggleWASM = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: () -> ()
	0x02, 0x0c, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x04, 0x65, 0x76, 0x69, 0x6c, 0x00, 0x00, // import env.evil
}

// TestMisbehavingPluginIsContained is the R3.4 containment acceptance (B8): a
// deliberately misbehaving plugin cannot escape its runtime, take down the host,
// or reach anything the host did not hand it. Combined with the structural fact
// that the Host holds no DB pool or signer handle (see
// TestPluginHostHoldsNoPrivilegedHandles, and the docs reality test), "contained
// to the guest runtime" means a plugin defect provably cannot touch the database
// or the signer — which is exactly the isolation trstctl advertises for
// third-party WASM plugins.
func TestMisbehavingPluginIsContained(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	// (1) A guest trap is contained: Invoke returns an error instead of crashing
	// the host process.
	boom, err := h.Load(ctx, trapWASM, pluginhost.NewGrant())
	if err != nil {
		t.Fatalf("load trapping plugin: %v", err)
	}
	t.Cleanup(func() { _ = boom.Close(ctx) })
	if _, err := h.Invoke(ctx, boom, "boom"); err == nil {
		t.Fatal("a trapping plugin returned no error; the trap was not contained")
	}

	// (2) The host survives the fault: a well-behaved plugin still loads and runs
	// afterward, so one plugin's defect does not poison the host.
	ok, err := h.Load(ctx, helloWASM, pluginhost.NewGrant())
	if err != nil {
		t.Fatalf("host unusable after a plugin trap: %v", err)
	}
	t.Cleanup(func() { _ = ok.Close(ctx) })
	got, err := h.Invoke(ctx, ok, "run")
	if err != nil || got != 42 {
		t.Fatalf("host did not recover after a plugin trap: got %d, err %v", got, err)
	}

	// (3) A plugin cannot import a host function the host never registered: its
	// powers are exactly its grant — nothing can be smuggled in through an import.
	if _, err := h.Load(ctx, smuggleWASM, pluginhost.NewGrant()); err == nil {
		t.Fatal("a plugin importing an unregistered host function loaded; the import surface is not closed")
	}
}

// TestUngrantedPluginCanDoNothingPrivileged is the zero-grant containment case: a
// plugin loaded with an empty grant cannot perform any gated operation. It can
// compute and return a value (pure compute is always allowed), but every
// capability call is denied.
func TestUngrantedPluginCanDoNothingPrivileged(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	p, err := h.Load(ctx, capWASM, pluginhost.NewGrant()) // no capabilities
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close(ctx) })
	if _, err := h.Invoke(ctx, p, "run"); err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if p.Stats().Writes != 0 {
		t.Errorf("an ungranted plugin performed %d writes, want 0", p.Stats().Writes)
	}
	if p.Stats().Denied == 0 {
		t.Error("an ungranted plugin's privileged call was not denied")
	}
}

// TestPluginHostHoldsNoPrivilegedHandles is the structural half of containment:
// the plugin host package imports neither the store (the DB pool) nor the signer,
// so by construction a plugin running on the host has no path to reach them. The
// runtime isolation proven above rests on this — there is simply no privileged
// handle in the host's address space for a guest to find.
func TestPluginHostHoldsNoPrivilegedHandles(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"internal/store", "internal/signing"} {
			if strings.Contains(string(src), forbidden) {
				t.Errorf("%s imports %s; the plugin host must hold no DB pool or signer handle", name, forbidden)
			}
		}
	}
}
