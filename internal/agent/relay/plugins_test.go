// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/pluginhost/wasmgen"
)

// The guarantees must hold in the RELAY, not merely have held on the brain
// (epic E4).
//
// Moving a sandbox is the kind of change where every property is assumed to
// travel with the code, because the code is the same code. It is also the kind
// of change where one of them quietly does not — a relay that loaded modules
// without verifying them, or widened the grant because "the relay already has
// network access", would be a downgrade wearing the same name and passing the
// same unit tests.
//
// So these re-prove each property here rather than citing the brain-side suite.

// signedPluginDir writes a signed module to a directory and returns the trust
// material for it.
func signedPluginDir(t *testing.T, name string, module []byte) (dir string, keyPEM []byte, sign func([]byte) []byte) {
	t.Helper()
	pubDER, signer, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate publisher key: %v", err)
	}
	dir = t.TempDir()
	writeModule(t, dir, name, module, signer(module))
	return dir, crypto.MarshalPublicKeyPEM(pubDER), signer
}

func writeModule(t *testing.T, dir, name string, module, sig []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name+".wasm"), module, 0o600); err != nil {
		t.Fatal(err)
	}
	if sig != nil {
		if err := os.WriteFile(filepath.Join(dir, name+".wasm.sig"), sig, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// benignModule reads a real file inside a directory the caller grants.
//
// A real file, because the host reads it: a module pointed at a path that does
// not exist fails for a reason unrelated to the sandbox, and a test that could
// not tell the two apart would pass for the wrong reason on the day the grant
// broke.
func benignModule(t *testing.T) (module []byte, dir string) {
	t.Helper()
	dir = t.TempDir()
	readable := filepath.Join(dir, "config")
	if err := os.WriteFile(readable, []byte("partner config"), 0o600); err != nil {
		t.Fatal(err)
	}
	return wasmgen.ReadGuest(readable), dir
}

// netDialModule dials a host. Used with a grant that HAS net.dial but constrains
// it to a different authority, which is what makes the denial a runtime one.
func netDialModule(addr string) []byte { return wasmgen.DialGuest(addr) }

// A signed third-party connector loads and deploys through the relay.
func TestASignedThirdPartyConnectorDeploysFromTheRelay(t *testing.T) {
	ctx := context.Background()
	module, readable := benignModule(t)
	dir, keyPEM, _ := signedPluginDir(t, "partner", module)

	rt, err := relay.NewPluginRuntime(ctx, relay.PluginConfig{
		Dir: dir, TrustedKeyPEMs: [][]byte{keyPEM},
		Grant: pluginhost.NewGrant(pluginhost.CapFSRead).
			WithPathPrefix(pluginhost.CapFSRead, readable),
	})
	if err != nil {
		t.Fatalf("load verified plugin: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close(ctx) })

	if !rt.Has("partner") {
		t.Fatalf("the signed module did not load; names = %v", rt.Names())
	}
	if err := rt.Deploy(ctx, "partner"); err != nil {
		t.Fatalf("deploy through the relay sandbox: %v", err)
	}
}

// The operator-facing census must come from the SAME successful verification
// that admitted the module. Re-reading filenames or configuration later would
// let the catalog describe a module other than the one the runtime can execute.
// It carries metadata only: never the WASM body, signature, or a secret value.
func TestPluginCensusComesFromVerifiedLoadedModules(t *testing.T) {
	ctx := context.Background()
	module, readable := benignModule(t)
	dir, keyPEM, _ := signedPluginDir(t, "partner", module)

	rt, err := relay.NewPluginRuntime(ctx, relay.PluginConfig{
		Dir: dir, TrustedKeyPEMs: [][]byte{keyPEM},
		Grant: pluginhost.NewGrant(pluginhost.CapNetDial, pluginhost.CapFSRead).
			WithPathPrefix(pluginhost.CapFSRead, readable).
			WithPathPrefix(pluginhost.CapNetDial, "appliance.internal:443"),
	})
	if err != nil {
		t.Fatalf("load verified plugin: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close(ctx) })

	entries := rt.Census()
	if len(entries) != 1 {
		t.Fatalf("plugin census = %+v, want one verified loaded module", entries)
	}
	got := entries[0]
	pubDER, err := crypto.ParseEd25519PublicKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "partner" || got.Digest != "sha256:"+crypto.SHA256Hex(module) ||
		got.Publisher != "sha256:"+crypto.SHA256Hex(pubDER) || got.ExecutionContext != "network_relay_wasm" {
		t.Fatalf("verified census identity = %+v", got)
	}
	if len(got.Grants) != 2 || got.Grants[0].Capability != "fs.read" ||
		len(got.Grants[0].Constraints) != 1 || got.Grants[0].Constraints[0] != readable ||
		got.Grants[1].Capability != "net.dial" || len(got.Grants[1].Constraints) != 1 ||
		got.Grants[1].Constraints[0] != "appliance.internal:443" {
		t.Fatalf("normalized effective grant = %+v", got.Grants)
	}
	wire, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "partner config") || strings.Contains(string(wire), "signature") {
		t.Fatalf("metadata-only census leaked module/signature material: %s", wire)
	}
}

// An UNSIGNED module is refused at load, and the refusal fails the whole
// runtime rather than skipping the file.
//
// Skipping would mean a relay comes up serving some connectors and silently
// missing others — and the missing one is the one somebody tampered with.
func TestAnUnsignedModuleIsRefusedAndFailsTheLoad(t *testing.T) {
	ctx := context.Background()
	pubDER, _, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	mod, _ := benignModule(t)
	writeModule(t, dir, "partner", mod, nil) // no .sig

	rt, err := relay.NewPluginRuntime(ctx, relay.PluginConfig{
		Dir: dir, TrustedKeyPEMs: [][]byte{crypto.MarshalPublicKeyPEM(pubDER)},
		Grant: pluginhost.NewGrant(pluginhost.CapFSRead).
			WithPathPrefix(pluginhost.CapFSRead, "/etc/partner"),
	})
	if err == nil {
		_ = rt.Close(ctx)
		t.Fatal("an unsigned module loaded on the relay; dropping a file into the plugin " +
			"directory must never be a way to get third-party code executed inside a " +
			"customer's network")
	}
	if !strings.Contains(err.Error(), "signature") && !strings.Contains(err.Error(), "unsigned") {
		t.Errorf("the refusal did not name the missing signature: %v", err)
	}
}

// A TAMPERED module is refused: the signature no longer matches the bytes.
func TestATamperedModuleIsRefused(t *testing.T) {
	ctx := context.Background()
	module, _ := benignModule(t)
	pubDER, sign, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// Sign the original, ship a modified body.
	sig := sign(module)
	tampered := append([]byte(nil), module...)
	tampered[len(tampered)-1] ^= 0xff
	writeModule(t, dir, "partner", tampered, sig)

	rt, err := relay.NewPluginRuntime(ctx, relay.PluginConfig{
		Dir: dir, TrustedKeyPEMs: [][]byte{crypto.MarshalPublicKeyPEM(pubDER)},
		Grant: pluginhost.NewGrant(pluginhost.CapFSRead).
			WithPathPrefix(pluginhost.CapFSRead, "/etc/partner"),
	})
	if err == nil {
		_ = rt.Close(ctx)
		t.Fatal("a tampered module loaded on the relay")
	}
}

// A module signed by an UNTRUSTED key is refused.
func TestAModuleSignedByAnUntrustedKeyIsRefused(t *testing.T) {
	ctx := context.Background()
	mod, _ := benignModule(t)
	dir, _, _ := signedPluginDir(t, "partner", mod)

	// A different publisher's key: the signature is valid, and not by anybody
	// this relay's operator authorized.
	otherPub, _, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := relay.NewPluginRuntime(ctx, relay.PluginConfig{
		Dir: dir, TrustedKeyPEMs: [][]byte{crypto.MarshalPublicKeyPEM(otherPub)},
		Grant: pluginhost.NewGrant(pluginhost.CapFSRead).
			WithPathPrefix(pluginhost.CapFSRead, "/etc/partner"),
	})
	if err == nil {
		_ = rt.Close(ctx)
		t.Fatal("a module signed by a key this relay does not trust was loaded")
	}
}

// An OUT-OF-GRANT operation is denied at RUNTIME, and the deploy FAILS.
//
// The acceptance criterion, and the one most likely to be lost in a move: the
// module loads, runs, reaches outside its grant, the sandbox denies the call —
// and if the deploy still returned nil the relay would report success for a
// connector that tried to reach somewhere its operator never authorized.
//
// The grant HAS net.dial and constrains it to one appliance. That is what makes
// this a runtime denial rather than a load failure: a module importing a
// capability it was not granted at all cannot instantiate, because the host only
// exports the import when the grant carries it. The interesting case — and the
// one a real partner connector hits — is a capability it does hold, pointed
// somewhere it does not.
func TestAnOutOfGrantOperationDeniesTheDeploy(t *testing.T) {
	ctx := context.Background()
	dir, keyPEM, _ := signedPluginDir(t, "partner", netDialModule("evil.example:443"))

	rt, err := relay.NewPluginRuntime(ctx, relay.PluginConfig{
		Dir: dir, TrustedKeyPEMs: [][]byte{keyPEM},
		Grant: pluginhost.NewGrant(pluginhost.CapNetDial).
			WithPathPrefix(pluginhost.CapNetDial, "appliance.internal:443"),
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close(ctx) })

	err = rt.Deploy(ctx, "partner")
	if err == nil {
		t.Fatal("a plugin that reached outside its capability grant reported a successful " +
			"deploy; the sandbox denial must fail the deploy, or an out-of-grant connector " +
			"succeeds quietly")
	}
	if !strings.Contains(err.Error(), "capability grant") {
		t.Errorf("the failure did not name the grant violation: %v", err)
	}
}

// A plugin directory with no trust keys refuses to come up.
//
// Fail closed: a trust policy with no keys that nonetheless loaded modules would
// be strictly worse than having no plugin support, because it would look like
// verification was happening.
func TestAPluginDirectoryWithoutTrustKeysIsRefused(t *testing.T) {
	ctx := context.Background()
	mod, _ := benignModule(t)
	dir, _, _ := signedPluginDir(t, "partner", mod)

	if _, err := relay.NewPluginRuntime(ctx, relay.PluginConfig{
		Dir:   dir,
		Grant: pluginhost.NewGrant(pluginhost.CapFSRead).WithPathPrefix(pluginhost.CapFSRead, "/etc/x"),
	}); err == nil {
		t.Fatal("a relay configured with a plugin directory and no publisher keys came up; " +
			"it would look like verification was happening while nothing was verified")
	}
}

// An UNSET grant is refused rather than defaulted.
//
// A grant that permits nothing is a legitimate configuration. A grant nobody set
// is a mistake. They are indistinguishable here, so the reading that cannot
// surprise anyone is the one that refuses.
func TestAnUnsetGrantIsRefusedRatherThanDefaulted(t *testing.T) {
	ctx := context.Background()
	mod, _ := benignModule(t)
	dir, keyPEM, _ := signedPluginDir(t, "partner", mod)

	if _, err := relay.NewPluginRuntime(ctx, relay.PluginConfig{
		Dir: dir, TrustedKeyPEMs: [][]byte{keyPEM},
	}); err == nil {
		t.Fatal("a relay ran third-party code under a grant nobody set")
	}
}

// No plugin directory means no plugin surface, not an error.
func TestNoPluginDirectoryLeavesTheSurfaceOff(t *testing.T) {
	ctx := context.Background()
	rt, err := relay.NewPluginRuntime(ctx, relay.PluginConfig{})
	if err != nil {
		t.Fatalf("an unconfigured relay failed to start: %v", err)
	}
	if rt != nil {
		t.Error("an unconfigured relay built a plugin runtime")
	}
	// The nil runtime must be safe to interrogate: the deploy path checks Has
	// before reaching for a plugin.
	if rt.Has("anything") {
		t.Error("a nil runtime claimed to carry a plugin")
	}
}
