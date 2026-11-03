// SPDX-License-Identifier: BUSL-1.1

package pluginhost_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/pluginhost/wasmgen"
)

// manifestJSON is a valid manifest for module, with edit applied to its
// decoded form so each case changes one thing.
func manifestJSON(t *testing.T, module []byte, edit func(m map[string]any)) []byte {
	t.Helper()
	m := map[string]any{
		"name":          "appliance",
		"version":       "1.2.0",
		"module_sha256": crypto.SHA256Hex(module),
		"host_api":      map[string]any{"min": 1, "max": 1},
		"permissions": map[string]any{
			"capabilities": []string{"net.http", "input.read"},
			"resources":    map[string][]string{"net.http": {"api.example:443"}},
			"credentials":  []string{"bearer"},
		},
		"actions":     []string{"deploy", "test", "readback"},
		"idempotency": "replace-by-name",
		"revocation":  "delete",
		"inputs":      []map[string]any{{"name": "partition", "type": "string", "required": true}},
		"limits":      map[string]any{"memory_pages": 64, "timeout_ms": 5000},
	}
	if edit != nil {
		edit(m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A242: a manifest is read strictly. Anything the host does not understand,
// or a limit beyond the host's, refuses the module instead of being ignored.
func TestManifestIsReadStrictlyA242(t *testing.T) {
	module := wasmgen.DialGuest("api.example:443")
	m, err := pluginhost.ParseManifest(manifestJSON(t, module, nil))
	if err != nil {
		t.Fatalf("valid manifest refused: %v", err)
	}
	if !m.SupportsHost() || !m.Has("readback") || m.ResourceLimits().Timeout != 5*time.Second {
		t.Fatalf("manifest read wrong: %+v", m)
	}
	for name, edit := range map[string]func(map[string]any){
		"unknown field":          func(m map[string]any) { m["grants_itself"] = true },
		"bad version":            func(m map[string]any) { m["version"] = "1.2" },
		"bad module digest":      func(m map[string]any) { m["module_sha256"] = "ABC" },
		"no deploy":              func(m map[string]any) { m["actions"] = []string{"test"} },
		"unknown action":         func(m map[string]any) { m["actions"] = []string{"deploy", "exec"} },
		"create-new no readback": func(m map[string]any) { m["idempotency"] = "create-new"; m["actions"] = []string{"deploy"} },
		"unknown idempotency":    func(m map[string]any) { m["idempotency"] = "hope" },
		"unknown revocation":     func(m map[string]any) { m["revocation"] = "ignore" },
		"unknown capability": func(m map[string]any) {
			m["permissions"].(map[string]any)["capabilities"] = []string{"proc.exec"}
		},
		"resource not asked for": func(m map[string]any) {
			m["permissions"].(map[string]any)["resources"] = map[string][]string{"fs.write": {"/etc"}}
		},
		"credential field": func(m map[string]any) {
			m["permissions"].(map[string]any)["credentials"] = []string{"password"}
		},
		"reserved credential header": func(m map[string]any) {
			m["permissions"].(map[string]any)["credentials"] = []string{"header:Proxy-Authorization"}
		},
		"memory over host":  func(m map[string]any) { m["limits"] = map[string]any{"memory_pages": pluginhost.MaxMemoryPages + 1} },
		"timeout over host": func(m map[string]any) { m["limits"] = map[string]any{"timeout_ms": 31000} },
		"host api range":    func(m map[string]any) { m["host_api"] = map[string]any{"min": 2, "max": 1} },
		"input type":        func(m map[string]any) { m["inputs"] = []map[string]any{{"name": "x", "type": "file"}} },
	} {
		if _, err := pluginhost.ParseManifest(manifestJSON(t, module, edit)); err == nil {
			t.Errorf("%s: manifest accepted", name)
		}
	}
	future, err := pluginhost.ParseManifest(manifestJSON(t, module, func(m map[string]any) {
		m["host_api"] = map[string]any{"min": 2, "max": 3}
	}))
	if err != nil || future.SupportsHost() {
		t.Fatalf("a module for a later host ABI reads as supported (err %v)", err)
	}
}

// A242: the operator's grant is the ceiling. A manifest that asks for a
// capability, a resource or a credential mode outside it refuses the module;
// within it, the module runs under exactly what it asked for.
func TestEffectiveGrantStaysInsideTheOperatorsA242(t *testing.T) {
	operator := pluginhost.NewGrant(pluginhost.CapHTTP, pluginhost.CapFSWrite, pluginhost.CapInputRead).
		WithPathPrefix(pluginhost.CapHTTP, "api.example:443").
		WithPathPrefix(pluginhost.CapHTTP, "backup.example").
		WithPathPrefix(pluginhost.CapFSWrite, "/srv/certs")
	parse := func(perms map[string]any) pluginhost.Manifest {
		t.Helper()
		m, err := pluginhost.ParseManifest(manifestJSON(t, []byte("module"), func(m map[string]any) { m["permissions"] = perms }))
		if err != nil {
			t.Fatalf("manifest: %v", err)
		}
		return m
	}
	effective, err := pluginhost.EffectiveGrant(operator, parse(map[string]any{
		"capabilities": []string{"net.http", "fs.write"},
		"resources":    map[string][]string{"net.http": {"backup.example:8443"}, "fs.write": {"/srv/certs/app"}},
		"credentials":  []string{"bearer"},
	}))
	if err != nil {
		t.Fatalf("a manifest inside the operator's grant was refused: %v", err)
	}
	switch {
	case !effective.Allows(pluginhost.CapHTTP, "backup.example:8443"):
		t.Fatal("the module did not get the host it asked for")
	case effective.Allows(pluginhost.CapHTTP, "api.example:443"):
		t.Fatal("the module got a host the operator allowed but it did not ask for")
	case effective.Allows(pluginhost.CapFSWrite, "/srv/certs/other/x"):
		t.Fatal("the module got a path outside the one it asked for")
	case effective.Has(pluginhost.CapInputRead):
		t.Fatal("the module got a capability it did not ask for")
	case !effective.AllowsCredential("bearer", ""), effective.AllowsCredential("basic", ""),
		effective.AllowsCredential("header", "X-Api-Key"):
		t.Fatal("the module's credential modes are not exactly the ones it declared")
	}
	for name, perms := range map[string]map[string]any{
		"capability":     {"capabilities": []string{"net.dial"}},
		"host":           {"capabilities": []string{"net.http"}, "resources": map[string][]string{"net.http": {"evil.example:443"}}},
		"any port":       {"capabilities": []string{"net.http"}, "resources": map[string][]string{"net.http": {"api.example"}}},
		"path":           {"capabilities": []string{"fs.write"}, "resources": map[string][]string{"fs.write": {"/srv/certs-evil"}}},
		"path traversal": {"capabilities": []string{"fs.write"}, "resources": map[string][]string{"fs.write": {"/srv/certs/../keys"}}},
	} {
		if _, err := pluginhost.EffectiveGrant(operator, parse(perms)); err == nil {
			t.Errorf("%s outside the operator's grant was granted", name)
		}
	}
	bearerOnly := operator.WithCredentials("bearer")
	if _, err := pluginhost.EffectiveGrant(bearerOnly, parse(map[string]any{
		"capabilities": []string{"net.http"}, "credentials": []string{"basic"},
	})); err == nil {
		t.Fatal("a credential mode the operator did not allow was granted")
	}
}

// A242: an upgrade's review lists exactly what it asks for beyond the approved
// version; one that asks for no more needs no review.
func TestPermissionDiffNamesEveryExpansionA242(t *testing.T) {
	approved := pluginhost.Permissions{
		Capabilities: []string{"net.http"},
		Resources:    map[string][]string{"net.http": {"a.example:443"}},
		Credentials:  []string{"bearer"},
	}
	wider := pluginhost.Permissions{
		Capabilities: []string{"net.http", "net.dial"},
		Resources:    map[string][]string{"net.http": {"a.example:443", "b.example:443"}},
		Credentials:  []string{"Bearer", "basic"},
	}
	want := []string{"capability net.dial", "credential basic", "resource net.http=b.example:443"}
	if got := pluginhost.PermissionDiff(approved, wider); !reflect.DeepEqual(got, want) {
		t.Fatalf("diff = %v, want %v", got, want)
	}
	if got := pluginhost.PermissionDiff(wider, approved); len(got) != 0 {
		t.Fatalf("a narrowing upgrade needs review: %v", got)
	}
	unconstrained := pluginhost.Permissions{Capabilities: []string{"net.http"}}
	if got := pluginhost.PermissionDiff(approved, unconstrained); !reflect.DeepEqual(got, []string{"resource net.http unconstrained"}) {
		t.Fatalf("dropping a host constraint is not flagged: %v", got)
	}
	if pluginhost.CompareVersions("1.10.0", "1.9.9") != 1 || pluginhost.CompareVersions("2.0.0", "2.0.0") != 0 {
		t.Fatal("versions compare as strings, not numbers")
	}
}

// A242: the host adds the target's credential only the ways the module's grant
// names. A module granted bearer that asks for basic is denied before any
// request is made.
func TestModuleCredentialsAreEnforcedAtTheHostA242(t *testing.T) {
	module := wasmgen.HTTPGuest(`{"method":"GET","url":"https://api.example/status","auth":"basic"}`, "")
	for _, tc := range []struct {
		modes   []string
		allowed bool
	}{{[]string{"bearer"}, false}, {[]string{"basic"}, true}, {nil, false}} {
		h := pluginhost.New()
		grant := pluginhost.NewGrant(pluginhost.CapHTTP).WithPathPrefix(pluginhost.CapHTTP, "api.example:443").
			WithCredentials(tc.modes...)
		p, err := h.Load(context.Background(), module, grant)
		if err != nil {
			t.Fatal(err)
		}
		sent := 0
		rc, err := h.InvokeWith(context.Background(), p, "deploy", pluginhost.Invocation{
			HTTP: func(context.Context, pluginhost.HTTPRequest) (pluginhost.HTTPResponse, error) {
				sent++
				return pluginhost.HTTPResponse{Status: 200}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if tc.allowed != (sent == 1) || tc.allowed != (rc == 0) || tc.allowed != (p.Stats().Denied == 0) {
			t.Errorf("credentials %v: sent %d, rc %d, denied %d", tc.modes, sent, rc, p.Stats().Denied)
		}
		_ = p.Close(context.Background())
		_ = h.Close(context.Background())
	}
}

// A242: a module's memory cannot grow past its limit and a call cannot run
// past its time; a trap and a timeout are told apart.
func TestModuleLimitsBoundMemoryAndTimeA242(t *testing.T) {
	tp, sign := trustedSigner(t)
	module := wasmgen.Module("cap_dial", 2, nil, []wasmgen.Export{
		{Name: "grow", Raw: wasmgen.Grow(64)},
		{Name: "spin", Raw: wasmgen.Spin},
		{Name: "trap", Raw: wasmgen.Trap},
	})
	grant := pluginhost.NewGrant(pluginhost.CapNetDial)
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(context.Background()) })
	load := func(limits pluginhost.Limits) *pluginhost.Plugin {
		t.Helper()
		p, _, err := h.LoadVerifiedModule(context.Background(), module, sign(module), tp, grant, limits)
		if err != nil {
			t.Fatalf("load under %+v: %v", limits, err)
		}
		t.Cleanup(func() { _ = p.Close(context.Background()) })
		return p
	}
	small := load(pluginhost.Limits{MemoryPages: 16, Timeout: 200 * time.Millisecond})
	if rc, err := h.Invoke(context.Background(), small, "grow"); err != nil || rc != 1 {
		t.Fatalf("memory grew past a 16-page limit: rc %d, err %v", rc, err)
	}
	if rc, err := h.Invoke(context.Background(), load(pluginhost.Limits{}), "grow"); err != nil || rc != 0 {
		t.Fatalf("64 pages refused under the default limit: rc %d, err %v", rc, err)
	}
	start := time.Now()
	_, err := h.Invoke(context.Background(), small, "spin")
	if elapsed := time.Since(start); pluginhost.FailureClass(err) != pluginhost.FailureTimeout || elapsed > 5*time.Second {
		t.Fatalf("a spinning call: class %q after %s (err %v)", pluginhost.FailureClass(err), elapsed, err)
	}
	if _, err := h.Invoke(context.Background(), small, "trap"); pluginhost.FailureClass(err) != pluginhost.FailureTrap {
		t.Fatalf("a trap is classed %q (err %v)", pluginhost.FailureClass(err), err)
	}
	if _, err := h.Invoke(context.Background(), small, "absent"); pluginhost.FailureClass(err) != pluginhost.FailureNoEntry {
		t.Fatalf("a missing entry point is classed %q", pluginhost.FailureClass(err))
	}
	// The module still serves after a timeout and a trap: each call has its own
	// instance.
	if rc, err := h.Invoke(context.Background(), small, "grow"); err != nil || rc != 1 {
		t.Fatalf("the module did not survive its failures: rc %d, err %v", rc, err)
	}
	if _, _, err := h.LoadVerifiedModule(context.Background(), module, sign(module), tp, grant,
		pluginhost.Limits{MemoryPages: pluginhost.MaxMemoryPages + 1}); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("limits beyond the host's loaded: %v", err)
	}
}

// A242: a manifest must be signed by the key that signed its module.
func TestManifestMustBeSignedByTheModulesPublisherA242(t *testing.T) {
	pubA, signA, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubB, signB, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	tp, err := pluginhost.NewTrustPolicy([][]byte{crypto.MarshalPublicKeyPEM(pubA), crypto.MarshalPublicKeyPEM(pubB)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	module := wasmgen.DialGuest("api.example:443")
	provenance, err := tp.VerifyProvenance(module, signA(module))
	if err != nil {
		t.Fatal(err)
	}
	manifest := manifestJSON(t, module, nil)
	if err := tp.VerifyPublisher(provenance.Publisher, manifest, signA(manifest)); err != nil {
		t.Fatalf("the publisher's own manifest signature refused: %v", err)
	}
	if err := tp.VerifyPublisher(provenance.Publisher, manifest, signB(manifest)); err == nil {
		t.Fatal("another trusted publisher's signature speaks for this module's manifest")
	}
	if err := tp.VerifyPublisher(provenance.Publisher, append(manifest, ' '), signA(manifest)); err == nil {
		t.Fatal("an edited manifest verified")
	}
}
