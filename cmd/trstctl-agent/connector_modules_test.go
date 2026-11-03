// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pluginhost/wasmgen"
)

// A242: the operator's two connector module commands. The conformance kit
// checks every module without approving anything; approving prints what the
// module asks for and what that adds, records it beside the agent's key, and
// the relay then loads it.
func TestConnectorModuleCheckAndApproveCommandsA242(t *testing.T) {
	ctx := context.Background()
	pubDER, sign, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	state, dir := t.TempDir(), t.TempDir()
	keyFile := filepath.Join(state, "publisher.pem")
	if err := os.WriteFile(keyFile, crypto.MarshalPublicKeyPEM(pubDER), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(name string, module []byte, actions []string) {
		t.Helper()
		manifest, err := json.Marshal(map[string]any{
			"name": name, "version": "1.0.0", "module_sha256": crypto.SHA256Hex(module),
			"host_api":    map[string]int{"min": 1, "max": 1},
			"permissions": map[string]any{"capabilities": []string{"net.http"}, "credentials": []string{"bearer"}},
			"actions":     actions, "idempotency": "replace-by-name", "revocation": "delete",
		})
		if err != nil {
			t.Fatal(err)
		}
		for file, body := range map[string][]byte{
			name + ".wasm": module, name + ".wasm.sig": sign(module),
			name + ".manifest.json": manifest, name + ".manifest.json.sig": sign(manifest),
		} {
			if err := os.WriteFile(filepath.Join(dir, file), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	write("partner-lb", wasmgen.HTTPGuest(`{"method":"PUT","url":"https://lb.internal/api","auth":"bearer"}`,
		`{"method":"GET","url":"https://lb.internal/api","auth":"bearer"}`), []string{"deploy", "test"})

	flags := pluginFlags{
		dir: dir, keys: keyFile, caps: "net.http", prefixes: "net.http=lb.internal:443",
		approvals: pluginApprovalsPath("", filepath.Join(state, "agent.key")),
	}
	cfg, err := pluginRuntimeConfig(flags)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := checkConnectorModulesCommand(ctx, &out, cfg); err != nil {
		t.Fatalf("the kit failed a conformant module: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "partner-lb 1.0.0 sha256:") || !strings.Contains(out.String(), "awaiting-approval") ||
		strings.Contains(out.String(), "FAIL") {
		t.Fatalf("kit output:\n%s", out.String())
	}
	if _, err := os.Stat(cfg.ApprovalsPath); !os.IsNotExist(err) {
		t.Fatal("the kit recorded an approval")
	}

	out.Reset()
	if err := approveConnectorModuleCommand(ctx, &out, cfg, "partner-lb", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"capability net.http", "credential bearer", `"credentials":["bearer"]`, "approved in " + cfg.ApprovalsPath} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("the review does not say %q:\n%s", want, out.String())
		}
	}
	if info, err := os.Stat(cfg.ApprovalsPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("approval record: %v %v", info, err)
	}
	rt, err := relay.NewPluginRuntime(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if names := rt.Names(); len(names) != 1 || names[0] != "partner-lb" {
		t.Fatalf("the approved module did not load: %v", rt.Modules())
	}
	_ = rt.Close(ctx)

	// A module declaring an action it does not export fails the kit.
	write("partner-fw", wasmgen.HTTPGuest(`{"method":"PUT","url":"https://lb.internal/api"}`, ""), []string{"deploy", "readback"})
	out.Reset()
	err = checkConnectorModulesCommand(ctx, &out, cfg)
	if err == nil || !strings.Contains(out.String(), "FAIL exports every action it declares: declared but not exported: readback") {
		t.Fatalf("the kit passed a module missing a declared action (err %v):\n%s", err, out.String())
	}
	if err := approveConnectorModuleCommand(ctx, &out, cfg, "absent", time.Now()); err == nil {
		t.Fatal("approving a module that is not there succeeded")
	}
	if _, err := pluginRuntimeConfig(pluginFlags{dir: dir, keys: keyFile, caps: "net.http", credentials: "password"}); err == nil {
		t.Fatal("an unknown credential mode was accepted as the ceiling")
	}
}
