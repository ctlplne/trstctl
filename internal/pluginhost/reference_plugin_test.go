// SPDX-License-Identifier: BUSL-1.1

package pluginhost_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/pluginhost/wasmgen"
)

// referenceWATs are the plugin sources this repository ships for authors to copy.
var referenceWATs = []string{
	"../../plugins/connectors/reference/reference-connector.wat",
	"../../plugins/connectors/reference/reference-http-connector.wat",
	"../../plugins/ca/reference/reference-ca.wat",
}

// abiArity is the published signature of each capability function: the number of
// i32 arguments a guest must declare on its import.
var abiArity = map[string]int{
	"cap_read":   5,
	"cap_write":  4,
	"cap_dial":   2,
	"cap_http":   5,
	"input_read": 5,
}

// TestReferencePluginsDeclareTheCurrentABI keeps the shipped reference plugins in
// sync with the host.
//
// These .wat files are what a plugin author copies, and they are text: nothing
// compiles them in CI (wat2wasm is not a build dependency), so a change to the
// host ABI can silently leave the repository shipping a reference plugin that
// cannot instantiate. That is exactly what happened when the capability functions
// grew from a single ignored argument to real (pointer, length) pairs — both
// reference plugins still declared `(param i32)` and would have failed to load
// with "signature mismatch" for the first author who tried them.
//
// The guard checks the declaration, not the behavior: the import's arity against
// the host's published arity, plus the exported memory the ABI requires for
// passing a path.
func TestReferencePluginsDeclareTheCurrentABI(t *testing.T) {
	importRe := regexp.MustCompile(`\(import\s+"env"\s+"(\w+)"[\s\S]*?\(param([^)]*)\)\s*\(result\s+i32\)`)

	for _, rel := range referenceWATs {
		body, err := os.ReadFile(rel) // #nosec G304 -- fixed in-repo reference plugin path (CWE-22)
		if err != nil {
			t.Errorf("read %s: %v; the reference plugins are a shipped artifact and must exist", rel, err)
			continue
		}
		src := string(body)

		m := importRe.FindStringSubmatch(src)
		if m == nil {
			t.Errorf("%s: no `(import \"env\" ...)` with an i32 result found; a reference plugin "+
				"must show an author how to declare a capability import", filepath.Base(rel))
			continue
		}
		fn, params := m[1], strings.Fields(m[2])
		want, known := abiArity[fn]
		if !known {
			t.Errorf("%s imports env.%s, which is not part of the ABI (%v)", filepath.Base(rel), fn, abiArity)
			continue
		}
		if len(params) != want {
			t.Errorf("%s declares env.%s with %d i32 params, but the host exports it with %d; "+
				"an author copying this file gets \"signature mismatch\" and cannot load the plugin",
				filepath.Base(rel), fn, len(params), want)
		}
		if !strings.Contains(src, `(memory (export "memory")`) {
			t.Errorf("%s does not export a memory named \"memory\"; the ABI passes paths as "+
				"(pointer, length) into guest memory, so the host cannot read anything without it",
				filepath.Base(rel))
		}
	}
}

// TestReferencePluginShapeInstantiates proves the shape the reference .wat files
// describe actually loads and performs its granted write.
//
// It builds that shape with wasmgen rather than compiling the .wat, because
// wat2wasm is not available in this environment. The two are kept honest about
// each other by TestReferencePluginsDeclareTheCurrentABI above, which checks the
// .wat declaration against the same ABI table this test exercises.
func TestReferencePluginShapeInstantiates(t *testing.T) {
	ctx := context.Background()
	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })

	outDir := t.TempDir()
	target := filepath.Join(outDir, "deployed.txt")
	guest := wasmgen.Module("cap_write", 4, []byte(target+"deployed"), []wasmgen.Export{
		{Name: "run", Const: 0},
		{Name: "deploy", Args: wasmgen.WriteArgs(target, "deployed")},
	})

	grant := pluginhost.NewGrant(pluginhost.CapFSWrite).
		WithPathPrefix(pluginhost.CapFSWrite, outDir)

	// Conformance first: run() must perform nothing privileged, which is what lets
	// the same module pass admission at zero capabilities.
	if report := h.Conformance(ctx, guest); report.OK() {
		t.Error("the reference shape passed conformance at ZERO capabilities while declaring " +
			"a privileged import; grant-shaped instantiation should have refused it")
	}
	if report := h.ConformanceUnderGrant(ctx, guest, grant); !report.OK() {
		t.Errorf("the reference shape failed conformance under its own grant: %+v", report.Checks)
	}

	p, err := h.Load(ctx, guest, grant)
	if err != nil {
		t.Fatalf("the reference plugin shape does not instantiate: %v", err)
	}
	t.Cleanup(func() { _ = p.Close(ctx) })

	if !p.HasExport("deploy") {
		t.Fatal("the reference connector shape must export deploy()")
	}
	status, err := h.Invoke(ctx, p, "deploy")
	if err != nil {
		t.Fatalf("Invoke deploy: %v", err)
	}
	if status != abiOK {
		t.Fatalf("deploy() returned %d, want %d (ok)", status, abiOK)
	}
	got, err := os.ReadFile(target) // #nosec G304 -- test reads the path it granted (CWE-22)
	if err != nil {
		t.Fatalf("the reference plugin's granted write did not reach the filesystem: %v", err)
	}
	if string(got) != "deployed" {
		t.Errorf("reference plugin wrote %q, want %q", got, "deployed")
	}
}

// TestReferenceHTTPConnectorRunsThroughTheHost (A193) keeps the shipped HTTP
// reference connector honest: its two requests are well-formed, the lengths
// its entry points pass match its data, and the same module shape, built with
// wasmgen because wat2wasm is not a build dependency, deploys through the
// host's HTTP service with the credential asked for by name and the
// certificate and key spliced by reference, and tests read-only.
func TestReferenceHTTPConnectorRunsThroughTheHost(t *testing.T) {
	ctx := context.Background()
	src, err := os.ReadFile("../../plugins/connectors/reference/reference-http-connector.wat")
	if err != nil {
		t.Fatal(err)
	}
	data := regexp.MustCompile(`\(data \(i32\.const (\d+)\) "((?:[^"\\]|\\.)*)"\)`).FindAllStringSubmatch(string(src), -1)
	if len(data) != 2 || data[0][1] != "0" {
		t.Fatalf("the reference connector should hold its deploy request at 0 and its test request after it: %v", data)
	}
	unescape := strings.NewReplacer(`\"`, `"`, `\\`, `\`)
	deployReq, testReq := unescape.Replace(data[0][2]), unescape.Replace(data[1][2])
	if data[1][1] != strconv.Itoa(len(deployReq)) {
		t.Fatalf("the test request starts at %s, want %d", data[1][1], len(deployReq))
	}
	lengths := regexp.MustCompile(`i32\.const (\d+)\s+;; req_len`).FindAllStringSubmatch(string(src), -1)
	if len(lengths) != 2 || lengths[0][1] != strconv.Itoa(len(deployReq)) || lengths[1][1] != strconv.Itoa(len(testReq)) {
		t.Fatalf("the entry points pass request lengths %v, want %d and %d", lengths, len(deployReq), len(testReq))
	}
	for _, req := range []string{deployReq, testReq} {
		var parsed pluginhost.HTTPRequest
		if err := json.Unmarshal([]byte(req), &parsed); err != nil {
			t.Fatalf("reference request %s does not parse: %v", req, err)
		}
	}

	h := pluginhost.New()
	t.Cleanup(func() { _ = h.Close(ctx) })
	grant := pluginhost.NewGrant(pluginhost.CapHTTP).WithPathPrefix(pluginhost.CapHTTP, "appliance.example:443")
	p, err := h.Load(ctx, wasmgen.HTTPGuest(deployReq, testReq), grant)
	if err != nil {
		t.Fatalf("the reference HTTP connector shape does not instantiate: %v", err)
	}
	t.Cleanup(func() { _ = p.Close(ctx) })
	var sent []pluginhost.HTTPRequest
	doer := func(_ context.Context, req pluginhost.HTTPRequest) (pluginhost.HTTPResponse, error) {
		sent = append(sent, req)
		return pluginhost.HTTPResponse{Status: 200, Body: "{}"}, nil
	}
	if status, err := h.InvokeWith(ctx, p, "deploy", pluginhost.Invocation{HTTP: doer}); err != nil || status != abiOK {
		t.Fatalf("deploy() = %d, %v", status, err)
	}
	if status, err := h.InvokeWith(ctx, p, "test", pluginhost.Invocation{HTTP: doer, ReadOnly: true}); err != nil || status != abiOK {
		t.Fatalf("test() under the read-only grant = %d, %v", status, err)
	}
	if len(sent) != 2 || sent[0].Method != "PUT" || sent[0].Auth != "basic" || !strings.Contains(string(sent[0].JSON), `"$input":"private_key_pem"`) ||
		sent[1].Method != "GET" {
		t.Fatalf("the host was asked for %+v", sent)
	}
}
