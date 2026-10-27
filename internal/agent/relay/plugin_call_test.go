// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/pluginhost/wasmgen"
)

// A193: a signed third-party connector deploys a certificate to an appliance
// as its administrator without ever holding the administrator's password or
// the certificate's private key. The relay reads the module's request, splices
// the key into the body by reference, adds the redeemed credential as Basic
// auth, and removes the password from the appliance's reply before the module
// reads it. The module's test entry point runs read-only: a GET runs, and a
// test that would change the appliance is refused before anything is sent.
func TestAReferencePluginDeploysWithHostInjectedAuthAndTestsReadOnly(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	var seen []*http.Request
	var bodies []string
	appliance := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.Clone(context.Background()))
		bodies = append(bodies, string(body))
		mu.Unlock()
		user, password, ok := r.BasicAuth()
		if !ok || user != "admin" || password != appliancePassword {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// An appliance that echoes the credential it received.
		_, _ = w.Write([]byte(`{"status":"stored","login":"admin:` + appliancePassword + `"}`))
	}))
	t.Cleanup(appliance.Close)
	host := strings.TrimPrefix(appliance.URL, "https://")

	deployReq := `{"method":"PUT","url":"` + appliance.URL + `/api/certs/edge","auth":"basic",` +
		`"json":{"cert":{"$input":"certificate_pem"},"key":{"$input":"private_key_pem"}}}`
	readTest := `{"method":"GET","url":"` + appliance.URL + `/api/certs/edge","auth":"basic"}`
	writeTest := `{"method":"PUT","url":"` + appliance.URL + `/api/certs/edge","auth":"basic","body":"x"}`
	grant := pluginhost.NewGrant(pluginhost.CapHTTP).WithPathPrefix(pluginhost.CapHTTP, host)

	load := func(module []byte) *relay.PluginRuntime {
		t.Helper()
		dir, keyPEM, _ := signedPluginDir(t, "partner-lb", module)
		rt, err := relay.NewPluginRuntime(ctx, relay.PluginConfig{Dir: dir, TrustedKeyPEMs: [][]byte{keyPEM}, Grant: grant})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = rt.Close(ctx) })
		return rt
	}
	targetConfig, err := json.Marshal(map[string]string{"username": "admin", "password_ref": "secret://lb-admin"}) // #nosec G101 -- a reference name (CWE-798)
	if err != nil {
		t.Fatal(err)
	}
	call := relay.PluginCall{
		Intent: relay.DeployIntent{Connector: "partner-lb", Target: "edge-lb", Fingerprint: "ff00", TargetConfig: targetConfig},
		Material: relay.Material{
			"credential.cert_pem": []byte(testCertPEM),
			"credential.key_pem":  []byte(testKeyPEM),
			"secret://lb-admin":   []byte(appliancePassword),
		},
		Client: appliance.Client(),
	}

	rt := load(wasmgen.HTTPGuest(deployReq, readTest))
	if err := rt.Deploy(ctx, "partner-lb", call); err != nil {
		t.Fatalf("deploy with host-injected auth: %v", err)
	}
	if len(seen) != 1 || seen[0].Method != http.MethodPut || !strings.Contains(bodies[0], "BEGIN PRIVATE KEY") || !strings.Contains(bodies[0], "BEGIN CERTIFICATE") {
		t.Fatalf("the appliance did not receive the certificate and key as asked: %d requests", len(seen))
	}
	if err := rt.Test(ctx, "partner-lb", call); err != nil || len(seen) != 2 || seen[1].Method != http.MethodGet {
		t.Fatalf("read-only test = %v after %d requests", err, len(seen))
	}

	// What the module reads back: the appliance echoed the password, the
	// relay removed it.
	resp, err := relay.PluginHTTPDoerForTest(call)(ctx, pluginhost.HTTPRequest{Method: "GET", URL: appliance.URL + "/api/certs/edge", Auth: "basic"})
	if err != nil || resp.Status != http.StatusOK || strings.Contains(resp.Body, appliancePassword) || !strings.Contains(resp.Body, "[redacted]") {
		t.Fatalf("response handed to the module = %+v, %v", resp, err)
	}
	if _, err := relay.PluginHTTPDoerForTest(call)(ctx, pluginhost.HTTPRequest{Method: "GET", URL: appliance.URL, Headers: map[string]string{"authorization": "Basic x"}}); err == nil {
		t.Fatal("a module set its own Authorization header")
	}

	writer := load(wasmgen.HTTPGuest(deployReq, writeTest))
	before := len(seen)
	if err := writer.Test(ctx, "partner-lb", call); err == nil || !strings.Contains(err.Error(), "outside its capability grant") || len(seen) != before {
		t.Fatalf("a test that writes = %v, %d requests sent", err, len(seen)-before)
	}
	untested := load(wasmgen.HTTPGuest(deployReq, ""))
	if err := untested.Test(ctx, "partner-lb", call); err == nil || !strings.Contains(err.Error(), "no test entry point") {
		t.Fatalf("a module without a test entry point = %v", err)
	}
}
