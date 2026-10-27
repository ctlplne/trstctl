// SPDX-License-Identifier: BUSL-1.1

package pluginhost_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/pluginhost/wasmgen"
)

// A193: a plugin's HTTP calls are made by the host, only to the authorities
// its grant names, only within a call the host gave an HTTP service, and the
// test entry point runs read-only: a request that would change the target is
// refused as a grant denial before anything is sent. A plugin reads the inputs
// the call carries, and nothing else.
func TestPluginHTTPCallsAreMadeByTheHostUnderTheGrant(t *testing.T) {
	ctx := context.Background()
	host := pluginhost.New()
	t.Cleanup(func() { _ = host.Close(ctx) })
	const deployReq = `{"method":"PUT","url":"https://appliance.test/api/certs/edge","auth":"basic","json":{"key":{"$input":"private_key_pem"}}}`
	const writingTest = `{"method":"POST","url":"https://appliance.test/api/certs/check"}`
	grant := pluginhost.NewGrant(pluginhost.CapHTTP).WithPathPrefix(pluginhost.CapHTTP, "appliance.test:443")
	plugin, err := host.Load(ctx, wasmgen.HTTPGuest(deployReq, writingTest), grant)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plugin.Close(ctx) })

	var mu sync.Mutex
	var sent []pluginhost.HTTPRequest
	doer := func(_ context.Context, req pluginhost.HTTPRequest) (pluginhost.HTTPResponse, error) {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, req)
		return pluginhost.HTTPResponse{Status: 204}, nil
	}
	rc, err := host.InvokeWith(ctx, plugin, "deploy", pluginhost.Invocation{HTTP: doer})
	if err != nil || rc != 0 || len(sent) != 1 {
		t.Fatalf("deploy = %d, %v; sent %+v", rc, err, sent)
	}
	var body map[string]map[string]string
	if sent[0].Method != "PUT" || sent[0].Auth != "basic" || json.Unmarshal(sent[0].JSON, &body) != nil || body["key"]["$input"] != "private_key_pem" {
		t.Fatalf("the host did not pass the request through as asked: %+v", sent[0])
	}
	if plugin.Stats().Requests != 1 {
		t.Fatalf("requests counted = %d", plugin.Stats().Requests)
	}

	denied := plugin.Stats().Denied
	rc, err = host.InvokeWith(ctx, plugin, "test", pluginhost.Invocation{HTTP: doer, ReadOnly: true})
	if err != nil || rc != 1 || len(sent) != 1 || plugin.Stats().Denied != denied+1 {
		t.Fatalf("read-only POST = %d, %v; sent %d, denied %d→%d", rc, err, len(sent), denied, plugin.Stats().Denied)
	}
	if rc, err := host.Invoke(ctx, plugin, "deploy"); err != nil || rc != 2 || len(sent) != 1 {
		t.Fatalf("a call with no HTTP service = %d, %v", rc, err)
	}

	elsewhere, err := host.Load(ctx, wasmgen.HTTPGuest(strings.Replace(deployReq, "appliance.test", "elsewhere.test", 1), ""), grant)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = elsewhere.Close(ctx) })
	if rc, err := host.InvokeWith(ctx, elsewhere, "deploy", pluginhost.Invocation{HTTP: doer}); err != nil || rc != 1 || len(sent) != 1 {
		t.Fatalf("a request outside the grant = %d, %v", rc, err)
	}
	if _, err := host.Load(ctx, wasmgen.HTTPGuest(deployReq, ""), pluginhost.NewGrant(pluginhost.CapNetDial)); err == nil {
		t.Fatal("a plugin importing cap_http loaded without the net.http grant")
	}

	reader, err := host.Load(ctx, wasmgen.InputGuest("certificate_pem", "deploy"), pluginhost.NewGrant(pluginhost.CapInputRead))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(ctx) })
	inputs := pluginhost.Invocation{Inputs: map[string][]byte{"certificate_pem": []byte("-----BEGIN CERTIFICATE-----")}}
	if rc, err := host.InvokeWith(ctx, reader, "deploy", inputs); err != nil || rc != 0 {
		t.Fatalf("reading a carried input = %d, %v", rc, err)
	}
	if rc, err := host.InvokeWith(ctx, reader, "deploy", pluginhost.Invocation{Inputs: map[string][]byte{"private_key_pem": []byte("k")}}); err != nil || rc != 2 {
		t.Fatalf("reading an input the call does not carry = %d, %v", rc, err)
	}
}
