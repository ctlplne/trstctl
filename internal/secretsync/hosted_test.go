// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/synctarget"
)

// Every hosted target type has an engine vendor and every vendor a type, so
// config can't accept a target the engine can't run (A241).
func TestHostedVendorsMatchTargetTypesA241(t *testing.T) {
	for _, typ := range synctarget.Types() {
		vendor := hostedVendors[typ]
		if vendor == nil || vendor.put == nil || vendor.list == nil || vendor.remove == nil || vendor.headers == nil {
			t.Fatalf("%s has no complete vendor", typ)
		}
		if vendor.readBack != ReadBackReceiptOnly && vendor.read == nil {
			t.Fatalf("%s reads back but has no read", typ)
		}
		if vendor.proof != ProofLocal && vendor.proof != ProofStandIn {
			t.Fatalf("%s proof %q", typ, vendor.proof)
		}
	}
	for typ := range hostedVendors {
		if _, ok := synctarget.Lookup(typ); !ok {
			t.Fatalf("vendor %s has no target type", typ)
		}
	}
	catalog := map[string]ProviderCatalogEntry{}
	for _, entry := range ProviderCatalog() {
		catalog[entry.ID] = entry
	}
	for _, typ := range synctarget.Types() {
		if entry, ok := catalog[typ]; !ok || !entry.ScopedSync || entry.ReadBack == "" || entry.Proof == "" {
			t.Fatalf("catalog row for %s: %+v", typ, entry)
		}
	}
}

// The engine checks the key before any request, filters a listing by
// prefix, refuses a listing over the limit, and a receipt-only target reads
// back presence with no digest.
func TestHostedEngineKeysListingAndReceiptOnlyA241(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]string{
			{"name": "APP_B", "digest": "x"}, {"name": "APP_A", "digest": "y"}, {"name": "OTHER", "digest": "z"},
		}})
	}))
	defer server.Close()
	p, err := NewHostedSyncPusher(HostedSyncConfig{Type: "fly", Endpoint: server.URL, HTTPClient: server.Client(), Token: []byte("t"), Binding: "app-a"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.Push(context.Background(), "db/password", []byte("v")); err == nil || requests.Load() != 0 {
		t.Fatalf("an invalid key was sent: err=%v requests=%d", err, requests.Load())
	}
	keys, err := p.ListKeys(context.Background(), "APP_", 10)
	if err != nil || strings.Join(keys, ",") != "APP_A,APP_B" {
		t.Fatalf("ListKeys = %v %v", keys, err)
	}
	if _, err := p.ListKeys(context.Background(), "", 2); !errors.Is(err, ErrScopedListLimit) {
		t.Fatalf("over the limit: %v", err)
	}
	exists, digest, err := p.ReadDigest(context.Background(), "APP_A")
	if err != nil || !exists || digest != "" || p.ReadsBack() {
		t.Fatalf("receipt-only readback = %v %q %v", exists, digest, err)
	}
	if state, err := p.ReconcileOperation(context.Background(), "APP_A", []byte("v")); err != nil || state != ReceiverStateUnknown {
		t.Fatalf("receipt-only reconcile = %v %v", state, err)
	}
	if _, err := NewHostedSyncPusher(HostedSyncConfig{Type: "fly", Binding: "app-a"}); err == nil {
		t.Fatal("a target without its token was built")
	}
	if _, err := NewHostedSyncPusher(HostedSyncConfig{Type: "fly", Binding: "App A", Token: []byte("t")}); err == nil {
		t.Fatal("a target with a bad binding was built")
	}
}

// A .env variable is written single-quoted, or double-quoted with escapes
// when it holds a single quote, and read back exactly; a line break or an
// interpolation it can't write safely is refused.
func TestDotenvLinesRoundTripA241(t *testing.T) {
	for _, value := range []string{"plain", "with space", `it's`, `back\slash`, `quote"d`, "#hash", `$HOME`, `a'b\c"d`} {
		line, err := dotenvLine("KEY", []byte(value))
		if err != nil {
			t.Fatalf("%q: %v", value, err)
		}
		key, raw := dotenvSplit(line)
		if key != "KEY" || string(dotenvValue(raw)) != value {
			t.Fatalf("%q wrote %s and read back %q", value, line, dotenvValue(raw))
		}
	}
	for _, value := range []string{"two\nlines", "it's ${HOME}"} {
		if _, err := dotenvLine("KEY", []byte(value)); err == nil {
			t.Fatalf("%q was written", value)
		}
	}
	if key, _ := dotenvSplit([]byte("# KEY=commented")); key != "" {
		t.Fatal("a comment has a key")
	}
	if key, raw := dotenvSplit([]byte("export NAME=bare value # note")); key != "NAME" || string(dotenvValue(raw)) != "bare value" {
		t.Fatalf("unquoted value: %q %q", key, dotenvValue(raw))
	}
}
