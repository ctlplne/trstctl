// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

func TestServedPolicyTenantIsolationAndReplicaRecovery(t *testing.T) {
	h := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()}, func(d *Deps) {
		d.EnablePolicyGate = true
		d.DefaultProfile = "tls-server"
	})
	ctx := context.Background()
	const other = "22222222-2222-2222-2222-222222222222"
	owners := map[string]string{}
	tokens := map[string]string{}
	for _, tenant := range []string{h.tenant, other} {
		registerServedTenantID(t, h, tenant, tenant)
		storeServerTestProfile(t, h.store, tenant, "tls-server", profile.CertificateProfile{Name: "tls-server", AllowedEKUs: []string{"serverAuth"}, MaxValidity: profile.Duration(24 * time.Hour), AllowedProtocols: []string{"api"}})
		owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: tenant, Kind: store.OwnerWorkload, Name: "local-service"})
		if err != nil {
			t.Fatal(err)
		}
		owners[tenant] = owner.ID
		tokens[tenant] = seedScopedTokenSubject(t, h.store, tenant, "operator-"+tenant, "policy:read", "policy:write", "owners:write", "identities:write", "certs:issue")
	}
	create := func(tenant, reason string) string {
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/policy/versions", tokens[tenant], "create-"+reason, map[string]any{"module": "package trstctl.policy\ndefault allow := false\ndefault reason := \"" + reason + "\"\nallow if { input.action == \"revoke\" }"})
		if status != http.StatusCreated {
			t.Fatalf("create: %d %s", status, raw)
		}
		var v struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		return v.ID
	}
	act := func(target *servedHarness, tenant, id, action, key string) {
		status, raw := secretsReqKey(t, target, http.MethodPost, "/api/v1/policy/versions/"+id+"/"+action, tokens[tenant], key, map[string]any{"reason": "owned integration test"})
		if status != http.StatusOK {
			t.Fatalf("%s: %d %s", action, status, raw)
		}
	}
	check := func(target *servedHarness, tenant, name, denied string) {
		id := createPolicyActivationIdentity(t, target, tokens[tenant], owners[tenant], name)
		status, raw := transitionPolicyActivationIdentity(t, target, tokens[tenant], id, name+"-issue")
		if denied == "" {
			if status != http.StatusOK {
				t.Errorf("%s should retain its boot policy: %d %s", name, status, raw)
			}
		} else if status != http.StatusForbidden || !bytes.Contains(raw, []byte(denied)) {
			t.Errorf("%s should enforce %q: %d %s", name, denied, status, raw)
		}
	}
	versionA := create(h.tenant, "tenant A freeze")
	versionB := create(other, "tenant B freeze")
	check(h, h.tenant, "draft-a", "")
	check(h, other, "draft-b", "")
	act(h, h.tenant, versionA, "activate", "activate-a")
	check(h, h.tenant, "active-a", "tenant A freeze")
	check(h, other, "unaffected-b", "")

	// A fresh server assembly shares only the durable PostgreSQL/NATS state;
	// no policy pointers or process-local caches are carried over.
	replica, err := Build(ctx, Deps{Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz, CACertFile: h.caFile, KEK: h.kek, EnablePolicyGate: true, DefaultProfile: "tls-server"})
	if err != nil {
		t.Fatal(err)
	}
	cleanupServedServer(t, replica)
	ts := httptest.NewServer(replica.Handler())
	t.Cleanup(ts.Close)
	second := &servedHarness{srv: replica, ts: ts, store: h.store, log: h.log, tenant: h.tenant}
	check(second, h.tenant, "recovered-a", "tenant A freeze")
	check(second, other, "recovered-b", "")
	act(second, other, versionB, "activate", "activate-b")
	check(h, h.tenant, "after-b-a", "tenant A freeze")
	check(h, other, "after-b-b", "tenant B freeze")
	act(h, h.tenant, versionA, "rollback", "rollback-a")
	check(second, h.tenant, "rollback-a", "")
	check(second, other, "rollback-a-keeps-b", "tenant B freeze")
	act(second, other, versionB, "rollback", "rollback-b")
	check(h, other, "rollback-b", "")
	// Simultaneous authors on different replicas must retain the actual immediate
	// predecessor. The final event, readout and both decision engines must agree.
	v1 := create(h.tenant, "concurrent one")
	v2 := create(h.tenant, "concurrent two")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); act(h, h.tenant, v1, "activate", "concurrent-activate-one") }()
	go func() { defer wg.Done(); act(second, h.tenant, v2, "activate", "concurrent-activate-two") }()
	wg.Wait()
	statusA, rawA := secretsReq(t, h, http.MethodGet, "/api/v1/policy/versions", tokens[h.tenant], nil)
	var state struct {
		Active struct {
			ID string `json:"id"`
		} `json:"active"`
	}
	if statusA != http.StatusOK || json.Unmarshal(rawA, &state) != nil {
		t.Fatalf("active read: %d %s", statusA, rawA)
	}
	reasons := map[string]string{v1: "concurrent one", v2: "concurrent two"}
	if reasons[state.Active.ID] == "" {
		t.Fatalf("unexpected active version: %s", rawA)
	}
	check(h, h.tenant, "concurrent-original", reasons[state.Active.ID])
	check(second, h.tenant, "concurrent-replica", reasons[state.Active.ID])
	predecessor := v1
	if state.Active.ID == v1 {
		predecessor = v2
	}
	act(second, h.tenant, state.Active.ID, "rollback", "concurrent-rollback")
	check(h, h.tenant, "concurrent-predecessor", reasons[predecessor])

	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/policy/versions", tokens[other], nil)
	if status != http.StatusOK || bytes.Contains(raw, []byte(versionA)) || bytes.Contains(raw, []byte("tenant A freeze")) {
		t.Fatalf("B policy history leaked A: %d %s", status, raw)
	}
}
