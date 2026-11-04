// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/discovery/lbtls/awselb/elbv2test"
	"trstctl.com/trstctl/internal/discovery/lbtls/bigip/bigiptest"
)

// TestServedListenerPolicyAllowingTLS10RaisesOneFindingX4 is X4 part 2,
// through a load_balancer_tls source configured as an operator configures one,
// against an ELBv2 stand-in (LocalStack's community image has none) and a
// BIG-IP iControl REST stand-in: each TLS listener appears with the policy it
// enforces and the versions it allows, and each listener whose policy allows
// TLS 1.0 is exactly one weak TLSv1.0 finding in the crypto inventory — the
// others one acceptable finding each. A second run raises no second finding;
// tightening a policy replaces the weak finding; neither appliance is changed;
// another tenant sees none of it.
func TestServedListenerPolicyAllowingTLS10RaisesOneFindingX4(t *testing.T) {
	const (
		elbKey, elbSecret = "AKIAX4ELBSERVED", "x4-elb-served-secret" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
		f5User, f5Pass    = "x4-auditor", "x4-auditor-password"       // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
		legacyARN         = "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/app/web/1/legacy"
		modernARN         = "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/net/edge/2/modern"
	)
	elb := elbv2test.New("us-east-1", elbKey, elbSecret)
	t.Cleanup(elb.Close)
	elb.Seed(
		[]elbv2test.LoadBalancer{
			{ARN: "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/1", Name: "web", Type: "application"},
			{ARN: "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/edge/2", Name: "edge", Type: "network"},
		},
		[]elbv2test.Listener{
			{ARN: legacyARN, LoadBalancerARN: "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/1", Protocol: "HTTPS", Port: 443, SslPolicy: "ELBSecurityPolicy-TLS-1-0-2015-04"},
			{ARN: modernARN, LoadBalancerARN: "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/edge/2", Protocol: "TLS", Port: 8443, SslPolicy: "ELBSecurityPolicy-TLS13-1-2-2021-06"},
		},
		[]elbv2test.Policy{
			{Name: "ELBSecurityPolicy-TLS-1-0-2015-04", Protocols: []string{"TLSv1", "TLSv1.1", "TLSv1.2"}, Ciphers: []string{"ECDHE-RSA-AES128-GCM-SHA256", "AES128-SHA"}},
			{Name: "ELBSecurityPolicy-TLS13-1-2-2021-06", Protocols: []string{"TLSv1.2", "TLSv1.3"}, Ciphers: []string{"TLS_AES_128_GCM_SHA256"}},
		},
	)
	f5 := bigiptest.New(f5User, f5Pass, "")
	t.Cleanup(f5.Close)
	f5.Seed(
		[]bigiptest.Profile{
			{FullPath: "/Common/clientssl-legacy", TMOptions: "{ dont-insert-empty-fragments no-tlsv1.3 }", Ciphers: "DEFAULT"},
			{FullPath: "/Common/clientssl-modern", TMOptions: "{ dont-insert-empty-fragments no-tlsv1 no-tlsv1.1 }", Ciphers: "ECDHE+AES-GCM"},
		},
		[]bigiptest.Virtual{
			{FullPath: "/Common/vs_portal", Destination: "/Common/10.0.0.10:443", Profiles: []string{"/Common/http", "/Common/clientssl-legacy"}},
			{FullPath: "/Common/vs_api", Destination: "/Common/10.0.0.11:443", Profiles: []string{"/Common/clientssl-modern"}},
		},
	)
	t.Setenv("TRSTCTL_X4_ELB_ACCESS_KEY_ID", elbKey)
	t.Setenv("TRSTCTL_X4_ELB_SECRET_ACCESS_KEY", elbSecret)
	t.Setenv("TRSTCTL_X4_F5_USER", f5User)
	t.Setenv("TRSTCTL_X4_F5_PASSWORD", f5Pass)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs(
		"env:TRSTCTL_X4_ELB_ACCESS_KEY_ID", "env:TRSTCTL_X4_ELB_SECRET_ACCESS_KEY", "env:TRSTCTL_X4_F5_USER", "env:TRSTCTL_X4_F5_PASSWORD"))
	ctx := t.Context()
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "risk:read", string(authz.PrivateEgress))
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, map[string]any{
		"name": "edge-tls-policies", "kind": "load_balancer_tls", "config": map[string]any{"providers": []map[string]any{ // #nosec G101 -- credential references only; no credential value enters the config (CWE-798)
			{"provider": "aws-elbv2", "region": "us-east-1", "endpoint": elb.URL(), "allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, elb.URL())}, // #nosec G101 -- credential references only; no credential value enters the config (CWE-798)
				"access_key_id_ref": "env:TRSTCTL_X4_ELB_ACCESS_KEY_ID", "secret_access_key_ref": "env:TRSTCTL_X4_ELB_SECRET_ACCESS_KEY"},
			{"provider": "f5-bigip", "endpoint": f5.URL(), "allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, f5.URL())}, // #nosec G101 -- credential references only; no credential value enters the config (CWE-798)
				"username_ref": "env:TRSTCTL_X4_F5_USER", "password_ref": "env:TRSTCTL_X4_F5_PASSWORD"},
		}},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create load_balancer_tls source: %d %s", status, body)
	}
	f5Host := strings.TrimPrefix(f5.URL(), "http://")
	portal, api := "f5-bigip://"+f5Host+"/Common/vs_portal@/Common/clientssl-legacy", "f5-bigip://"+f5Host+"/Common/vs_api@/Common/clientssl-modern"

	type finding struct {
		Kind      string         `json:"kind"`
		Ref       string         `json:"ref"`
		RiskScore int            `json:"risk_score"`
		Metadata  map[string]any `json:"metadata"`
	}
	run := func(key string) map[string]finding {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", writer, key, map[string]any{"source_id": source.ID})
		var queued struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &queued) != nil || queued.ID == "" {
			t.Fatalf("queue %s: %d %s", key, status, body)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatalf("drain %s: %v", key, err)
		}
		r, err := h.store.GetDiscoveryRun(ctx, h.tenant, queued.ID)
		if err != nil || r.Status != "succeeded" || r.Targets != 2 || r.Discovered != 4 {
			t.Fatalf("%s run = %+v %v", key, r, err)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, writer, nil)
		var listed struct {
			Items []finding `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil || len(listed.Items) != 4 {
			t.Fatalf("%s findings = %d %s", key, status, body)
		}
		out := map[string]finding{}
		for _, f := range listed.Items {
			if f.Kind != "tls_listener_policy" {
				t.Fatalf("finding kind = %+v", f)
			}
			out[f.Ref] = f
		}
		return out
	}
	// inventory returns the crypto-inventory facts at each listener.
	inventory := func(token string) map[string][]map[string]any {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", token, nil)
		var inv struct {
			Items []map[string]any `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &inv) != nil {
			t.Fatalf("CBOM assets = %d %s", status, body)
		}
		out := map[string][]map[string]any{}
		for _, a := range inv.Items {
			loc, _ := a["location"].(string)
			out[loc] = append(out[loc], a)
		}
		return out
	}
	expectOne := func(inv map[string][]map[string]any, location, protocol, strength string, outOfPolicy bool) {
		t.Helper()
		got := inv[location]
		if len(got) != 1 || got[0]["kind"] != "host-config" || got[0]["protocol"] != protocol || got[0]["strength"] != strength || got[0]["out_of_policy"] != outOfPolicy {
			t.Fatalf("inventory at %s = %v, want one %s %s finding", location, got, protocol, strength)
		}
	}

	first := run("x4-lb-1")
	for ref, want := range map[string]struct {
		lowest string
		tls10  bool
		risk   int
	}{legacyARN: {"TLSv1.0", true, 70}, modernARN: {"TLSv1.2", false, 10}, portal: {"TLSv1.0", true, 70}, api: {"TLSv1.2", false, 10}} {
		f, ok := first[ref]
		if !ok || f.Metadata["lowest_protocol"] != want.lowest || f.Metadata["allows_tls10"] != want.tls10 || f.RiskScore != want.risk {
			t.Fatalf("listener %s = %+v, want %+v", ref, f, want)
		}
	}
	if p := first[legacyARN]; p.Metadata["policy"] != "ELBSecurityPolicy-TLS-1-0-2015-04" || p.Metadata["load_balancer"] != "web" || p.Metadata["port"] != float64(443) || p.Metadata["region"] != "us-east-1" {
		t.Fatalf("ELB listener metadata = %v", p.Metadata)
	}
	if p := first[portal]; p.Metadata["policy"] != "/Common/clientssl-legacy" || p.Metadata["host"] != f5Host {
		t.Fatalf("BIG-IP listener metadata = %v", p.Metadata)
	}
	inv := inventory(writer)
	expectOne(inv, legacyARN, "TLSv1.0", "weak", true)
	expectOne(inv, portal, "TLSv1.0", "weak", true)
	expectOne(inv, modernARN, "TLSv1.2", "acceptable", false)
	expectOne(inv, api, "TLSv1.2", "acceptable", false)

	// The same listeners again: still one finding each.
	run("x4-lb-2")
	inv = inventory(writer)
	expectOne(inv, legacyARN, "TLSv1.0", "weak", true)
	expectOne(inv, portal, "TLSv1.0", "weak", true)

	// The operator tightens both legacy policies: the weak findings are replaced.
	elb.SetPolicy(legacyARN, "ELBSecurityPolicy-TLS13-1-2-2021-06")
	f5.SetOptions("/Common/clientssl-legacy", "{ dont-insert-empty-fragments no-tlsv1 no-tlsv1.1 }")
	third := run("x4-lb-3")
	if third[legacyARN].Metadata["allows_tls10"] != false || third[portal].Metadata["allows_tls10"] != false {
		t.Fatalf("tightened listeners still allow TLS 1.0: %v %v", third[legacyARN].Metadata, third[portal].Metadata)
	}
	inv = inventory(writer)
	expectOne(inv, legacyARN, "TLSv1.2", "acceptable", false)
	expectOne(inv, portal, "TLSv1.2", "acceptable", false)

	if elb.NonDescribeCalls() != 0 || elb.Refused() != 0 || f5.Mutations() != 0 || f5.Refused() != 0 {
		t.Fatalf("elb non-describe=%d refused=%d, bigip mutations=%d refused=%d", elb.NonDescribeCalls(), elb.Refused(), f5.Mutations(), f5.Refused())
	}

	other := uuid.NewString()
	registerServedTenantID(t, h, other, "X4 listener isolation tenant")
	otherToken := seedScopedToken(t, h.store, other, "discovery:read", "risk:read")
	if got := inventory(otherToken); len(got[legacyARN]) != 0 || len(got[portal]) != 0 {
		t.Fatalf("another tenant read X4 inventory: %v", got)
	}
	for _, path := range []string{"/api/v1/discovery/sources", "/api/v1/discovery/findings?source_id=" + source.ID} {
		status, body := secretsReq(t, h, http.MethodGet, path, otherToken, nil)
		if bytes.Contains(body, []byte(legacyARN)) || bytes.Contains(body, []byte(source.ID)) {
			t.Fatalf("another tenant read X4 data at %s: %d %s", path, status, body)
		}
	}
}
