// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// A57: the DNS-01 preflight reads the challenge record from live DNS when the
// caller supplies no observation. An unpublished record fails the check, the
// published value passes it, the response says the values came from live DNS,
// and a caller-supplied observation is still accepted and labeled as such.
func TestServedDNS01PreflightReadsLiveTXT(t *testing.T) {
	dns := newServedDNSWebhookFixture(t, "live-txt-token")
	dns.setCAA("live.test", []acmesrv.CAARecord{{Tag: "issue", Value: "trstctl.example"}})
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithACMEDNS01CAAResolver(dns), api.WithACMEDNS01TXTResolver(dns))
	})
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, map[string]any{
		"name": "live-cloudflare", "provider": "cloudflare", "zone": "live.test",
		"credential_refs": map[string]any{ // #nosec G101 -- fabricated fixture reference, no value is real (CWE-798)
			"api_token_ref": "secret://dns/cloudflare/live-token",
		},
		"config":            map[string]any{"zone_id": "zone-live"},
		"caa_issuer_domain": "trstctl.example",
		"allowed_methods":   []string{"dns-01"},
		"allow_wildcards":   true,
	})
	if status != http.StatusCreated {
		t.Fatalf("create provider config = %d %s", status, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &created)

	preflight := func(body map[string]any) (bool, []string, map[string]any) {
		t.Helper()
		body["config_id"] = created.ID
		status, raw := secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/preflight", tok, body)
		if status != http.StatusOK {
			t.Fatalf("preflight = %d %s", status, raw)
		}
		var res struct {
			Ready          bool           `json:"ready"`
			FailedChecks   []string       `json:"failed_checks"`
			TXTObservation map[string]any `json:"txt_observation"`
		}
		if err := json.Unmarshal(raw, &res); err != nil {
			t.Fatal(err)
		}
		return res.Ready, res.FailedChecks, res.TXTObservation
	}

	// Nothing published yet: live DNS answers nothing, the check fails closed.
	ready, failed, obs := preflight(map[string]any{"domain": "www.live.test", "expected_txt": "proof-1"})
	if ready || !containsString(failed, "txt_propagation") || obs["source"] != "live_dns" || obs["record_name"] != "_acme-challenge.www.live.test" {
		t.Fatalf("unpublished record: ready=%v failed=%v observation=%v", ready, failed, obs)
	}
	// Published: live DNS carries the value, the check passes and says so.
	dns.setTXT("_acme-challenge.www.live.test", "proof-1")
	ready, failed, obs = preflight(map[string]any{"domain": "www.live.test", "expected_txt": "proof-1"})
	if !ready || len(failed) != 0 || obs["source"] != "live_dns" {
		t.Fatalf("published record: ready=%v failed=%v observation=%v", ready, failed, obs)
	}
	observed, _ := obs["observed"].([]any)
	if len(observed) != 1 || observed[0] != "proof-1" {
		t.Fatalf("observation did not carry the live value: %v", obs)
	}
	// A caller-supplied observation is used as given and labeled, even when
	// live DNS says otherwise, so an operator can tell the two apart.
	ready, _, obs = preflight(map[string]any{"domain": "www.live.test", "expected_txt": "proof-2", "observed_txt": []string{"proof-2"}})
	if !ready || obs["source"] != "caller_supplied" {
		t.Fatalf("caller-supplied observation: ready=%v observation=%v", ready, obs)
	}
	// Without an expected value nothing is looked up.
	_, _, obs = preflight(map[string]any{"domain": "www.live.test"})
	if obs["source"] != "none" {
		t.Fatalf("no expected value must not trigger a lookup: %v", obs)
	}
}
