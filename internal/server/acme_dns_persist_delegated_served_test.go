// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// P1-L4: a delegated DNS-01 provider config publishes the standing
// dns-persist-01 record through a delegation of its own. With
// persist_delegation_target, _validation-persist.<name> points (CNAME) at
// that target and the record is written there — never at the name itself or
// at the _acme-challenge target. Without it, the record follows the
// _acme-challenge delegation target as before, and a persist name delegated
// anywhere else is refused before anything is written.
func TestServedDelegatedConfigPublishesThePersistRecordAtItsOwnTargetP1L4(t *testing.T) {
	dns := newServedDNSWebhookFixture(t, "p1l4-delegated-token")
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "P1-L4 delegated persist tenant")
	h.srv.acmeDNS01.cnameResolver = dns
	h.srv.acmeDNS01.caaResolver = dns
	h.srv.acmeDNS01.txtResolvers = []acmesrv.Resolver{dns}
	startServedDirectOutboxPump(t, h.srv)
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read", "issuers:write", "secrets:read", "secrets:write")
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", tok, map[string]any{
		"name": "dns/p1l4/bearer-token", "value": "p1l4-delegated-token",
	}); status != http.StatusCreated {
		t.Fatalf("create the DNS bearer secret: status %d body %s", status, body)
	}
	const (
		challengeTarget = "p1l4.auth.acme-dns.example.net"
		persistTarget   = "p1l4-persist.auth.acme-dns.example.net"
		sharedTarget    = "p1l4-shared.auth.acme-dns.example.net"
		elsewhere       = "elsewhere.auth.acme-dns.example.net"
		account         = "https://ca.example.test/acme/acct/14"
	)
	providerConfig := func(name, zone, delegation, persist string) map[string]any {
		body := map[string]any{"name": name, "provider": "webhook", "zone": zone, "delegation_target": delegation,
			"credential_refs": map[string]any{"bearer_token_ref": "secret://dns/p1l4/bearer-token"}, // #nosec G101 -- a secret:// reference, no credential value (CWE-798)
			"config":          map[string]any{"endpoint": dns.URL()}, "allowed_methods": []string{"dns-01"}, "allow_upstream_dv": true}
		if persist != "" {
			body["persist_delegation_target"] = persist
		}
		return body
	}
	for name, body := range map[string]map[string]any{
		"a persist target on a direct config": providerConfig("p1l4-direct", "p1l4-direct.test", "", persistTarget),
		"a persist target that is no name":    providerConfig("p1l4-bad", "p1l4-bad.test", challengeTarget, "not a name!"),
	} {
		if status, raw := secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok, body); status != http.StatusBadRequest {
			t.Fatalf("%s: status %d body %s; want 400", name, status, raw)
		}
	}
	status, raw := secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok,
		providerConfig("p1l4-own", "p1l4.test", challengeTarget, persistTarget+"."))
	var saved struct {
		PersistDelegationTarget string `json:"persist_delegation_target"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &saved) != nil || saved.PersistDelegationTarget != persistTarget {
		t.Fatalf("the config with its own persist target: status %d body %s", status, raw)
	}
	if status, raw := secretsReq(t, h, http.MethodPost, "/api/v1/acme/dns-01/provider-configs", tok,
		providerConfig("p1l4-shared", "p1l4-shared.test", sharedTarget, "")); status != http.StatusCreated {
		t.Fatalf("the config without a persist target: status %d body %s", status, raw)
	}

	solver := &upstreamACMEDNS01Solver{automation: h.srv.acmeDNS01, log: h.log, caaIssuerDomain: "letsencrypt.org", persist: true}
	solve := func(identifier string) error {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		retract, err := solver.Solve(ctx, acmekey.ChallengeRequest{TenantID: h.tenant, Type: acmekey.ChallengeDNSPersist01,
			Identifier: identifier, IssuerDomainNames: []string{"ca.example.test"}, AccountURI: account})
		if retract != nil {
			t.Fatalf("%s: a standing record must never be retracted", identifier)
		}
		return err
	}
	value := acmesrv.DNSPersistRecordValue("ca.example.test", account, false)
	standing := func(name string) bool {
		t.Helper()
		values, _ := dns.LookupTXT(context.Background(), name)
		return containsString(values, value)
	}

	// Its own persist target: written there, nowhere else.
	ownName := acmesrv.DNSPersistRecordName("app.p1l4.test")
	dns.setCNAME(ownName, persistTarget+".")
	if err := solve("app.p1l4.test"); err != nil {
		t.Fatalf("the standing record through its own persist target: %v", err)
	}
	if !standing(ownName) || !standing(persistTarget) {
		t.Fatalf("the standing record is not at %s through %s", persistTarget, ownName)
	}
	dns.assertNeverRequested(t, ownName)
	dns.assertNeverRequested(t, challengeTarget)

	// No persist target: the persist name may follow the _acme-challenge
	// target, as before.
	sharedName := acmesrv.DNSPersistRecordName("app.p1l4-shared.test")
	dns.setCNAME(sharedName, sharedTarget+".")
	if err := solve("app.p1l4-shared.test"); err != nil || !standing(sharedTarget) {
		t.Fatalf("the standing record through the shared target: %v", err)
	}

	// No persist target, and the persist name delegated elsewhere: refused.
	// The delivery fails (the outbox keeps only the redacted category) and
	// writes nothing.
	strayName := acmesrv.DNSPersistRecordName("api.p1l4-shared.test")
	dns.setCNAME(strayName, elsewhere+".")
	if err := solve("api.p1l4-shared.test"); err == nil || !strings.Contains(err.Error(), strayName) {
		t.Fatalf("a persist name delegated elsewhere: %v; want its publish refused", err)
	}
	var lastError string
	if err := h.store.SystemPool().QueryRow(context.Background(),
		`SELECT coalesce(last_error, '') FROM outbox WHERE tenant_id = $1 AND destination = $2 AND convert_from(payload, 'UTF8') LIKE '%' || $3 || '%' ORDER BY id DESC LIMIT 1`,
		h.tenant, destinationACMEDNS01Present, strayName).Scan(&lastError); err != nil || lastError == "" {
		t.Fatalf("the stray publish's delivery error = %q (%v); want its delivery failed", lastError, err)
	}
	dns.assertNeverRequested(t, elsewhere)
	dns.assertNeverRequested(t, strayName)
	t.Logf("P1L4_PERSIST_DELEGATION_OK own=%s shared=%s", persistTarget, sharedTarget)
}
