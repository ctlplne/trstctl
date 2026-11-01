// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	acme "trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/store"
)

// persistTXT answers the standing-record check.
type persistTXT struct {
	mu  sync.Mutex
	txt map[string][]string
}

func (r *persistTXT) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.txt[name]...), nil
}

// P1: with upstream_dns_persist on, the upstream client prefers
// dns-persist-01, publishes the standing record once through the operator's
// consenting DNS-01 provider config (after the CAA check), reuses it while it
// names the authority and this account, and never retracts it.
func TestUpstreamDNSPersistPublishesTheStandingRecordOnce(t *testing.T) {
	ctx := context.Background()
	h := newServedHarness(t, config.Protocols{})
	seedDNS01Config(t, ctx, h, store.ACMEDNS01ProviderConfig{
		Name: "persist", Provider: "manual", Zone: "persist.test",
		AllowedMethods: []string{"dns-01"}, AllowUpstreamDV: true,
	})
	caa := &countingCAAResolver{}
	h.srv.acmeDNS01.caaResolver = caa
	zone := &persistTXT{txt: map[string][]string{}}
	h.srv.acmeDNS01.txtResolvers = []acme.Resolver{zone}

	binding := (&upstreamDVHolder{}).bind("letsencrypt.org", "pebble")
	if got := strings.Join(binding.withPersist(true).persistSolverTypes(h), ","); got != "dns-persist-01,dns-01" {
		t.Fatalf("a persist-enabled authority solves [%s]", got)
	}
	solver := &upstreamACMEDNS01Solver{automation: h.srv.acmeDNS01, log: h.log, caaIssuerDomain: "letsencrypt.org", persist: true}
	const account = "https://ca.example.test/acme/acct/7"
	req := acmekey.ChallengeRequest{
		TenantID: h.tenant, Type: acmekey.ChallengeDNSPersist01, Identifier: "app.persist.test",
		IssuerDomainNames: []string{"ca.example.test"}, AccountURI: account,
	}

	// No standing record: one publish is enqueued (no outbox worker runs
	// here, so the wait gives up after the enqueue), and nothing to retract.
	attemptCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	retract, _ := solver.Solve(attemptCtx, req)
	cancel()
	if retract != nil {
		t.Fatal("a standing record must never be retracted")
	}
	if got := countUpstreamPresentRows(t, ctx, h); got != 1 {
		t.Fatalf("%d publishes for the first order, want 1", got)
	}
	var payload acmeDNS01OutboxPayload
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = $2`,
			h.tenant, destinationACMEDNS01Present).Scan(&raw); err != nil {
			return err
		}
		return json.Unmarshal(raw, &payload)
	}); err != nil {
		t.Fatal(err)
	}
	if payload.RecordName != "_validation-persist.app.persist.test" || payload.Value != "ca.example.test; accounturi="+account {
		t.Fatalf("published %s = %q", payload.RecordName, payload.Value)
	}
	if caa.calls == 0 {
		t.Fatal("the standing record was published without the CAA check")
	}

	// The provider published it: the next order reuses it with no publish.
	zone.txt[payload.RecordName] = []string{payload.Value}
	retract, err := solver.Solve(ctx, req)
	if err != nil || retract != nil {
		t.Fatalf("reusing the standing record: retract=%v err=%v", retract != nil, err)
	}
	if got := countUpstreamPresentRows(t, ctx, h); got != 1 {
		t.Fatalf("%d publishes after a reuse, want 1", got)
	}

	// A wildcard needs a config that allows wildcards.
	wild := req
	wild.Identifier = "*.persist.test"
	if _, err := solver.Solve(ctx, wild); err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("a wildcard standing record without consent: %v", err)
	}
	// Without the flag the authority's dns-persist-01 is not answered.
	plain := &upstreamACMEDNS01Solver{automation: h.srv.acmeDNS01, log: h.log, caaIssuerDomain: "letsencrypt.org"}
	if _, err := plain.Solve(ctx, req); err == nil {
		t.Fatal("dns-persist-01 was answered without upstream_dns_persist")
	}
}

// persistSolverTypes reports what the binding's solver would solve once the
// automation is in place.
func (b *upstreamDVBinding) persistSolverTypes(h *servedHarness) []string {
	return (&upstreamACMEDNS01Solver{automation: h.srv.acmeDNS01, log: h.log, persist: b.persist}).SolvableChallenges()
}
