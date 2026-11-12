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

	// P1-L2: a parent's policy=wildcard record does not stand for a name
	// upstream (whether the authority honors it is its choice): the client
	// still publishes the name's own record.
	zone.txt["_validation-persist.persist.test"] = []string{acme.DNSPersistRecordValue("ca.example.test", account, true)}
	sub := req
	sub.Identifier = "api.persist.test"
	attemptCtx, cancel = context.WithTimeout(ctx, 300*time.Millisecond)
	_, _ = solver.Solve(attemptCtx, sub)
	cancel()
	if got := countUpstreamPresentRows(t, ctx, h); got != 2 {
		t.Fatalf("%d publishes after a name under a parent's policy=wildcard record, want 2", got)
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

// P1-L5: upstream_dns_persist_issuer pins which of the authority's issuer
// domain names the standing record names. Unpinned, a record naming any
// listed name stands and a new one names the first. Pinned, only a record
// naming the pin stands, a new one names it, and a pin the authority does
// not list refuses before anything is published.
func TestUpstreamDNSPersistUsesThePinnedIssuerP1L5(t *testing.T) {
	ctx := context.Background()
	h := newServedHarness(t, config.Protocols{})
	seedDNS01Config(t, ctx, h, store.ACMEDNS01ProviderConfig{
		Name: "persist-pin", Provider: "manual", Zone: "pin.p1l5.test",
		AllowedMethods: []string{"dns-01"}, AllowUpstreamDV: true,
	})
	caa := &countingCAAResolver{}
	h.srv.acmeDNS01.caaResolver = caa
	zone := &persistTXT{txt: map[string][]string{}}
	h.srv.acmeDNS01.txtResolvers = []acme.Resolver{zone}
	holder := &upstreamDVHolder{}
	holder.set(h.srv.acmeDNS01, h.log)

	const account = "https://ca.example.test/acme/acct/9"
	const recordName = "_validation-persist.app.pin.p1l5.test"
	req := acmekey.ChallengeRequest{
		TenantID: h.tenant, Type: acmekey.ChallengeDNSPersist01, Identifier: "app.pin.p1l5.test",
		IssuerDomainNames: []string{"ca1.example.test", "ca2.example.test"}, AccountURI: account,
	}
	published := func() []string {
		t.Helper()
		var values []string
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT convert_from(payload, 'UTF8')::jsonb->>'value' FROM outbox
				WHERE tenant_id = $1 AND destination = $2 AND convert_from(payload, 'UTF8')::jsonb->>'record_name' = $3
				ORDER BY id`, h.tenant, destinationACMEDNS01Present, recordName)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var v string
				if err := rows.Scan(&v); err != nil {
					return err
				}
				values = append(values, v)
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return values
	}
	solve := func(b *upstreamDVBinding) error {
		t.Helper()
		// No outbox worker runs here: a publish is enqueued and the wait
		// gives up after it.
		attemptCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer cancel()
		retract, err := b.Solve(attemptCtx, req)
		if retract != nil {
			t.Fatal("a standing record must never be retracted")
		}
		return err
	}

	// A record naming the first listed name already stands at the name.
	zone.txt[recordName] = []string{acme.DNSPersistRecordValue("ca1.example.test", account, false)}
	if err := solve(holder.bind("letsencrypt.org", "unpinned").withPersist(true)); err != nil {
		t.Fatalf("unpinned reuse: %v", err)
	}
	if got := published(); len(got) != 0 {
		t.Fatalf("unpinned: a listed name's record stands, yet published %q", got)
	}

	// Pinned to the second name: ca1's record does not stand for it, and the
	// new record names ca2 (the pin is read case- and dot-insensitively).
	pinned := holder.bind("letsencrypt.org", "pinned").withPersist(true).withPersistIssuer("CA2.example.test.")
	_ = solve(pinned)
	want := "ca2.example.test; accounturi=" + account
	if got := published(); len(got) != 1 || got[0] != want {
		t.Fatalf("pinned: published %q, want [%q]", got, want)
	}
	// Once the provider has published it, the pinned binding reuses it.
	zone.txt[recordName] = append(zone.txt[recordName], want)
	if err := solve(pinned); err != nil {
		t.Fatalf("pinned reuse: %v", err)
	}
	if got := published(); len(got) != 1 {
		t.Fatalf("pinned reuse published again: %q", got)
	}

	// A pin the authority does not list refuses before the CAA check and
	// before any publish.
	calls := caa.calls
	err := solve(holder.bind("letsencrypt.org", "unlisted").withPersist(true).withPersistIssuer("ca3.example.test"))
	if err == nil || !strings.Contains(err.Error(), `upstream_dns_persist_issuer "ca3.example.test" is not among the issuer domain names the authority lists (ca1.example.test, ca2.example.test)`) {
		t.Fatalf("an unlisted pin: %v", err)
	}
	if got := published(); len(got) != 1 || caa.calls != calls {
		t.Fatalf("an unlisted pin published %q or checked CAA (%d calls)", got, caa.calls-calls)
	}
}
