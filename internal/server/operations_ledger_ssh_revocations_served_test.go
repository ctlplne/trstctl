// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/sshkrlreceipt"
)

type servedSSHRevocationRow struct {
	ID             string `json:"id"`
	Source         string `json:"source"`
	CredentialType string `json:"credential_type"`
	State          string `json:"state"`
	StateReason    string `json:"state_reason"`
	SourceStatus   string `json:"source_status"`
	Subject        struct {
		Name string `json:"name"`
	} `json:"subject"`
}

// A245-L1 Done-when (served, part 2): the operations ledger lists each SSH
// certificate revocation, delivered once the served KRL lists it and verified
// only when every host agent that reports its KRL enforces a list at or past
// the version that first listed it. A revocation by key ID never shows the key
// ID; a caller without certs:read does not see the rows; a projection rebuild
// and a replayed KRL reproduce them.
func TestServedOperationsLedgerShowsSSHRevocationsAndHostAdoptionA245L1(t *testing.T) {
	ctx := t.Context()
	h := newServedHarnessWithEventOptions(t, config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		[]events.OpenOption{events.WithRequiredPrivacyEventPolicies()}, withAgentChannel)
	registerServedTenant(t, h, "A245-L1 SSH revocations tenant")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	operator := seedScopedToken(t, h.store, h.tenant, "certs:write", "certs:read", "lifecycle:read")
	lifecycleOnly := seedScopedToken(t, h.store, h.tenant, "lifecycle:read")
	const departedLaptop = "a245l1-departed-laptop"

	ledger := func(tok string) []servedSSHRevocationRow {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/operations/ledger?limit=100", tok, nil)
		var body struct {
			Items []servedSSHRevocationRow `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &body) != nil {
			t.Fatalf("ledger: HTTP %d %s", status, raw)
		}
		if bytes.Contains(raw, []byte(departedLaptop)) {
			t.Fatalf("the ledger shows a revoked key ID: %s", raw)
		}
		var out []servedSSHRevocationRow
		for _, item := range body.Items {
			if item.Source == "ssh_certificate_revocation" {
				out = append(out, item)
			}
		}
		return out
	}
	// The harness runs no projection tail; each read catches up first, as the
	// server's tail does after an append.
	row := func(name string) servedSSHRevocationRow {
		t.Helper()
		if err := h.srv.proj.ProjectCatchUp(ctx, h.log); err != nil {
			t.Fatalf("project: %v", err)
		}
		for _, r := range ledger(operator) {
			if r.Subject.Name == name {
				return r
			}
		}
		t.Fatalf("no ledger row for %q", name)
		return servedSSHRevocationRow{}
	}
	revoke := func(key string, body map[string]any) {
		t.Helper()
		if status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/certificates/revoke", operator, key, body); status != http.StatusOK {
			t.Fatalf("revoke %v: HTTP %d %s", body, status, raw)
		}
	}

	revoke("a245l1-revoke-serial", map[string]any{"serial": 245001, "reason": "the build host was retired"})
	first := row("serial 245001")
	if first.State != "delivered" || first.SourceStatus != "revoked" || first.CredentialType != "ssh_certificate" ||
		!strings.Contains(first.StateReason, "listed in the served KRL from version 1") ||
		!strings.Contains(first.StateReason, "no host agent reports") {
		t.Fatalf("before any host reports, the revocation reads %+v", first)
	}

	// A host that installed the served list enforces the revocation.
	host := enrollKRLAgent(t, h, ln.Addr().String(), "a245l1-edge", []string{mtls.AgentRoleHost})
	report := func(installed uint64) {
		t.Helper()
		served := servedKRL(t, h)
		now := time.Now().UTC().Unix()
		receipt := sshkrlreceipt.Receipt{KRLTenantID: h.tenant, InstalledVersion: installed, InstalledSHA256: crypto.SHA256Hex(served),
			Outcome: sshkrlreceipt.OutcomeInstalled, FetchedVersion: installed, FetchedSHA256: crypto.SHA256Hex(served),
			CheckedAtUnix: now, InstalledAtUnix: now, PollEverySeconds: 30}
		if err := host.report(t, h.tenant, receipt); err != nil {
			t.Fatalf("host receipt: %v", err)
		}
	}
	report(1)
	if got := row("serial 245001"); got.State != "verified" || !strings.Contains(got.StateReason, "every reporting host (1) enforces a KRL that lists it") {
		t.Fatalf("after the host installed version 1, the revocation reads %+v", got)
	}

	// A later revocation by key ID is listed from version 2; the host still
	// enforces version 1, so it is delivered, not verified, and the first
	// revocation stays verified.
	revoke("a245l1-revoke-key", map[string]any{"key_id": departedLaptop})
	second := row("a key ID")
	if second.State != "delivered" || !strings.Contains(second.StateReason, "listed in the served KRL from version 2") ||
		!strings.Contains(second.StateReason, "0 of 1 reporting hosts") {
		t.Fatalf("a revocation the host has not installed reads %+v", second)
	}
	if got := row("serial 245001"); got.State != "verified" {
		t.Fatalf("an older revocation stopped reading verified: %+v", got)
	}
	report(2)
	if got := row("a key ID"); got.State != "verified" {
		t.Fatalf("after the host installed version 2, the key ID revocation reads %+v", got)
	}

	// The detail names who revoked it; a caller without certs:read sees none.
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/operations/ledger/"+url.PathEscape(first.ID), operator, nil)
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"revoked by `)) || !bytes.Contains(raw, []byte("the build host was retired")) {
		t.Fatalf("detail: HTTP %d %s", status, raw)
	}
	if rows := ledger(lifecycleOnly); len(rows) != 0 {
		t.Fatalf("a caller without certs:read sees %+v", rows)
	}
	if status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/operations/ledger/"+url.PathEscape(first.ID), lifecycleOnly, nil); status != http.StatusNotFound {
		t.Fatalf("detail without certs:read: HTTP %d %s", status, raw)
	}

	// Replay: a projection rebuild yields the same rows, and a KRL rebuilt
	// from the log lists each revocation from the same version.
	before := ledger(operator)
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatalf("rebuild projections: %v", err)
	}
	after := ledger(operator)
	if len(after) != 2 || len(before) != 2 || after[0] != before[0] || after[1] != before[1] {
		t.Fatalf("rebuilt rows differ:\n before %+v\n after  %+v", before, after)
	}
	sp, err := h.srv.sshWorkflowProtocol(h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{strings.TrimPrefix(first.ID, "ssh_certificate_revocation:"), strings.TrimPrefix(second.ID, "ssh_certificate_revocation:")}
	live := sp.revocationsListedIn(ids)
	replayed, err := newSSHProtocol(sp.ca, h.tenant, sp.guard, sp.workflow)
	if err != nil {
		t.Fatal(err)
	}
	if err := replayed.restoreRevocations(ctx, h.log); err != nil {
		t.Fatalf("replay revocations: %v", err)
	}
	if got := replayed.revocationsListedIn(ids); len(got) != 2 || got[ids[0]] != live[ids[0]] || got[ids[1]] != live[ids[1]] || live[ids[0]] != 1 || live[ids[1]] != 2 {
		t.Fatalf("listed versions after replay = %v; live %v", got, live)
	}
	t.Logf("A245L1_SSH_REVOCATIONS_OK first=%s second=%s", first.ID, second.ID)
}
