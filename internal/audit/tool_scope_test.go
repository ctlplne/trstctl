// SPDX-License-Identifier: MPL-2.0
package audit_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventledger"
	"trstctl.com/trstctl/internal/events"
)

// Decode the wire selector so the negative control runs on the old Query too:
// silently ignoring a new selector must fail on results, not just compilation.
func workloadAuditQuery(t *testing.T, tool string) audit.Query {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"tenant_id": tenantA, "tool": tool})
	if err != nil {
		t.Fatal(err)
	}
	var q audit.Query
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	return q
}

func TestAuditToolScopeIncludesAttestationSSHAndWorkloadCertificates(t *testing.T) {
	log := openLog(t)
	want := []string{"workload.attester_trust_source.upserted", "attestation.verified", "attestation.rejected", "attestation.bound", "ephemeral.issued", "ssh.cert.issued", "agent.identity.issued", "broker.agent_identity.task_bound"}
	appendEvent(t, log, tenantA, "owner.created")
	appendEvent(t, log, tenantB, "attestation.verified")
	for _, typ := range want {
		appendEvent(t, log, tenantA, typ)
	}
	for _, source := range []string{"manual-ui", "attested:k8s_sat"} {
		raw, err := json.Marshal(map[string]string{"source": source, "subject": "ssh is not a tool selector"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(t.Context(), events.Event{Type: "certificate.recorded", TenantID: tenantA, Data: raw}); err != nil {
			t.Fatal(err)
		}
	}
	want = append(want, "certificate.recorded")
	svc := newService(t, log)
	q := workloadAuditQuery(t, "workloads_machines")
	recs, err := svc.Search(t.Context(), q)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range recs {
		if r.TenantID != tenantA {
			t.Fatal("tool filter crossed the tenant boundary")
		}
		got = append(got, r.Type)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tool-scoped types = %v, want %v", got, want)
	}
	q.Limit = 2
	limited, err := svc.Search(t.Context(), q)
	if err != nil || len(limited) != 2 || limited[0].Type != want[0] || limited[1].Type != want[1] {
		t.Fatalf("limit applied before tool scope: %+v, %v", limited, err)
	}
	q.Limit = 0
	signed, bundle, err := svc.ExportWithBundle(t.Context(), q)
	if err != nil || signed == "" || len(bundle.Records) != len(want) {
		t.Fatalf("export lost tool scope: count=%d err=%v", len(bundle.Records), err)
	}
	q.Types = []string{"owner.created"}
	if rows, err := svc.Search(t.Context(), q); err != nil || len(rows) != 0 {
		t.Fatalf("disjoint type filter widened tool scope: %d %v", len(rows), err)
	}
	q.Types = nil
	q.Contains = "ssh"
	if rows, err := svc.Search(t.Context(), q); err != nil || len(rows) != 2 {
		t.Fatalf("free text must intersect the tool predicate: %d %v", len(rows), err)
	}
}

func TestAuditToolScopeRejectsUnknownSelector(t *testing.T) {
	log := openLog(t)
	appendEvent(t, log, tenantA, "owner.created")
	svc := newService(t, log)
	for _, tool := range []string{"workload", "ghost", "WORKLOADS_MACHINES"} {
		q := workloadAuditQuery(t, tool)
		if _, err := svc.Search(t.Context(), q); err == nil {
			t.Errorf("unknown tool %q was silently ignored", tool)
		}
		if _, err := svc.Export(t.Context(), q); err == nil {
			t.Errorf("export ignored unknown tool %q", tool)
		}
	}
}

func TestAuditToolScopeRetainsSharedLifecycleMembershipAfterRetention(t *testing.T) {
	log := openLog(t)
	ctx := t.Context()
	appendPayload := func(tenant, typ, payload string) events.Event {
		t.Helper()
		e, err := log.Append(ctx, events.Event{TenantID: tenant, Type: typ, Data: []byte(payload)})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	// The second tenant deliberately uses the same coordinates. Only the first
	// tenant's immutable source/kind may classify its later lifecycle evidence.
	appendPayload(tenantB, "certificate.recorded", `{"id":"other","fingerprint":"ordinary","source":"attested:k8s_sat"}`)
	appendPayload(tenantA, "certificate.recorded", `{"id":"machine-cert","fingerprint":"machine","source":"attested:k8s_sat"}`)
	appendPayload(tenantA, "identity.created", `{"id":"machine-id","kind":"workload_identity"}`)
	prefixEnd := appendPayload(tenantA, "certificate.recorded", `{"id":"regular-cert","fingerprint":"ordinary","source":"manual-ui"}`)
	key, err := jose.GenerateRSASigningKey("tool-scope-retention")
	if err != nil {
		t.Fatal(err)
	}
	cp := &memCheckpoints{}
	svc := audit.NewService(log, key, audit.WithCheckpoints(cp))
	prefix, err := svc.Search(ctx, audit.Query{TenantID: tenantA})
	if err != nil {
		t.Fatal(err)
	}
	seed := prefix[len(prefix)-1].Hash
	if err := cp.SaveAuditCheckpoint(ctx, audit.Checkpoint{TenantID: tenantA, BoundarySeq: prefixEnd.Sequence, BoundaryHash: seed, RecordCount: len(prefix)}); err != nil {
		t.Fatal(err)
	}
	appendPayload(tenantA, "certificate.revoked", `{"fingerprint":"machine"}`)
	appendPayload(tenantA, "identity.revoked", `{"identity_id":"machine-id"}`)
	appendPayload(tenantA, "certificate.revoked", `{"fingerprint":"ordinary"}`)
	q := audit.Query{TenantID: tenantA, Tool: "workloads_machines"}
	rows, gotSeed, err := svc.SearchWithSeed(ctx, q)
	if err != nil || len(rows) != 2 || gotSeed != seed {
		t.Fatalf("retained workload scope: records=%+v seed=%q err=%v", rows, gotSeed, err)
	}
	if rows[0].Type != "certificate.revoked" || rows[1].Type != "identity.revoked" {
		t.Fatalf("wrong shared lifecycle records: %+v", rows)
	}
	if _, err := audit.VerifyChainFrom(seed, rows); err != nil {
		t.Fatalf("tool scope broke retained chain: %v", err)
	}
	q.AsOfSequence = rows[0].Sequence
	if bounded, err := svc.Search(ctx, q); err != nil || len(bounded) != 1 {
		t.Fatalf("as-of must intersect tool membership: %d %v", len(bounded), err)
	}
	q.AsOfSequence = 0
	q.FeatureID, q.Action = "F6", "revoke"
	if filtered, err := svc.Search(ctx, q); err != nil || len(filtered) != 1 || filtered[0].Type != "identity.revoked" {
		t.Fatalf("feature/action must intersect tool membership: %+v %v", filtered, err)
	}
}

func TestAuditToolScopeUsesCanonicalNamespacesNotActorWords(t *testing.T) {
	log := openLog(t)
	cases := []struct{ tool, event string }{
		{"discover", "discovery.scan.completed"}, {"certificates", "certificate.recorded"},
		{"workloads_machines", "attestation.verified"}, {"secrets", "secret.version.written"},
		{"software_trust", "codesign.signed"}, {"operations", "incident.executed"},
		{"platform_integrations", "auth.login"},
	}
	for _, item := range cases {
		if _, err := log.Append(t.Context(), events.Event{TenantID: tenantA, Type: item.event, Data: []byte(`{"subject":"ssh certificate secret login signing incident discovery"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	svc := newService(t, log)
	for _, item := range cases {
		rows, err := svc.Search(t.Context(), audit.Query{TenantID: tenantA, Tool: item.tool})
		if err != nil || len(rows) != 1 || rows[0].Type != item.event {
			t.Errorf("%s membership inferred from words: %+v %v", item.tool, rows, err)
		}
	}
}

func TestAuditToolScopeDoesNotLearnMembershipFromFutureRecords(t *testing.T) {
	log := openLog(t)
	start := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	for i, item := range []struct{ typ, payload string }{
		{"certificate.revoked", `{"fingerprint":"later-discovered"}`},
		{"certificate.recorded", `{"id":"later-cert","fingerprint":"later-discovered","source":"attested:k8s_sat"}`},
	} {
		if _, err := log.Append(t.Context(), events.Event{TenantID: tenantA, Type: item.typ, Data: []byte(item.payload), Time: start.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	svc := newService(t, log)
	for _, q := range []audit.Query{
		{TenantID: tenantA, Tool: "workloads_machines", AsOfSequence: 1},
		{TenantID: tenantA, Tool: "workloads_machines", Until: start.Add(30 * time.Second)},
	} {
		if rows, err := svc.Search(t.Context(), q); err != nil || len(rows) != 0 {
			t.Errorf("point-in-time scope learned from later metadata: %+v %v", rows, err)
		}
	}
	if rows, err := svc.Search(t.Context(), audit.Query{TenantID: tenantA, Tool: "workloads_machines"}); err != nil || len(rows) != 2 {
		t.Fatalf("current scope lost known lifecycle: %+v %v", rows, err)
	}
}

func TestAuditToolScopeIncludesExactSoftwareCampaignLedgerEvents(t *testing.T) {
	log := openLog(t)
	want := []string{
		eventledger.EventPQCMigrationCampaignStarted,
		eventledger.EventPQCMigrationCampaignUpdated,
		eventledger.EventPQCMigrationCampaignFindingDispositioned,
		eventledger.EventPQCMigrationCampaignClosed,
	}
	for _, typ := range want {
		appendEvent(t, log, tenantA, typ)
		appendEvent(t, log, tenantB, typ)
	}
	appendEvent(t, log, tenantA, "owner.created")
	rows, err := newService(t, log).Search(t.Context(), audit.Query{TenantID: tenantA, Tool: "software_trust"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, row := range rows {
		if row.TenantID != tenantA {
			t.Fatal("software campaign selector crossed the tenant boundary")
		}
		got = append(got, row.Type)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("software campaign event scope = %v, want %v", got, want)
	}
}
