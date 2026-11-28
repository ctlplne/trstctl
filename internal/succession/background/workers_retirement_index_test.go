// SPDX-License-Identifier: BUSL-1.1

package background

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/eventstest"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/retirement"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

func TestRetirementWorkerUsesTenantBoundPredecessorForLegacyBlankPolicy(t *testing.T) {
	policy := pcasstore.RetirementPolicy{IdentityID: "spiffe://qa.local/db", PredecessorEpoch: 0}
	want := succession.TenantKeyHandle("tenant-a", policy.IdentityID, 0)
	handle, err := retirementPredecessorHandle("tenant-a", policy)
	if err != nil || handle != want {
		t.Fatalf("blank legacy policy resolved to %q, err=%v; want %q", handle, err, want)
	}
	policy.PredecessorHandle = succession.TenantKeyHandle("tenant-b", policy.IdentityID, 0)
	if _, err := retirementPredecessorHandle("tenant-a", policy); err == nil {
		t.Fatal("worker accepted another tenant's predecessor handle")
	}
}

func TestRetirementWorkerKeepsPolicyBoundedTenantEvidenceAcrossColdRestart(t *testing.T) {
	ctx := t.Context()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := eventstest.OpenFixture(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := log.Close(); err != nil {
			t.Error(err)
		}
	}()
	appendFact := func(tenantID, eventType string, payload any) events.Event {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		ev, err := log.Append(ctx, events.Event{TenantID: tenantID, Type: eventType, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	rpKey, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	roster, err := json.Marshal([]map[string]any{{"relying_party": "rp-a", "public_der": rpKey.Public().DER}})
	if err != nil {
		t.Fatal(err)
	}
	policies := []pcasstore.RetirementPolicy{
		{IdentityID: "identity-a", PredecessorEpoch: 2, Status: "active", RosterJSON: roster},
		{IdentityID: "identity-retired", PredecessorEpoch: 3, Status: "retired"},
	}
	sig, err := retirement.SignAck(rpKey, "tenant-a", "identity-a", 2, "rp-a")
	if err != nil {
		t.Fatal(err)
	}
	appendFact("tenant-a", succession.TypeRPAck, succession.RPAckV1{
		TenantID: "tenant-a", IdentityID: "identity-a", Epoch: 2, RelyingParty: "rp-a", AckSignature: sig})
	for i := range 40 {
		appendFact("tenant-a", succession.TypeRPAck, succession.RPAckV1{
			TenantID: "tenant-a", IdentityID: "identity-a", Epoch: 2,
			RelyingParty: fmt.Sprintf("unlisted-%d", i), AckSignature: []byte("no"),
		})
		appendFact("tenant-a", succession.TypeRPAck, succession.RPAckV1{
			TenantID: "tenant-a", IdentityID: "identity-a", Epoch: 2, RelyingParty: "rp-a", AckSignature: sig,
		})
	}
	appendFact("tenant-b", succession.TypeRPAck, succession.RPAckV1{
		TenantID: "tenant-b", IdentityID: "identity-a", Epoch: 2, RelyingParty: "rp-a", AckSignature: sig})
	appendFact("tenant-a", succession.TypeRetirement, succession.RetirementV1{
		TenantID: "tenant-a", IdentityID: "identity-retired", Epoch: 3})
	check := func() {
		t.Helper()
		view, err := collectTenantRetirementEvidence(ctx, log, "tenant-a", policies, time.Hour, time.Now().Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		active := view[retirementEvidenceKey{"identity-a", 2}]
		retired := view[retirementEvidenceKey{"identity-retired", 3}]
		if len(view) != 2 || active == nil || len(active.acks) != 1 || active.acks[0].RelyingParty != "rp-a" ||
			active.retired || retired == nil || !retired.retired || len(retired.acks) != 0 {
			t.Fatalf("policy-bound evidence: active=%+v retired=%+v count=%d", active, retired, len(view))
		}
	}
	check()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = eventstest.OpenFixture(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	check()
}
