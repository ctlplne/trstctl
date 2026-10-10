// SPDX-License-Identifier: BUSL-1.1

package background

import (
	"encoding/json"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/retirement"
)

func TestRetirementWorkerIndexedEvidenceAcrossColdRestart(t *testing.T) {
	ctx := t.Context()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := events.Open(ctx, cfg)
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
	appendFact("tenant-a", succession.TypeSuccession, map[string]string{"noise": "before"})
	first := appendFact("tenant-a", succession.TypeRPAck, succession.RPAckV1{
		TenantID: "tenant-a", IdentityID: "identity-a", Epoch: 2, RelyingParty: "rp-a", AckSignature: []byte("signed-a")})
	appendFact("tenant-b", succession.TypeFinding, map[string]string{"noise": "between"})
	second := appendFact("tenant-b", succession.TypeRPAck, succession.RPAckV1{
		TenantID: "tenant-b", IdentityID: "identity-b", Epoch: 3, RelyingParty: "rp-b", AckSignature: []byte("signed-b")})
	third := appendFact("tenant-a", succession.TypeRetirement, succession.RetirementV1{
		TenantID: "tenant-a", IdentityID: "identity-a", Epoch: 2})
	check := func() {
		t.Helper()
		facts, err := collectEvents(ctx, log)
		if err != nil {
			t.Fatal(err)
		}
		var sequences []uint64
		for _, fact := range facts {
			sequences = append(sequences, fact.Sequence)
		}
		if !reflect.DeepEqual(sequences, []uint64{first.Sequence, second.Sequence, third.Sequence}) {
			t.Fatalf("indexed retirement facts = %v", sequences)
		}
		acks, err := retirement.AcksFromEvents(facts)
		if err != nil || len(acks) != 2 || acks[0].TenantID != "tenant-a" || acks[1].TenantID != "tenant-b" {
			t.Fatalf("indexed relying-party acknowledgments = %+v, err=%v", acks, err)
		}
		if !alreadyRetired(facts, "tenant-a", "identity-a", 2) || alreadyRetired(facts, "tenant-b", "identity-a", 2) {
			t.Fatal("retirement decision lost tenant or predecessor binding")
		}
	}
	check()
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = events.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	check()
}
