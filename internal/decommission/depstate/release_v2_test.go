// SPDX-License-Identifier: BUSL-1.1

package depstate

import (
	"encoding/json"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/caevent"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

func TestSourceBoundReleaseRequiresEarlierExactManagedLeaf(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	const caID = "22222222-2222-4222-8222-222222222222"
	const certID = "33333333-3333-4333-8333-333333333333"
	der := []byte("public certificate DER fixture")
	issuedData, err := json.Marshal(map[string]any{
		"id": certID, "ca_id": caID, "serial": "7a", "fingerprint": crypto.SHA256Hex(der), "certificate_der": der,
	})
	if err != nil {
		t.Fatal(err)
	}
	issued := eventspec.Event{ID: "managed-leaf-source", Type: caevent.EventCAEndEntityIssued,
		SchemaVersion: caevent.CAEndEntityInventorySchemaVersion, TenantID: tenantID, Sequence: 17, Data: issuedData}
	release := DependencyReleasedV2{TenantID: tenantID, KeyID: caID,
		Dependent:     Dependent{Class: DependentCredential, ID: certID},
		SourceEventID: issued.ID, SourceSequence: issued.Sequence,
		Serial: "7a", CertificateSHA256: crypto.SHA256Hex(der),
		CeremonyID: "approved-ceremony", Actor: "operator", ApprovalEventIDs: []string{"approval-one", "approval-two"},
		Reason: ReleaseReasonExpiredRequesterCustody, RiskAccepted: true}
	encoded, err := Encode(release)
	if err != nil {
		t.Fatal(err)
	}
	encoded.ID = "release-exact-leaf"
	encoded.Sequence = 21
	if encoded.SchemaVersion != SchemaV2 {
		t.Fatalf("release schema = %d, want v2", encoded.SchemaVersion)
	}
	decoded, err := Decode(encoded)
	if err != nil || !reflect.DeepEqual(decoded, release) {
		t.Fatalf("round trip = %#v, %v", decoded, err)
	}
	startedData, err := json.Marshal(map[string]any{"ceremony_id": release.CeremonyID,
		"purpose": ReleasePurposeV2(release), "threshold": 2, "opener": release.Actor})
	if err != nil {
		t.Fatal(err)
	}
	started := eventspec.Event{ID: "release-ceremony-start", Type: caCeremonyStarted,
		TenantID: tenantID, Sequence: 18, Data: startedData}
	approvalOne := eventspec.Event{ID: "approval-one", Type: caCeremonyApproved, TenantID: tenantID,
		Sequence: 19, Data: []byte(`{"ceremony_id":"approved-ceremony","custodian":"custodian-one"}`)}
	approvalTwo := eventspec.Event{ID: "approval-two", Type: caCeremonyApproved, TenantID: tenantID,
		Sequence: 20, Data: []byte(`{"ceremony_id":"approved-ceremony","custodian":"custodian-two"}`)}
	valid := []eventspec.Event{issued, started, approvalOne, approvalTwo, encoded}
	state, err := Fold(valid)
	if err != nil {
		t.Fatal(err)
	}
	if got, found := state.Lookup(tenantID, caID); !found || len(got.Unaccounted()) != 0 || len(got.Released) != 1 {
		t.Fatalf("exact release not reflected: found=%v state=%+v", found, got)
	}
	folder := NewKeyFolder(tenantID, caID)
	for _, event := range valid {
		if err := folder.Apply(event); err != nil {
			t.Fatal(err)
		}
	}
	if got, found := folder.Snapshot(); !found || len(got.Unaccounted()) != 0 || len(got.Released) != 1 {
		t.Fatalf("signer fold differs: found=%v state=%+v", found, got)
	}
	for name, mutate := range map[string]func(*DependencyReleasedV2){
		"source identity":         func(p *DependencyReleasedV2) { p.SourceEventID = "other" },
		"source position":         func(p *DependencyReleasedV2) { p.SourceSequence++ },
		"certificate digest":      func(p *DependencyReleasedV2) { p.CertificateSHA256 = crypto.SHA256Hex([]byte("other")) },
		"CA key":                  func(p *DependencyReleasedV2) { p.KeyID = "44444444-4444-4444-8444-444444444444" },
		"dependent":               func(p *DependencyReleasedV2) { p.Dependent.ID = "55555555-5555-4555-8555-555555555555" },
		"single approval":         func(p *DependencyReleasedV2) { p.ApprovalEventIDs = p.ApprovalEventIDs[:1] },
		"missing risk acceptance": func(p *DependencyReleasedV2) { p.RiskAccepted = false },
	} {
		t.Run(name, func(t *testing.T) {
			changed := release
			mutate(&changed)
			event, err := Encode(changed)
			if err != nil {
				t.Fatal(err)
			}
			event.Sequence = 21
			if _, err := Fold([]eventspec.Event{issued, started, approvalOne, approvalTwo, event}); err == nil {
				t.Fatal("unbound source release counted by retirement fold")
			}
		})
	}
	if _, err := Fold([]eventspec.Event{encoded, issued}); err == nil {
		t.Fatal("release before registration counted by retirement fold")
	}
	if _, err := Fold([]eventspec.Event{issued, started, approvalOne, encoded}); err == nil {
		t.Fatal("release with only one approved custodian counted")
	}
	cancelled := eventspec.Event{ID: "ceremony-cancel", Type: caCeremonyCancelled, TenantID: tenantID,
		Sequence: 21, Data: []byte(`{"ceremony_id":"approved-ceremony"}`)}
	if _, err := Fold([]eventspec.Event{issued, started, approvalOne, approvalTwo, cancelled, encoded}); err == nil {
		t.Fatal("cancelled release ceremony counted")
	}
}
