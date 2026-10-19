// SPDX-License-Identifier: BUSL-1.1

package depstate

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/caevent"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

func TestRevokedHostLeafReleaseRequiresExactRevocationAndCustodians(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	const caID = "22222222-2222-4222-8222-222222222222"
	const certID = "33333333-3333-4333-8333-333333333333"
	der := []byte("public certificate DER fixture")
	digest := crypto.SHA256Hex(der)
	issuedData, _ := json.Marshal(map[string]any{
		"id": certID, "ca_id": caID, "serial": "7a", "fingerprint": digest, "certificate_der": der,
	})
	issued := eventspec.Event{ID: "managed-leaf-source", Type: caevent.EventCAEndEntityIssued,
		SchemaVersion: caevent.CAEndEntityInventorySchemaVersion, TenantID: tenantID, Sequence: 17, Data: issuedData}
	revokedData, _ := json.Marshal(map[string]any{
		"request_binding": crypto.SHA256Hex([]byte("request")), "reason": "cessationOfOperation",
		"items": []map[string]any{{"id": certID, "matched": true, "status": "revoked",
			"fingerprint": digest, "serial": "7a", "ca_id": caID}},
	})
	revoked := eventspec.Event{ID: "exact-revocation", Type: "certificate.revocation.batch.applied",
		SchemaVersion: 1, TenantID: tenantID, Sequence: 18, Data: revokedData}
	release := DependencyReleasedV3{DependencyReleasedV2: DependencyReleasedV2{
		TenantID: tenantID, KeyID: caID, Dependent: Dependent{Class: DependentCredential, ID: certID},
		SourceEventID: issued.ID, SourceSequence: issued.Sequence, Serial: "7a", CertificateSHA256: digest,
		CeremonyID: "approved-ceremony", Actor: "operator", ApprovalEventIDs: []string{"approval-one", "approval-two"},
		Reason: ReleaseReasonRevokedUnservedHostCustody, RiskAccepted: true},
		RevocationEventID: revoked.ID, RevocationSequence: revoked.Sequence,
	}
	encoded, err := Encode(release)
	if err != nil || encoded.SchemaVersion != SchemaV3 {
		t.Fatalf("encode v3 release: event=%+v err=%v", encoded, err)
	}
	encoded.ID, encoded.Sequence = "release-exact-leaf", 22
	startedData, _ := json.Marshal(map[string]any{"ceremony_id": release.CeremonyID,
		"purpose": ReleasePurposeV3(release), "threshold": 2, "opener": release.Actor})
	started := eventspec.Event{ID: "release-ceremony-start", Type: caCeremonyStarted,
		TenantID: tenantID, Sequence: 19, Data: startedData}
	approvalOne := eventspec.Event{ID: "approval-one", Type: caCeremonyApproved, TenantID: tenantID,
		Sequence: 20, Data: []byte(`{"ceremony_id":"approved-ceremony","custodian":"custodian-one"}`)}
	approvalTwo := eventspec.Event{ID: "approval-two", Type: caCeremonyApproved, TenantID: tenantID,
		Sequence: 21, Data: []byte(`{"ceremony_id":"approved-ceremony","custodian":"custodian-two"}`)}
	valid := []eventspec.Event{issued, revoked, started, approvalOne, approvalTwo, encoded}
	state, err := Fold(valid)
	if err != nil {
		t.Fatal(err)
	}
	if got, found := state.Lookup(tenantID, caID); !found || len(got.Unaccounted()) != 0 || len(got.Released) != 1 {
		t.Fatalf("exact revoked release not reflected: found=%v state=%+v", found, got)
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
	for name, mutate := range map[string]func(*DependencyReleasedV3){
		"revocation event":    func(v *DependencyReleasedV3) { v.RevocationEventID = "other" },
		"revocation sequence": func(v *DependencyReleasedV3) { v.RevocationSequence++ },
		"mint digest":         func(v *DependencyReleasedV3) { v.CertificateSHA256 = crypto.SHA256Hex([]byte("other")) },
		"single approval":     func(v *DependencyReleasedV3) { v.ApprovalEventIDs = v.ApprovalEventIDs[:1] },
	} {
		t.Run(name, func(t *testing.T) {
			changed := release
			mutate(&changed)
			event, err := Encode(changed)
			if err != nil {
				t.Fatal(err)
			}
			event.Sequence = 22
			if _, err := Fold([]eventspec.Event{issued, revoked, started, approvalOne, approvalTwo, event}); err == nil {
				t.Fatal("unbound revoked release counted by retirement fold")
			}
		})
	}
	if _, err := Fold([]eventspec.Event{issued, started, approvalOne, approvalTwo, encoded}); err == nil {
		t.Fatal("release without revocation proof counted")
	}
}
