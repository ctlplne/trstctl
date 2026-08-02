// SPDX-License-Identifier: LicenseRef-trstctl-EE

package aggregate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/ee/decommission/gate"
	"trstctl.com/trstctl/ee/decommission/record"
	"trstctl.com/trstctl/ee/pqcmigration"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/signing"
)

// Guard for VDEC-claim-9 and the aggregate branch of VDEC-claim-18.
func TestAggregate_TenantScopeRecordOfflineVerifiable(t *testing.T) {
	ctx := context.Background()
	perKeyMinter := newPerKeyMinter(t)
	aggregateMinter := newAggregateMinter(t)

	rootCA := mustMintPerKey(t, ctx, perKeyMinter, "tenant-a", "key://tenant-a/root-ca", 41, "audit-head-root")
	sshCA := mustMintPerKey(t, ctx, perKeyMinter, "tenant-a", "key://tenant-a/ssh-ca", 42, "audit-head-ssh")

	rec, err := aggregateMinter.Mint(ctx, MintRequest{
		TenantID: "tenant-a",
		Records: []LeafInput{
			{KeyClass: "ssh-ca", Record: sshCA},
			{KeyClass: "x509-ca", Record: rootCA},
		},
		AuditChainHead:          "audit-head-after-last-destroyed-key",
		InventoryLedgerPosition: 99,
		InventoryKeyIDs:         []string{"key://tenant-a/ssh-ca", "key://tenant-a/root-ca"},
		GovernanceEvidenceRefs:  []string{"governance:evidence-pack/vdec/offboarding/tenant-a"},
	})
	if err != nil {
		t.Fatalf("Mint aggregate: %v", err)
	}
	if err := VerifyRecord(rec, aggregateMinter.PublicKey()); err != nil {
		t.Fatalf("VerifyRecord aggregate: %v", err)
	}
	if got := rec.Commitment.TenantID; got != "tenant-a" {
		t.Fatalf("tenant id = %q, want tenant-a", got)
	}
	if got := rec.Commitment.AuditChainHead; got != "audit-head-after-last-destroyed-key" {
		t.Fatalf("audit head = %q, want final head", got)
	}
	if len(rec.Commitment.LeafRoot) == 0 || len(rec.Commitment.Leaves) != 2 {
		t.Fatalf("aggregate leaves/root = %d/%x, want two leaves and root", len(rec.Commitment.Leaves), rec.Commitment.LeafRoot)
	}
	if !rec.Commitment.Inventory.Exhausted || rec.Commitment.Inventory.LedgerPosition != 99 || rec.Commitment.Inventory.KeyCount != 2 {
		t.Fatalf("inventory completeness = %+v, want exhausted at ledger position 99", rec.Commitment.Inventory)
	}
	if len(rec.Commitment.KeyClassCounts) != 2 {
		t.Fatalf("key class counts = %+v, want both key classes", rec.Commitment.KeyClassCounts)
	}

	proof, err := ProofForKey(rec, "key://tenant-a/root-ca")
	if err != nil {
		t.Fatalf("ProofForKey: %v", err)
	}
	if err := VerifyLeafDescent(rec, proof, rootCA, aggregateMinter.PublicKey(), perKeyMinter.PublicKey()); err != nil {
		t.Fatalf("VerifyLeafDescent: %v", err)
	}

	tampered := rec
	tampered.Commitment.AuditChainHead = "different-audit-head"
	if err := VerifyRecord(tampered, aggregateMinter.PublicKey()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("VerifyRecord tampered audit head error = %v, want unverified", err)
	}
}

// Guard for VDEC-claim-10.
func TestCampaign_KeyedToSuccessionEpoch(t *testing.T) {
	ctx := context.Background()
	perKeyMinter := newPerKeyMinter(t)
	aggregateMinter := newAggregateMinter(t)
	guard := &successionGuard{}

	jobs, residuals, err := pqcmigration.BuildSuccessionJobs(ctx, []pqcmigration.Credential{
		{
			AssetID:           "asset-cert-a",
			IdentityID:        "spiffe://tenant-a/ns/payments/sa/api",
			Type:              pqcmigration.CredentialX509,
			Algorithm:         "RSA-2048",
			QuantumVulnerable: true,
			Protocol:          "acme",
		},
	}, pqcmigration.StaticDecider{})
	if err != nil {
		t.Fatalf("BuildSuccessionJobs: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("succession jobs/residuals = %d/%d, want one consumed succession job", len(jobs), len(residuals))
	}

	successorRecordDigest := crypto.SHA256Sum([]byte("pcas-succession-record-consumed-as-data"))
	campaign, err := CampaignBindingFromPQC(CampaignRequest{
		CampaignID:                        "campaign:pqc-2026q3",
		SuccessionEpochID:                 "succession-epoch:2026q3-hybrid",
		SupersedingSuccessionRecordDigest: successorRecordDigest,
		SuccessionJobs:                    jobs,
		ForbiddenSuccessionAuthorityUse:   guard,
	})
	if err != nil {
		t.Fatalf("CampaignBindingFromPQC: %v", err)
	}
	if guard.calls != 0 {
		t.Fatalf("aggregate code invoked succession authority guard %d times, want 0", guard.calls)
	}

	perKey := mustMintPerKey(t, ctx, perKeyMinter, "tenant-a", "key://tenant-a/rsa-predecessor", 72, "audit-head-rsa")
	rec, err := aggregateMinter.Mint(ctx, MintRequest{
		TenantID:                "tenant-a",
		Records:                 []LeafInput{{KeyClass: "x509-ca", Record: perKey}},
		AuditChainHead:          "audit-head-after-pqc-campaign",
		InventoryLedgerPosition: 120,
		InventoryKeyIDs:         []string{"key://tenant-a/rsa-predecessor"},
		Campaign:                &campaign,
	})
	if err != nil {
		t.Fatalf("Mint campaign aggregate: %v", err)
	}
	if err := VerifyRecord(rec, aggregateMinter.PublicKey()); err != nil {
		t.Fatalf("VerifyRecord campaign aggregate: %v", err)
	}
	if rec.Commitment.Campaign == nil {
		t.Fatal("campaign binding missing from aggregate commitment")
	}
	if got := rec.Commitment.Campaign.SuccessionEpochID; got != "succession-epoch:2026q3-hybrid" {
		t.Fatalf("succession epoch id = %q", got)
	}
	if !bytes.Equal(rec.Commitment.Campaign.SupersedingSuccessionRecordDigest, successorRecordDigest) {
		t.Fatal("aggregate did not bind supplied superseding succession-record digest")
	}
	if len(rec.Commitment.Campaign.SuccessionJobDigests) != 1 {
		t.Fatalf("succession job digests = %d, want 1", len(rec.Commitment.Campaign.SuccessionJobDigests))
	}
}

// Guard for VDEC-claim-20.
func TestErasure_SanitizationClaimBound(t *testing.T) {
	ctx := context.Background()
	perKeyMinter := newPerKeyMinter(t)
	aggregateMinter := newAggregateMinter(t)
	dataSet := depstate.Dependent{Class: depstate.DependentDataSet, ID: "s3://tenant-a/pii-archive"}
	ciphertext := depstate.Dependent{Class: depstate.DependentCiphertext, ID: "s3://tenant-a/live/object-7"}

	events := []eventspec.Event{
		mustDepEvent(t, 1, depstate.DependencyRegisteredV1{TenantID: "tenant-a", KeyID: "key://tenant-a/dek-erasure", Dependent: dataSet}),
		mustDepEvent(t, 2, depstate.DependencyRegisteredV1{TenantID: "tenant-a", KeyID: "key://tenant-a/dek-erasure", Dependent: ciphertext}),
		mustDepEvent(t, 3, depstate.DependencyErasureDesignatedV1{TenantID: "tenant-a", KeyID: "key://tenant-a/dek-erasure", Dependent: dataSet, DesignationRef: "ledger:event/3"}),
	}
	state := foldedState(t, events, "tenant-a", "key://tenant-a/dek-erasure")
	claim := SanitizationClaim{
		TenantID:       "tenant-a",
		KeyID:          "key://tenant-a/dek-erasure",
		DataSetID:      dataSet.ID,
		Scope:          "tenant-a/pii-archive",
		StorageRefs:    []string{"bucket:pii-archive", "prefix:2026/"},
		DesignationRef: "ledger:event/3",
	}
	jobs, err := PlanReprotectionWithErasure(state, []SanitizationClaim{claim})
	if err != nil {
		t.Fatalf("PlanReprotectionWithErasure: %v", err)
	}
	if len(jobs) != 1 || jobs[0].Dependent != ciphertext {
		t.Fatalf("jobs = %+v, want only non-erasure ciphertext dependent", jobs)
	}

	g := newGate(t)
	refused, err := g.VerifyGatedDestroy(ctx, gateRequestFromEvents(t, events, 3))
	if err != nil {
		t.Fatalf("VerifyGatedDestroy before non-erasure completion: %v", err)
	}
	if refused.Approved {
		t.Fatal("gate approved while non-erasure dependent still required re-protection")
	}
	complete := append([]eventspec.Event{}, events...)
	complete = append(complete, mustDepEvent(t, 4, depstate.ReprotectionCompletedV1{
		TenantID:       "tenant-a",
		KeyID:          "key://tenant-a/dek-erasure",
		JobID:          jobs[0].ID,
		Dependent:      ciphertext,
		SuccessorKeyID: "key://tenant-a/dek-successor",
	}))
	approved, err := g.VerifyGatedDestroy(ctx, gateRequestFromEvents(t, complete, 4))
	if err != nil {
		t.Fatalf("VerifyGatedDestroy after non-erasure completion: %v", err)
	}
	if !approved.Approved {
		t.Fatalf("gate refused even though erasure designation plus non-erasure completion accounts for all dependents: %+v", approved)
	}

	perKey := mustMintPerKey(t, ctx, perKeyMinter, "tenant-a", "key://tenant-a/dek-erasure", 88, "audit-head-erasure")
	rec, err := aggregateMinter.Mint(ctx, MintRequest{
		TenantID:                "tenant-a",
		Records:                 []LeafInput{{KeyClass: "data-encryption-key", Record: perKey}},
		AuditChainHead:          "audit-head-after-erasure-destroy",
		InventoryLedgerPosition: 140,
		InventoryKeyIDs:         []string{"key://tenant-a/dek-erasure"},
		SanitizationClaims:      []SanitizationClaim{claim},
	})
	if err != nil {
		t.Fatalf("Mint erasure aggregate: %v", err)
	}
	if err := VerifyRecord(rec, aggregateMinter.PublicKey()); err != nil {
		t.Fatalf("VerifyRecord erasure aggregate: %v", err)
	}
	if len(rec.Commitment.SanitizationClaims) != 1 || len(rec.Commitment.SanitizationClaims[0].ClaimDigest) == 0 {
		t.Fatalf("sanitization claims = %+v, want bound claim digest", rec.Commitment.SanitizationClaims)
	}
	tampered := rec
	tampered.Commitment.SanitizationClaims[0].DesignationRef = "ledger:event/tampered"
	if err := VerifyRecord(tampered, aggregateMinter.PublicKey()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("VerifyRecord tampered sanitization claim error = %v, want unverified", err)
	}
}

type successionGuard struct {
	calls int
}

func (g *successionGuard) OnForbiddenSuccessionAuthorityUse(string) error {
	g.calls++
	return nil
}

func newAggregateMinter(t *testing.T) *Minter {
	t.Helper()
	minter, err := NewMinter(Config{
		SignerID:  "test-vdec-aggregate-signer",
		Algorithm: crypto.ECDSAP256,
		Now:       func() time.Time { return time.Unix(1800000900, 0) },
	})
	if err != nil {
		t.Fatalf("NewMinter aggregate: %v", err)
	}
	t.Cleanup(minter.Destroy)
	return minter
}

func newPerKeyMinter(t *testing.T) *record.Minter {
	t.Helper()
	minter, err := record.NewMinter(record.Config{
		SignerID:  "test-vdec-per-key-signer",
		Algorithm: crypto.ECDSAP256,
		Now:       func() time.Time { return time.Unix(1800000800, 0) },
	})
	if err != nil {
		t.Fatalf("record.NewMinter: %v", err)
	}
	t.Cleanup(minter.Destroy)
	return minter
}

func mustMintPerKey(t *testing.T, ctx context.Context, minter *record.Minter, tenantID, keyID string, epoch uint64, auditHead string) record.SignedRecord {
	t.Helper()
	rec, err := minter.Mint(ctx, record.MintRequest{
		TenantID:               tenantID,
		StableKeyID:            keyID,
		FinalEpoch:             epoch,
		CompletionEventsDigest: crypto.SHA256Sum([]byte("completion:" + keyID)),
		RequiredSetDigest:      crypto.SHA256Sum([]byte("required:" + keyID)),
		DestructionEvidence: record.EvidenceFromDestruction(gate.DestructionEvidence{
			Kind:               gate.TypeCustodyHSMDestroyed,
			TenantID:           tenantID,
			StableKeyID:        keyID,
			FinalEpoch:         epoch,
			AttestationClass:   gate.ClassCertifiedHardware,
			AttestationClassID: gate.ClassCertifiedHardware.ID(),
			Record:             []byte("hsm destroyed " + keyID),
			Digest:             crypto.SHA256Sum([]byte("destroyed:" + keyID)),
		}),
		AuditChainHead: auditHead,
	})
	if err != nil {
		t.Fatalf("Mint per-key %s: %v", keyID, err)
	}
	return rec
}

func mustDepEvent(t *testing.T, seq uint64, payload depstate.Payload) eventspec.Event {
	t.Helper()
	ev, err := depstate.Encode(payload)
	if err != nil {
		t.Fatalf("depstate.Encode(%T): %v", payload, err)
	}
	ev.Sequence = seq
	ev.SchemaVersion = depstate.SchemaV1
	return ev
}

func foldedState(t *testing.T, events []eventspec.Event, tenantID, keyID string) depstate.KeyState {
	t.Helper()
	proj, err := depstate.Fold(events)
	if err != nil {
		t.Fatalf("depstate.Fold: %v", err)
	}
	state, ok := proj.Lookup(tenantID, keyID)
	if !ok {
		t.Fatalf("state for %s/%s missing", tenantID, keyID)
	}
	return state
}

func newGate(t *testing.T) *gate.Gate {
	t.Helper()
	g, err := gate.New(gate.Config{
		SignerID:  "test-vdec-gate",
		Algorithm: crypto.ECDSAP256,
		Now:       func() time.Time { return time.Unix(1800000700, 0) },
	})
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	t.Cleanup(g.Destroy)
	return g
}

func gateRequestFromEvents(t *testing.T, events []eventspec.Event, bound uint64) signing.GatedDestroyRequest {
	t.Helper()
	bounded := gate.BoundEvents(events, bound)
	state := foldedState(t, bounded, "tenant-a", "key://tenant-a/dek-erasure")
	requiredSet, err := gate.RequiredSetBytes(state)
	if err != nil {
		t.Fatalf("RequiredSetBytes: %v", err)
	}
	requiredDigest, err := gate.RequiredSetDigest(state)
	if err != nil {
		t.Fatalf("RequiredSetDigest: %v", err)
	}
	segment, err := gate.EncodeLedgerSegment(88, events)
	if err != nil {
		t.Fatalf("EncodeLedgerSegment: %v", err)
	}
	return signing.GatedDestroyRequest{
		TenantID:             "tenant-a",
		Handle:               "handle/dek-erasure",
		SubjectRef:           "key://tenant-a/dek-erasure",
		AssertedFinalEpoch:   88,
		LedgerPosition:       bound,
		RequiredSet:          requiredSet,
		RequiredSetDigest:    requiredDigest,
		SatisfactionEvidence: segment,
		AuditChainHead:       gate.AuditChainHead(bounded),
	}
}

func TestAggregateCanonicalRoundTrip(t *testing.T) {
	ctx := context.Background()
	perKeyMinter := newPerKeyMinter(t)
	aggregateMinter := newAggregateMinter(t)
	perKey := mustMintPerKey(t, ctx, perKeyMinter, "tenant-a", "key://tenant-a/round-trip", 7, "audit-head-round-trip")
	rec, err := aggregateMinter.Mint(ctx, MintRequest{
		TenantID:                "tenant-a",
		Records:                 []LeafInput{{KeyClass: "x509-ca", Record: perKey}},
		AuditChainHead:          "audit-head-aggregate-round-trip",
		InventoryLedgerPosition: 7,
		InventoryKeyIDs:         []string{"key://tenant-a/round-trip"},
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	raw, err := EncodeRecord(rec)
	if err != nil {
		t.Fatalf("EncodeRecord: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("encoded aggregate JSON invalid: %v", err)
	}
	decoded, err := DecodeRecord(raw)
	if err != nil {
		t.Fatalf("DecodeRecord: %v", err)
	}
	again, err := EncodeRecord(decoded)
	if err != nil {
		t.Fatalf("EncodeRecord decoded: %v", err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("aggregate canonical encoding changed after round trip")
	}
	if err := VerifyRecord(decoded, aggregateMinter.PublicKey()); err != nil {
		t.Fatalf("VerifyRecord decoded: %v", err)
	}
}
