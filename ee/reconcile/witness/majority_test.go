// SPDX-License-Identifier: LicenseRef-trstctl-EE

package witness_test

import (
	"bytes"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/digest"
	"trstctl.com/trstctl/ee/reconcile/witness"
	"trstctl.com/trstctl/internal/crypto"
)

// Three-way majority classification (XREC-claim-7).
func TestMajority_MinorityConformsToMajority(t *testing.T) {
	key := canon.RecordKey{TenantID: "tenant-a", RecordType: canon.RecordTypeX509Certificate, StableID: "cert-a"}
	result, err := witness.ClassifyMajority(witness.MajorityRequest{
		TenantID:    "tenant-a",
		SpecVersion: canon.SpecVersionV1,
		Planes: []witness.PlaneState{
			majorityPlane(t, "tenant-a", "vault", "cert-a", "active"),
			majorityPlane(t, "tenant-a", "kms", "cert-a", "active"),
			majorityPlane(t, "tenant-a", "ca", "cert-a", "revoked"),
		},
	})
	if err != nil {
		t.Fatalf("ClassifyMajority: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(result.Entries))
	}
	entry := result.Entries[0]
	if entry.RecordKey != key || !equalStrings(entry.MajorityAuthorityIDs, []string{"kms", "vault"}) ||
		!equalStrings(entry.MinorityAuthorityIDs, []string{"ca"}) {
		t.Fatalf("majority entry = %+v", entry)
	}
	if entry.AuthoritativeAuthorityID != "" {
		t.Fatalf("unexpected authoritative override: %+v", entry)
	}
	if len(entry.PerPlaneProofs) != 3 {
		t.Fatalf("proofs = %d, want every plane proof", len(entry.PerPlaneProofs))
	}
	for _, proof := range entry.PerPlaneProofs {
		if proof.DigestHash == "" || proof.Inclusion == nil || proof.Absence != nil {
			t.Fatalf("proof = %+v, want signed digest ref plus inclusion proof", proof)
		}
	}
	if len(entry.Actions) != 1 || entry.Actions[0].AuthorityID != "ca" ||
		entry.Actions[0].Operation != witness.OperationConformToMajority ||
		entry.Actions[0].TargetMaterialHash != entry.TargetMaterialHash {
		t.Fatalf("actions = %+v, want ca conforming to majority", entry.Actions)
	}
}

// Authoritative-plane override of the majority vote (XREC-claim-7).
func TestMajority_AuthoritativePlaneOverridesVote(t *testing.T) {
	result, err := witness.ClassifyMajority(witness.MajorityRequest{
		TenantID:    "tenant-a",
		SpecVersion: canon.SpecVersionV1,
		AuthoritativeByRecordType: map[string]string{
			canon.RecordTypeX509Certificate: "self",
		},
		Planes: []witness.PlaneState{
			majorityPlane(t, "tenant-a", "vault", "cert-a", "active"),
			majorityPlane(t, "tenant-a", "kms", "cert-a", "active"),
			majorityPlane(t, "tenant-a", "self", "cert-a", "revoked"),
		},
	})
	if err != nil {
		t.Fatalf("ClassifyMajority: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(result.Entries))
	}
	entry := result.Entries[0]
	if entry.AuthoritativeAuthorityID != "self" || !equalStrings(entry.MinorityAuthorityIDs, []string{"kms", "vault"}) {
		t.Fatalf("authoritative entry = %+v, want self override with kms/vault minority", entry)
	}
	if len(entry.Actions) != 2 {
		t.Fatalf("actions = %+v, want both non-authoritative planes conformed", entry.Actions)
	}
	for _, action := range entry.Actions {
		if action.Operation != witness.OperationConformToAuthoritative || action.TargetAuthorityID != "self" {
			t.Fatalf("action = %+v, want authoritative conform", action)
		}
	}
}

func majorityPlane(t *testing.T, tenantID, authorityID, stableID, status string) witness.PlaneState {
	t.Helper()
	set, err := canon.ReduceTenant(canon.SpecVersionV1, tenantID, []canon.ObservedRecord{{
		TenantID:   tenantID,
		RecordType: canon.RecordTypeX509Certificate,
		StableID:   stableID,
		Algorithm:  "RSA_2048",
		Status:     status,
		Provenance: canon.Provenance{AuthorityID: authorityID, NativeID: stableID},
		Attributes: map[string]canon.Value{
			"subject_dn": canon.DN("CN=" + stableID),
		},
	}})
	if err != nil {
		t.Fatalf("ReduceTenant: %v", err)
	}
	built, err := digest.Build(digest.BuildRequest{
		Set:         set,
		AuthorityID: authorityID,
		Watermark:   digest.Watermark{Position: authorityID + "-100", ObservedAt: time.Date(2026, 7, 8, 4, 0, 0, 0, time.UTC).Unix()},
		GeneratedAt: time.Date(2026, 7, 8, 4, 1, 0, 0, time.UTC).Unix(),
	})
	if err != nil {
		t.Fatalf("digest.Build: %v", err)
	}
	hash, err := built.Body.DigestHash()
	if err != nil {
		t.Fatalf("DigestHash: %v", err)
	}
	return witness.PlaneState{
		AuthorityID: authorityID,
		Set:         set,
		Tree:        built.Tree,
		Digest: digest.SignedDigest{
			Body:         built.Body,
			DigestHash:   hash,
			KeyID:        authorityID + "-digest-key",
			Algorithm:    crypto.ECDSAP256,
			PublicKeyDER: []byte("public-" + authorityID),
			Signature:    bytes.Repeat([]byte{0x42}, 64),
		},
	}
}
