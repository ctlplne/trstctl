// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"strings"
	"testing"
)

func TestValidateCertificateRevocationBatchHasClosedOutcomes(t *testing.T) {
	valid := func() CertificateRevocationBatchApplied {
		return CertificateRevocationBatchApplied{
			RequestBinding: strings.Repeat("a", 64), Reason: "keyCompromise",
			Items: []CertificateRevocationItem{{
				ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Matched: true, Status: "revoked",
				Fingerprint: strings.Repeat("b", 64), Serial: "abc123", CAID: "11111111-1111-4111-8111-111111111111",
			}},
		}
	}
	if err := ValidateCertificateRevocationBatch(valid()); err != nil {
		t.Fatal(err)
	}
	for name, corrupt := range map[string]func(*CertificateRevocationBatchApplied){
		"unknown_reason":     func(b *CertificateRevocationBatchApplied) { b.Reason = "invented" },
		"unhold_not_revoke":  func(b *CertificateRevocationBatchApplied) { b.Reason = "removeFromCRL" },
		"invalid_binding":    func(b *CertificateRevocationBatchApplied) { b.RequestBinding = strings.Repeat("z", 64) },
		"empty_selection":    func(b *CertificateRevocationBatchApplied) { b.Items = nil },
		"duplicate_id":       func(b *CertificateRevocationBatchApplied) { b.Items = append(b.Items, b.Items[0]) },
		"noncanonical_id":    func(b *CertificateRevocationBatchApplied) { b.Items[0].ID = strings.ToUpper(b.Items[0].ID) },
		"invalid_serial":     func(b *CertificateRevocationBatchApplied) { b.Items[0].Serial = "not-a-serial" },
		"missing_authority":  func(b *CertificateRevocationBatchApplied) { b.Items[0].CAID = "" },
		"missing_signature":  func(b *CertificateRevocationBatchApplied) { b.Items[0].Fingerprint = "" },
		"revoked_not_found":  func(b *CertificateRevocationBatchApplied) { b.Items[0].Matched = false },
		"unknown_status":     func(b *CertificateRevocationBatchApplied) { b.Items[0].Status = "pending" },
		"success_with_error": func(b *CertificateRevocationBatchApplied) { b.Items[0].Error = "unbounded detail" },
		"failed_with_authority": func(b *CertificateRevocationBatchApplied) {
			b.Items[0].Status, b.Items[0].Error = "failed", CertificateRevocationUnsupportedReason
		},
		"skipped_with_authority": func(b *CertificateRevocationBatchApplied) {
			b.Items[0].Status, b.Items[0].Error = "skipped", "already revoked"
		},
		"oversized_selection": func(b *CertificateRevocationBatchApplied) {
			b.Items = make([]CertificateRevocationItem, MaxCertificateRevocationBatch+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			batch := valid()
			corrupt(&batch)
			if err := ValidateCertificateRevocationBatch(batch); err == nil {
				t.Fatal("invalid or unbounded receipt was accepted")
			}
		})
	}
	for _, item := range []CertificateRevocationItem{
		{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Status: "failed", Error: "not found"},
		{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Matched: true, Status: "failed", Error: CertificateRevocationUnsupportedReason},
		{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Matched: true, Status: "skipped", Error: "already revoked"},
	} {
		batch := valid()
		batch.Items = []CertificateRevocationItem{item}
		if err := ValidateCertificateRevocationBatch(batch); err != nil {
			t.Errorf("valid closed outcome %s: %v", item.Status, err)
		}
	}
}

func TestValidateCertificateRevocationBatchPinsExternalAuthority(t *testing.T) {
	valid := CertificateRevocationBatchApplied{
		RequestBinding: strings.Repeat("a", 64), Reason: "superseded",
		Items: []CertificateRevocationItem{{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Matched: true,
			Status: "queued", Fingerprint: strings.Repeat("b", 64), Serial: "a1", ExternalCAID: "selected-vault"}},
	}
	if err := ValidateCertificateRevocationBatch(valid); err != nil {
		t.Fatal(err)
	}
	for name, corrupt := range map[string]func(*CertificateRevocationItem){
		"missing_issuer":      func(item *CertificateRevocationItem) { item.ExternalCAID = "" },
		"ambiguous_issuer":    func(item *CertificateRevocationItem) { item.CAID = "11111111-1111-4111-8111-111111111111" },
		"unbounded_issuer":    func(item *CertificateRevocationItem) { item.ExternalCAID = strings.Repeat("a", 257) },
		"untrimmed_issuer":    func(item *CertificateRevocationItem) { item.ExternalCAID = " selected-vault" },
		"unmatched_leaf":      func(item *CertificateRevocationItem) { item.Matched = false },
		"missing_fingerprint": func(item *CertificateRevocationItem) { item.Fingerprint = "" },
		"noncanonical_serial": func(item *CertificateRevocationItem) { item.Serial = "A1" },
		"false_completion":    func(item *CertificateRevocationItem) { item.Status = "revoked" },
	} {
		t.Run(name, func(t *testing.T) {
			batch := valid
			batch.Items = append([]CertificateRevocationItem(nil), valid.Items...)
			corrupt(&batch.Items[0])
			if err := ValidateCertificateRevocationBatch(batch); err == nil {
				t.Fatal("invalid external authority accepted")
			}
		})
	}
}
