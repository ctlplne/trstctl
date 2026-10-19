// SPDX-License-Identifier: BUSL-1.1

package depstate

import (
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

const certificateRevocationBatchApplied = "certificate.revocation.batch.applied"

// rememberRevokedManagedLeaves only accepts a completed local-issuer outcome.
// The event fold checks the immutable revocation independently of the mutable
// certificate inventory and the release producer's reviewed SQL projection.
func rememberRevokedManagedLeaves(e eventspec.Event, record func(keyID, certID, serial, digest string) error) error {
	if e.Type != certificateRevocationBatchApplied {
		return nil
	}
	if e.ID == "" || e.Sequence == 0 || (e.SchemaVersion != 1 && e.SchemaVersion != 2) {
		return fmt.Errorf("managed-leaf revocation has no immutable event identity")
	}
	var batch struct {
		Reason string `json:"reason"`
		Items  []struct {
			ID          string `json:"id"`
			Matched     bool   `json:"matched"`
			Status      string `json:"status"`
			CAID        string `json:"ca_id"`
			Serial      string `json:"serial"`
			Fingerprint string `json:"fingerprint"`
		} `json:"items"`
	}
	if err := json.Unmarshal(e.Data, &batch); err != nil {
		return err
	}
	if !crypto.IsValidRevocationReason(batch.Reason) || batch.Reason == "removeFromCRL" {
		return fmt.Errorf("managed-leaf revocation has no supported reason")
	}
	seen := make(map[string]struct{}, len(batch.Items))
	for _, item := range batch.Items {
		if _, duplicate := seen[item.ID]; duplicate {
			return fmt.Errorf("managed-leaf revocation repeats certificate")
		}
		seen[item.ID] = struct{}{}
		if item.Status != "revoked" {
			continue
		}
		if !item.Matched || item.ID == "" || item.CAID == "" || item.Serial == "" || len(item.Fingerprint) != 64 {
			return fmt.Errorf("managed-leaf revocation has no exact local issuer binding")
		}
		if err := record(item.CAID, item.ID, item.Serial, strings.ToLower(item.Fingerprint)); err != nil {
			return err
		}
	}
	return nil
}

// ExactRevokedLeaf checks one immutable local revocation outcome. The caller
// must also prove that the event was projected through the authority fence.
func ExactRevokedLeaf(e eventspec.Event, caID, certID, serial, digest string) error {
	matched := false
	if err := rememberRevokedManagedLeaves(e, func(itemCA, itemID, itemSerial, itemDigest string) error {
		if itemCA == caID && itemID == certID && itemSerial == serial && itemDigest == digest {
			matched = true
		}
		return nil
	}); err != nil {
		return err
	}
	if !matched {
		return fmt.Errorf("managed-leaf revocation does not bind the exact issuer and certificate")
	}
	return nil
}

func (b *keyBuilder) rememberRevocation(e eventspec.Event, certID, serial, digest string) error {
	key := (Dependent{Class: DependentCredential, ID: certID}).key()
	source, registered := b.leafSources[key]
	if !registered {
		return nil
	}
	if e.Sequence <= source.sequence || serial != source.serial || digest != source.certificateSHA256 {
		return fmt.Errorf("managed-leaf revocation differs from exact mint")
	}
	revocation := managedLeafRevocation{eventID: e.ID, sequence: e.Sequence,
		serial: serial, certificateSHA256: digest}
	if prior, found := b.revocations[key]; found && prior != revocation {
		return fmt.Errorf("managed-leaf revocation has a competing outcome")
	}
	b.revocations[key] = revocation
	return nil
}

func (b *keyBuilder) validateRevokedSourceBoundRelease(e eventspec.Event, release DependencyReleasedV3) error {
	if e.TenantID == "" || release.TenantID != e.TenantID || release.KeyID != b.state.KeyID ||
		release.Dependent.Class != DependentCredential || release.Dependent.ID == "" ||
		release.SourceEventID == "" || release.SourceSequence == 0 || release.Serial == "" ||
		release.CertificateSHA256 == "" || release.CeremonyID == "" || release.Actor == "" ||
		release.RevocationEventID == "" || release.RevocationSequence == 0 ||
		release.Reason != ReleaseReasonRevokedUnservedHostCustody || !release.RiskAccepted ||
		len(release.ApprovalEventIDs) < 2 {
		return fmt.Errorf("revoked host release lacks exact identity, approval, or risk evidence")
	}
	key := release.Dependent.key()
	source, registered := b.leafSources[key]
	revoked, found := b.revocations[key]
	if !registered || !found || source.eventID != release.SourceEventID ||
		source.sequence != release.SourceSequence || source.serial != release.Serial ||
		source.certificateSHA256 != release.CertificateSHA256 ||
		revoked.eventID != release.RevocationEventID || revoked.sequence != release.RevocationSequence ||
		revoked.serial != release.Serial || revoked.certificateSHA256 != release.CertificateSHA256 ||
		(e.Sequence != 0 && e.Sequence <= revoked.sequence) {
		return fmt.Errorf("revoked host release differs from immutable mint or revocation")
	}
	if _, already := b.accounted[key]; already {
		return fmt.Errorf("revoked host release repeats an accounted dependent")
	}
	ceremony := b.ceremonies[release.CeremonyID]
	if ceremony == nil || ceremony.cancelled || ceremony.purpose != ReleasePurposeV3(release) ||
		ceremony.threshold < 2 || len(ceremony.approvals) < ceremony.threshold ||
		len(ceremony.approvals) != len(release.ApprovalEventIDs) {
		return fmt.Errorf("revoked host release lacks its exact approved ceremony")
	}
	seen := make(map[string]struct{}, len(release.ApprovalEventIDs))
	for _, id := range release.ApprovalEventIDs {
		if id == "" {
			return fmt.Errorf("revoked host release has empty approval evidence")
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("revoked host release repeats approval evidence")
		}
		seen[id] = struct{}{}
		found = false
		for _, approved := range ceremony.approvals {
			if approved == id {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("revoked host release approval differs from ceremony")
		}
	}
	return nil
}
