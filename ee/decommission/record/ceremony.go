// SPDX-License-Identifier: LicenseRef-trstctl-EE

package record

import (
	"context"

	"trstctl.com/trstctl/ee/decommission/gate"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

// mintRequestFromCeremonyBundle carries the control-plane-unavailable half of
// VDEC-claim-11: destroy and quorum are recorded in a signed ceremony bundle that
// is verified and replayed on recovery, and a bundle failing verification is
// rejected rather than replayed.
func mintRequestFromCeremonyBundle(bundle gate.CeremonyBundle) MintRequest {
	bundle = gate.NormalizeCeremonyBundleForRecord(bundle)
	return MintRequest{
		TenantID:                   bundle.TenantID,
		StableKeyID:                bundle.StableKeyID,
		FinalEpoch:                 bundle.FinalEpoch,
		CompletionEventsDigest:     bundle.CompletionEventsDigest,
		RequiredSetDigest:          bundle.RequiredSetDigest,
		QuorumEvidence:             &bundle.QuorumEvidence,
		RevocationCompletionDigest: bundle.RevocationCompletionDigest,
		DestructionEvidence:        EvidenceFromDestruction(bundle.DestructionEvidence),
		AuditChainHead:             bundle.AuditChainHead,
	}
}

func ReconcileCeremonyBundle(ctx context.Context, minter *Minter, bundle gate.CeremonyBundle, trust crypto.PublicKey, policy gate.QuorumPolicy, sink gate.EvidenceAppendSink) (SignedRecord, eventspec.Event, error) {
	appended, err := gate.ReconcileCeremonyBundle(ctx, bundle, trust, policy, sink)
	if err != nil {
		return SignedRecord{}, eventspec.Event{}, err
	}
	rec, err := minter.Mint(ctx, mintRequestFromCeremonyBundle(bundle))
	if err != nil {
		return SignedRecord{}, eventspec.Event{}, err
	}
	return rec, appended, nil
}
