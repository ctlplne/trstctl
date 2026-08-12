// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package signerwiring assembles VDEC components that must live inside the
// isolated signer process.
package signerwiring

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/ee/decommission/aggregate"
	"trstctl.com/trstctl/ee/decommission/gate"
	"trstctl.com/trstctl/ee/decommission/record"
	"trstctl.com/trstctl/ee/decommission/retirementwire"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

var ErrSignerRuntimeUnavailable = errors.New("vdec signer runtime: required custody backend is not configured")

const (
	ArtifactKindDestructionRecord      = "vdec-destruction-record"
	ArtifactKindRecordCountersignature = "vdec-destruction-record-countersignature"
	ArtifactKindAggregateRecord        = "vdec-aggregate-decommissioning-record"

	defaultDestructionRecordKeyID      = "vdec-destruction-record"
	defaultCountersignatureKeyID       = "vdec-destruction-record-countersignature"
	defaultAggregateRecordKeyID        = "vdec-aggregate-decommissioning-record"
	defaultCountersignatureAuthorityID = "trstctl-vdec-countersignature"
)

type Config struct {
	SignerID string
	FloorDir string
}

// Runtime is retained by the signer through signing.WithGatedDestruction and
// signing.WithArtifactSigner. It delegates gate decisions while keeping
// signer-held VDEC keys and custody components alive for the shipped EE binary.
//
// This assembly is the isolated-signing-process element of the VDEC-claim-12
// system: the key material and the attestation key live behind the process and
// memory boundary that verifies, refuses, destroys, and mints, and the control
// plane holds neither.
type Runtime struct {
	Gate                       *gate.Gate
	SoftwareCustodyDestroyer   *gate.SoftwareCustodyDestroyer
	HSMCustodyBoundary         *gate.HSMCustodyBoundary
	RecordMinter               *record.Minter
	AggregateMinter            *aggregate.Minter
	ControlPlaneOutageCeremony *gate.CeremonySigner
	Countersigner              *crypto.LockedSigner
	Sink                       gate.RefusalAppendSink
}

func NewRuntime(cfg Config) (*Runtime, error) {
	signerID := strings.TrimSpace(cfg.SignerID)
	if signerID == "" {
		signerID = "trstctl-signer"
	}
	refusalSink, err := gate.NewRefusalSink(cfg.FloorDir)
	if err != nil {
		return nil, fmt.Errorf("vdec signer runtime: build refusal sink: %w", err)
	}
	quorumPolicy, err := gate.LoadQuorumPolicy(cfg.FloorDir)
	if err != nil {
		return nil, fmt.Errorf("vdec signer runtime: load quorum policy: %w", err)
	}
	gated, err := gate.New(gate.Config{SignerID: signerID, Sink: refusalSink, QuorumPolicy: quorumPolicy})
	if err != nil {
		return nil, fmt.Errorf("vdec signer runtime: build gated destruction verifier: %w", err)
	}
	destroyCfg := gate.DestroyConfig{SignerID: signerID, Sink: refusalSink}
	softwareDestroyer := gate.NewSoftwareCustodyDestroyer(destroyCfg)
	hsmBoundary, err := gate.NewHSMCustodyBoundary(unconfiguredHSMModule{}, destroyCfg)
	if err != nil {
		return nil, fmt.Errorf("vdec signer runtime: build HSM custody boundary: %w", err)
	}
	recordMinter, err := record.NewMinter(record.Config{SignerID: signerID})
	if err != nil {
		return nil, fmt.Errorf("vdec signer runtime: build destruction-record minter: %w", err)
	}
	aggregateMinter, err := aggregate.NewMinter(aggregate.Config{SignerID: signerID})
	if err != nil {
		return nil, fmt.Errorf("vdec signer runtime: build aggregate-record minter: %w", err)
	}
	ceremonySigner, err := gate.NewCeremonySigner(gate.CeremonyConfig{SignerID: signerID, QuorumPolicy: quorumPolicy})
	if err != nil {
		return nil, fmt.Errorf("vdec signer runtime: build control-plane-unavailable ceremony signer: %w", err)
	}
	countersigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, fmt.Errorf("vdec signer runtime: build countersignature key: %w", err)
	}
	return &Runtime{
		Gate:                       gated,
		SoftwareCustodyDestroyer:   softwareDestroyer,
		HSMCustodyBoundary:         hsmBoundary,
		RecordMinter:               recordMinter,
		AggregateMinter:            aggregateMinter,
		ControlPlaneOutageCeremony: ceremonySigner,
		Countersigner:              countersigner,
		Sink:                       refusalSink,
	}, nil
}

func (r *Runtime) VerifyGatedDestroy(ctx context.Context, req signing.GatedDestroyRequest) (signing.GatedDestroyDecision, error) {
	if r == nil || r.Gate == nil {
		return signing.GatedDestroyDecision{}, ErrSignerRuntimeUnavailable
	}
	return r.Gate.VerifyGatedDestroy(ctx, req)
}

// FinalizeGatedDestroy runs only after internal/signing has successfully
// destroyed the signer-local handle. It mints the complete public record inside
// this process, so the control plane can persist and verify success but cannot
// manufacture it without the irreversible custody operation.
func (r *Runtime) FinalizeGatedDestroy(ctx context.Context, req signing.GatedDestroyRequest, decision signing.GatedDestroyDecision) (signing.GatedDestroyDecision, error) {
	if r == nil || r.RecordMinter == nil || !decision.Approved {
		return signing.GatedDestroyDecision{}, ErrSignerRuntimeUnavailable
	}
	// Historical low-level callers send only gate.DestroyContextV1. They still
	// receive the gate decision, preserving the generic RPC contract. The served
	// retirement worker adds command_event_id and therefore requires the complete
	// record path below; a malformed claimed finalization remains fail-closed.
	var marker struct {
		CommandEventID string `json:"command_event_id"`
	}
	if err := json.Unmarshal(req.Context, &marker); err != nil || strings.TrimSpace(marker.CommandEventID) == "" {
		return decision, nil
	}
	finalization, err := retirementwire.Decode(req.Context)
	if err != nil {
		return signing.GatedDestroyDecision{}, err
	}
	var quorumEvidence *gate.QuorumEvidence
	if len(decision.Authorization) != 0 {
		decoded, err := gate.DecodeQuorumEvidence(decision.Authorization)
		if err != nil {
			return signing.GatedDestroyDecision{}, err
		}
		publicEvidence, err := gate.RedactQuorumEvidence(decoded)
		if err != nil {
			return signing.GatedDestroyDecision{}, err
		}
		quorumEvidence = &publicEvidence
	}
	evidenceRecord, err := json.Marshal(struct {
		Domain         string `json:"domain"`
		TenantID       string `json:"tenant_id"`
		StableKeyID    string `json:"stable_key_id"`
		HandleSHA256   string `json:"handle_sha256"`
		FinalEpoch     uint64 `json:"final_epoch"`
		CommandEventID string `json:"command_event_id"`
	}{
		Domain: "trstctl/vdec/signer-handle-destroyed/v1", TenantID: req.TenantID,
		StableKeyID: req.SubjectRef, HandleSHA256: crypto.SHA256Hex([]byte(req.Handle)),
		FinalEpoch: req.AssertedFinalEpoch, CommandEventID: finalization.CommandEventID,
	})
	if err != nil {
		return signing.GatedDestroyDecision{}, err
	}
	evidence := gate.DestructionEvidence{
		Kind: gate.TypeCustodyZeroized, TenantID: req.TenantID, StableKeyID: req.SubjectRef,
		FinalEpoch: req.AssertedFinalEpoch, AttestationClass: gate.ClassSoftwareZeroize,
		AttestationClassID: gate.ClassSoftwareZeroize.ID(), Record: evidenceRecord,
		Digest: crypto.SHA256Sum(evidenceRecord),
	}
	signed, err := r.RecordMinter.Mint(ctx, record.MintRequest{
		TenantID: req.TenantID, StableKeyID: req.SubjectRef, FinalEpoch: req.AssertedFinalEpoch,
		CompletionEventsDigest: finalization.CompletionEventsDigest,
		RequiredSetDigest:      req.RequiredSetDigest, QuorumEvidence: quorumEvidence,
		RevocationCompletionDigest: finalization.RevocationCompletionDigest,
		DestructionEvidence:        record.EvidenceFromDestruction(evidence),
		AuditChainHead:             hex.EncodeToString(req.AuditChainHead), PolicyRef: finalization.PolicyRef,
	})
	if err != nil {
		return signing.GatedDestroyDecision{}, err
	}
	encoded, err := record.EncodeRecord(signed)
	if err != nil {
		return signing.GatedDestroyDecision{}, err
	}
	decision.Evidence = encoded
	return decision, nil
}

func (r *Runtime) SignArtifact(ctx context.Context, req signing.ArtifactSignRequest) (signing.ArtifactSignature, error) {
	if err := ctx.Err(); err != nil {
		return signing.ArtifactSignature{}, err
	}
	if r == nil {
		return signing.ArtifactSignature{}, ErrSignerRuntimeUnavailable
	}
	switch req.Kind {
	case ArtifactKindDestructionRecord:
		var mint record.MintRequest
		if err := json.Unmarshal(req.Payload, &mint); err != nil {
			return signing.ArtifactSignature{}, fmt.Errorf("vdec signer runtime: decode destruction record request: %w", err)
		}
		rec, err := r.RecordMinter.Mint(ctx, mint)
		if err != nil {
			return signing.ArtifactSignature{}, err
		}
		return artifactSignature(req.KeyID, defaultDestructionRecordKeyID, rec.AttestationAlgorithm, rec.AttestationPublicKeyDER, rec.Signature), nil
	case ArtifactKindRecordCountersignature:
		if r.Countersigner == nil || r.Sink == nil {
			return signing.ArtifactSignature{}, ErrSignerRuntimeUnavailable
		}
		var rec record.SignedRecord
		if err := json.Unmarshal(req.Payload, &rec); err != nil {
			return signing.ArtifactSignature{}, fmt.Errorf("vdec signer runtime: decode countersignature record: %w", err)
		}
		signed, err := record.AttachCountersignature(ctx, rec, record.CountersignatureRequest{
			AuthorityID: authorityID(req.AuthorityID),
			KeyID:       keyID(req.KeyID, defaultCountersignatureKeyID),
			Signer:      r.Countersigner,
			Sink:        r.Sink,
		})
		if err != nil {
			return signing.ArtifactSignature{}, err
		}
		if len(signed.Countersignatures) == 0 {
			return signing.ArtifactSignature{}, ErrSignerRuntimeUnavailable
		}
		cs := signed.Countersignatures[len(signed.Countersignatures)-1]
		return artifactSignature(cs.KeyID, defaultCountersignatureKeyID, cs.Algorithm, cs.PublicKeyDER, cs.Signature), nil
	case ArtifactKindAggregateRecord:
		if r.AggregateMinter == nil {
			return signing.ArtifactSignature{}, ErrSignerRuntimeUnavailable
		}
		var mint aggregate.MintRequest
		if err := json.Unmarshal(req.Payload, &mint); err != nil {
			return signing.ArtifactSignature{}, fmt.Errorf("vdec signer runtime: decode aggregate record request: %w", err)
		}
		rec, err := r.AggregateMinter.Mint(ctx, mint)
		if err != nil {
			return signing.ArtifactSignature{}, err
		}
		return artifactSignature(req.KeyID, defaultAggregateRecordKeyID, rec.AttestationAlgorithm, rec.AttestationPublicKeyDER, rec.Signature), nil
	default:
		return signing.ArtifactSignature{}, fmt.Errorf("vdec signer runtime: unsupported artifact kind %q", req.Kind)
	}
}

func (r *Runtime) Destroy() {
	if r == nil {
		return
	}
	if r.Gate != nil {
		r.Gate.Destroy()
		r.Gate = nil
	}
	if r.RecordMinter != nil {
		r.RecordMinter.Destroy()
		r.RecordMinter = nil
	}
	if r.AggregateMinter != nil {
		r.AggregateMinter.Destroy()
		r.AggregateMinter = nil
	}
	if r.ControlPlaneOutageCeremony != nil {
		r.ControlPlaneOutageCeremony.Destroy()
		r.ControlPlaneOutageCeremony = nil
	}
	if r.Countersigner != nil {
		r.Countersigner.Destroy()
		r.Countersigner = nil
	}
}

func artifactSignature(requested, fallback string, alg crypto.Algorithm, pub, sig []byte) signing.ArtifactSignature {
	return signing.ArtifactSignature{
		KeyID:        keyID(requested, fallback),
		Algorithm:    alg,
		PublicKeyDER: append([]byte(nil), pub...),
		Signature:    append([]byte(nil), sig...),
	}
}

func authorityID(requested string) string {
	if trimmed := strings.TrimSpace(requested); trimmed != "" {
		return trimmed
	}
	return defaultCountersignatureAuthorityID
}

func keyID(requested, fallback string) string {
	if trimmed := strings.TrimSpace(requested); trimmed != "" {
		return trimmed
	}
	return fallback
}

type unconfiguredHSMModule struct{}

func (unconfiguredHSMModule) DestroyKey(context.Context, gate.HSMDestroyRequest) (gate.HSMDestroyAttestation, error) {
	return gate.HSMDestroyAttestation{}, ErrSignerRuntimeUnavailable
}
