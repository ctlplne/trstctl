// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// EndpointReplacementIdentityID binds a successor to one exact reviewed request.
// Preview and execution share this derivation so preview can refuse a different
// active successor without breaking recovery of the already accepted request.
func EndpointReplacementIdentityID(tenantID, originalID, previewFingerprint string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("endpoint-replacement\x00"+tenantID+"\x00"+originalID+"\x00"+previewFingerprint)).String()
}

// EnsureEndpointReplacement prepares one successor for an exact reviewed
// original. Its deterministic identity and event make a retry after creation
// safe even when the HTTP response was never cached. Issuance still goes through
// the normal policy, approval, lifecycle event, and outbox path afterward.
func (o *Orchestrator) EnsureEndpointReplacement(ctx context.Context, tenantID string, reviewed store.Identity, version uint64, target store.DeploymentTarget, issuer store.IdentityEndpointIssuer) (store.Identity, error) {
	return o.EnsureEndpointReplacementWithProfile(ctx, tenantID, reviewed, version, target, issuer, "")
}

// EnsureEndpointReplacementWithProfile retains the explicitly selected policy
// on the new identity. Its revision is authorized by the normal issuance gate;
// the original identity's policy is never changed by replacement preparation.
func (o *Orchestrator) EnsureEndpointReplacementWithProfile(ctx context.Context, tenantID string, reviewed store.Identity, version uint64, target store.DeploymentTarget, issuer store.IdentityEndpointIssuer, profileName string) (store.Identity, error) {
	if reviewed.TenantID != tenantID || len(issuer.PreviewFingerprint) != 64 || target.ID == "" || target.Type == "" || target.Name == "" {
		return store.Identity{}, fmt.Errorf("%w: exact tenant, original, destination, and preview are required", store.ErrIdentityEnrollmentConflict)
	}
	id := EndpointReplacementIdentityID(tenantID, reviewed.ID, issuer.PreviewFingerprint)
	reviewedJSON, err := json.Marshal(reviewed)
	if err != nil {
		return store.Identity{}, err
	}
	attrs := map[string]string{
		"endpoint_replaces_identity_id": reviewed.ID,
		"endpoint_original_version":     strconv.FormatUint(version, 10),
		"endpoint_original_sha256":      crypto.SHA256Hex(reviewedJSON),
		"issuing_authority_source":      issuer.Source, "issuing_authority_id": issuer.ID,
		"issuing_authority_name": issuer.Name, "endpoint_preview_sha256": issuer.PreviewFingerprint,
		"connector": target.Type, "deployment_connector": target.Type,
		"target": target.Name, "deployment_target": target.Name, "deployment_target_id": target.ID,
	}
	if issuer.SubjectKeyAlgorithm != "" {
		attrs["subject_key_algorithm"] = issuer.SubjectKeyAlgorithm
	}
	if profileName != "" {
		attrs["profile_name"] = profileName
	}
	if route := deploymentRoute(target); route != "" {
		attrs["deployment_route"] = route
	}
	attributes, err := json.Marshal(attrs)
	if err != nil {
		return store.Identity{}, err
	}
	created := store.Identity{ID: id, TenantID: tenantID, Kind: store.KindX509Certificate,
		Name: reviewed.Name, OwnerID: issuer.OwnerID, Status: "requested", Attributes: attributes}
	if err := store.ValidateIdentityEndpointIssuer(created, issuer); err != nil {
		return store.Identity{}, err
	}
	if err := store.ValidateEndpointReplacementSource(reviewed, created.Name, target.ID); err != nil {
		return store.Identity{}, err
	}
	err = o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		original, currentVersion, err := o.store.IdentityApprovalTargetTx(ctx, tx, tenantID, reviewed.ID, true)
		if err != nil {
			return err
		}
		want, err := json.Marshal(reviewed)
		if err != nil {
			return err
		}
		got, err := json.Marshal(original)
		if err != nil {
			return err
		}
		if currentVersion != version || !bytes.Equal(got, want) {
			return fmt.Errorf("%w: original identity changed after preview; preview again", store.ErrIdentityEnrollmentConflict)
		}
		active, err := o.store.ActiveEndpointReplacementTx(ctx, tx, tenantID, original.ID)
		if err != nil {
			return err
		}
		if active != "" && active != id {
			return fmt.Errorf("%w: original already has active replacement %s; complete or revoke it before starting another", store.ErrIdentityEnrollmentConflict, active)
		}
		if existing, _, err := o.store.IdentityApprovalTargetTx(ctx, tx, tenantID, id, true); err == nil {
			var existingAttrs map[string]string
			if json.Unmarshal(existing.Attributes, &existingAttrs) != nil || existing.Kind != created.Kind ||
				existing.Name != created.Name || existing.OwnerID != created.OwnerID {
				return fmt.Errorf("%w: replacement no longer matches its reviewed request", store.ErrIdentityEnrollmentConflict)
			}
			for key, want := range attrs {
				if existingAttrs[key] != want {
					return fmt.Errorf("%w: replacement binding changed", store.ErrIdentityEnrollmentConflict)
				}
			}
			if existingAttrs["profile_name"] != profileName || existingAttrs["profile"] != "" || existingAttrs["subject_key_algorithm"] != issuer.SubjectKeyAlgorithm {
				return fmt.Errorf("%w: replacement certificate profile changed", store.ErrIdentityEnrollmentConflict)
			}
			if existing.Status == "revoked" || existing.Status == "retired" {
				return fmt.Errorf("%w: this replacement was closed; preview a new request with a new reason", store.ErrIdentityEnrollmentConflict)
			}
			return nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		pending, err := o.store.EndpointReplacementWorkPendingTx(ctx, tx, tenantID, original.ID, target.ID)
		if err != nil {
			return err
		}
		if pending {
			return fmt.Errorf("%w: earlier lifecycle or destination work is pending; wait for its terminal receipt before replacement", store.ErrIdentityEnrollmentConflict)
		}
		payload, err := json.Marshal(projections.IdentityCreated{ID: id, Kind: string(created.Kind), Name: created.Name,
			OwnerID: created.OwnerID, Attributes: attributes})
		if err != nil {
			return err
		}
		eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("endpoint-replacement-event\x00"+tenantID+"\x00"+id)).String()
		ev, err := o.log.Append(ctx, events.Event{ID: eventID, TenantID: tenantID, Type: projections.EventIdentityCreated, SchemaVersion: 1, Data: payload})
		if err != nil {
			return err
		}
		if ev.ID != eventID || ev.TenantID != tenantID || ev.Type != projections.EventIdentityCreated || ev.SchemaVersion != 1 || !bytes.Equal(ev.Data, payload) {
			return fmt.Errorf("%w: retained replacement event differs from the reviewed request", store.ErrIdempotencyConflict)
		}
		return o.proj.ApplyTx(ctx, tx, ev)
	})
	if err != nil {
		return store.Identity{}, err
	}
	return o.store.GetIdentity(ctx, tenantID, id)
}

// validateEndpointReplacementIssuanceTx acquires the original before the new
// identity (the same lock order as preparation). Requested records alone never
// pause renewal: a policy denial must not strand the currently valid endpoint.
// Only the successor that wins the issued transition reserves the handoff.
func (o *Orchestrator) validateEndpointReplacementIssuanceTx(ctx context.Context, tx pgx.Tx, tenantID string, identity store.Identity) error {
	if len(identity.Attributes) == 0 {
		return nil
	}
	var attrs map[string]string
	// Other identity attributes may contain objects; decode only this contract.
	var binding struct {
		OriginalID string `json:"endpoint_replaces_identity_id"`
		Version    string `json:"endpoint_original_version"`
		Snapshot   string `json:"endpoint_original_sha256"`
	}
	if err := json.Unmarshal(identity.Attributes, &binding); err != nil {
		return err
	}
	if binding.OriginalID == "" {
		return nil
	}
	if err := json.Unmarshal(identity.Attributes, &attrs); err != nil {
		return err
	}
	original, version, err := o.store.IdentityApprovalTargetTx(ctx, tx, tenantID, binding.OriginalID, true)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(original)
	if err != nil {
		return err
	}
	if binding.Version != strconv.FormatUint(version, 10) || binding.Snapshot != crypto.SHA256Hex(raw) {
		return fmt.Errorf("%w: original identity changed before replacement issuance; preview again", store.ErrIdentityEnrollmentConflict)
	}
	if err := store.ValidateEndpointReplacementSource(original, identity.Name, attrs["deployment_target_id"]); err != nil {
		return err
	}
	active, err := o.store.ActiveEndpointReplacementTx(ctx, tx, tenantID, original.ID)
	if err != nil {
		return err
	}
	if active != "" && active != identity.ID {
		return fmt.Errorf("%w: original already has active replacement %s", store.ErrIdentityEnrollmentConflict, active)
	}
	pending, err := o.store.EndpointReplacementWorkPendingTx(ctx, tx, tenantID, original.ID, attrs["deployment_target_id"])
	if err != nil {
		return err
	}
	if pending {
		return fmt.Errorf("%w: earlier lifecycle or destination work is pending", store.ErrIdentityEnrollmentConflict)
	}
	return nil
}
