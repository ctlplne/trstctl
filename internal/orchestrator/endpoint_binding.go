// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// BindIdentityEndpoint records the reviewed issuer and destination together.
func (o *Orchestrator) BindIdentityEndpoint(ctx context.Context, tenantID, identityID string, target store.DeploymentTarget, issuer store.IdentityEndpointIssuer) (store.Identity, error) {
	return o.BindIdentityEndpointAtVersion(ctx, tenantID, identityID, target, issuer, nil)
}

// BindIdentityEndpointAtVersion checks lifecycle revision and, when supplied,
// the complete reviewed identity under its row lock. Metadata edits do not
// advance the lifecycle revision. An already matching binding is a no-op.
func (o *Orchestrator) BindIdentityEndpointAtVersion(ctx context.Context, tenantID, identityID string, target store.DeploymentTarget, issuer store.IdentityEndpointIssuer, expectedVersion *uint64, reviewed ...store.Identity) (store.Identity, error) {
	if target.ID == "" || target.Type == "" || target.Name == "" || len(issuer.PreviewFingerprint) != 64 || len(reviewed) > 1 {
		return store.Identity{}, fmt.Errorf("%w: destination and exact reviewed identity are required", store.ErrIdentityEnrollmentConflict)
	}
	err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		identity, version, err := o.store.IdentityApprovalTargetTx(ctx, tx, tenantID, identityID, true)
		if err != nil {
			return err
		}
		if err := store.ValidateIdentityEndpointIssuer(identity, issuer); err != nil {
			return err
		}
		if expectedVersion != nil && version != *expectedVersion {
			return fmt.Errorf("%w: identity changed after preview; preview again", store.ErrIdentityEnrollmentConflict)
		}
		wanted := identity
		if len(reviewed) == 1 {
			wanted = reviewed[0]
		}
		wanted, err = endpointBoundIdentity(wanted, target, issuer)
		if err != nil {
			return err
		}
		same, err := sameIdentitySnapshot(identity, wanted)
		if err != nil {
			return err
		}
		if same {
			return nil
		}
		if len(reviewed) == 1 {
			same, err = sameIdentitySnapshot(identity, reviewed[0])
			if err != nil {
				return err
			}
			if !same {
				return fmt.Errorf("%w: identity metadata changed after preview; preview again", store.ErrIdentityEnrollmentConflict)
			}
		}
		payload, err := json.Marshal(projections.IdentityConnectorTargetBound{IdentityID: identityID, TargetID: target.ID, Connector: target.Type, Target: target.Name, Route: deploymentRoute(target), Issuer: &issuer})
		if err != nil {
			return err
		}
		ev, err := o.log.Append(ctx, events.Event{Type: projections.EventIdentityConnectorTargetBound, TenantID: tenantID, SchemaVersion: 2, Data: payload})
		if err != nil {
			return err
		}
		return o.proj.ApplyTx(ctx, tx, ev)
	})
	if err != nil {
		return store.Identity{}, err
	}
	return o.store.GetIdentity(ctx, tenantID, identityID)
}

func endpointBoundIdentity(identity store.Identity, target store.DeploymentTarget, issuer store.IdentityEndpointIssuer) (store.Identity, error) {
	attrs := map[string]json.RawMessage{}
	if len(identity.Attributes) > 0 {
		if err := json.Unmarshal(identity.Attributes, &attrs); err != nil {
			return store.Identity{}, err
		}
	}
	if attrs == nil {
		return store.Identity{}, fmt.Errorf("%w: identity attributes must be an object", store.ErrIdentityEnrollmentConflict)
	}
	for key, value := range map[string]string{"issuing_authority_source": issuer.Source, "issuing_authority_id": issuer.ID, "issuing_authority_name": issuer.Name, "endpoint_preview_sha256": issuer.PreviewFingerprint, "connector": target.Type, "deployment_connector": target.Type, "target": target.Name, "deployment_target": target.Name, "deployment_target_id": target.ID} {
		raw, err := json.Marshal(value)
		if err != nil {
			return store.Identity{}, err
		}
		attrs[key] = raw
	}
	if issuer.SubjectKeyAlgorithm != "" {
		raw, err := json.Marshal(issuer.SubjectKeyAlgorithm)
		if err != nil {
			return store.Identity{}, err
		}
		attrs["subject_key_algorithm"] = raw
	}
	if route := deploymentRoute(target); route != "" {
		raw, err := json.Marshal(route)
		if err != nil {
			return store.Identity{}, err
		}
		attrs["deployment_route"] = raw
	}
	raw, err := json.Marshal(attrs)
	identity.Attributes = raw
	return identity, err
}

// Compare JSON values, including attributes, without depending on JSONB's key
// ordering or whitespace. Both snapshots contain public identity metadata.
func sameIdentitySnapshot(left, right store.Identity) (bool, error) {
	decode := func(value store.Identity) (any, error) {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		var out any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		err = decoder.Decode(&out)
		return out, err
	}
	a, err := decode(left)
	if err != nil {
		return false, err
	}
	b, err := decode(right)
	if err != nil {
		return false, err
	}
	return reflect.DeepEqual(a, b), nil
}
