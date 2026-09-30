// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// IdentityEndpointIssuer records the authority explicitly reviewed for an
// endpoint enrollment. It contains public metadata, never CA credentials.
type IdentityEndpointIssuer struct {
	SubjectKeyAlgorithm string `json:"subject_key_algorithm,omitempty"`
	OwnerID             string `json:"owner_id"`
	Source              string `json:"source"`
	ID                  string `json:"id"`
	Name                string `json:"name"`
	PreviewFingerprint  string `json:"preview_fingerprint"`
}

var ErrIdentityEnrollmentConflict = errors.New("identity cannot be enrolled with this owner and issuer")

// ValidateEndpointReplacementSource requires the exact managed listener. A
// replacement retains the DNS name but is a separate credential lifecycle.
func ValidateEndpointReplacementSource(identity Identity, name, targetID string) error {
	if (identity.Kind != KindX509Certificate && identity.Kind != "x509") ||
		(identity.Status != "deployed" && identity.Status != "renewal_failed" && identity.Status != "revoked") {
		return fmt.Errorf("%w: replacement requires a deployed, renewal_failed, or revoked X.509 identity", ErrIdentityEnrollmentConflict)
	}
	var attrs struct {
		TargetID string `json:"deployment_target_id"`
	}
	if json.Unmarshal(identity.Attributes, &attrs) != nil || targetID == "" || attrs.TargetID != targetID || identity.Name != name {
		return fmt.Errorf("%w: replacement must name the original identity's exact DNS name and destination", ErrIdentityEnrollmentConflict)
	}
	return nil
}

// ActiveEndpointReplacement reads the current successor for an operator preview.
// Execution must recheck with ActiveEndpointReplacementTx under the original's lock.
func (s *Store) ActiveEndpointReplacement(ctx context.Context, tenantID, originalID string) (string, error) {
	var id string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		id, err = s.ActiveEndpointReplacementTx(ctx, tx, tenantID, originalID)
		return err
	})
	return id, err
}

// ActiveEndpointReplacementTx is read under the original identity's row lock
// by replacement creation and renewal. This serializes their decisions about
// the same original. Revocation of the original is always allowed.
func (s *Store) ActiveEndpointReplacementTx(ctx context.Context, tx pgx.Tx, tenantID, originalID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT id::text FROM identities
		WHERE tenant_id = $1 AND attributes->>'endpoint_replaces_identity_id' = $2
		AND status IN ('issued', 'deployed', 'renewing', 'renewal_failed') ORDER BY created_at, id LIMIT 1`, tenantID, originalID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// ConflictingTargetBindings returns active identities that can write to the
// same configured destination. A reviewed replacement may coexist with its
// exact predecessor and its same-target replacement ancestors until the
// operator retires them; any unrelated writer is a conflict. Requested
// identities are included because issuance can still deploy after this read.
func (s *Store) ConflictingTargetBindings(ctx context.Context, tenantID, targetID, identityID, predecessorID string, includeRequested bool) ([]string, error) {
	var conflicts []string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		conflicts, err = s.ConflictingTargetBindingsTx(ctx, tx, tenantID, targetID, identityID, predecessorID, includeRequested)
		return err
	})
	return conflicts, err
}

func (s *Store) ConflictingTargetBindingsTx(ctx context.Context, tx pgx.Tx, tenantID, targetID, identityID, predecessorID string, includeRequested bool) ([]string, error) {
	if targetID == "" {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `WITH RECURSIVE predecessors(id) AS (
		SELECT $4::text WHERE $4 <> ''
		UNION
		SELECT parent.id::text FROM identities current
		JOIN predecessors ON current.id::text = predecessors.id
		JOIN identities parent ON parent.tenant_id = $1
		  AND parent.id::text = current.attributes->>'endpoint_replaces_identity_id'
		  AND parent.attributes->>'deployment_target_id' = $2
		WHERE current.tenant_id = $1 AND current.attributes->>'deployment_target_id' = $2
	)
	SELECT id::text FROM identities
		WHERE tenant_id = $1 AND kind IN ('x509_certificate', 'x509')
		AND attributes->>'deployment_target_id' = $2
		AND id::text <> $3 AND id::text NOT IN (SELECT id FROM predecessors)
		AND (status IN ('issued', 'deployed', 'renewing', 'renewal_failed')
		  OR ($5 AND status = 'requested'))
		ORDER BY id LIMIT 20`, tenantID, targetID, identityID, predecessorID, includeRequested)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var conflicts []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		conflicts = append(conflicts, id)
	}
	return conflicts, rows.Err()
}

// LockTargetBindingTx serializes competing enrollment and renewal decisions
// for one physical destination. Call before ConflictingTargetBindingsTx in a
// mutating command so two requests cannot both observe an empty destination.
func (s *Store) LockTargetBindingTx(ctx context.Context, tx pgx.Tx, tenantID, targetID string) error {
	var id string
	return tx.QueryRow(ctx, `SELECT id::text FROM deployment_targets
		WHERE tenant_id = $1 AND id::text = $2 FOR UPDATE`, tenantID, targetID).Scan(&id)
}

// EndpointReplacementWorkPendingTx refuses to start while earlier issuance,
// renewal, deployment, or rollback can still write to the listener. Payload
// identity_id and target lanes are public routing metadata, outside key seals.
func (s *Store) EndpointReplacementWorkPendingTx(ctx context.Context, tx pgx.Tx, tenantID, originalID, targetID string) (bool, error) {
	var pending bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM outbox
		WHERE tenant_id = $1 AND status IN ('pending', 'processing')
		AND (effect_lane = $3 OR CASE WHEN destination IN
		('ca.issue', 'ca.renew', 'endpoint.renew', 'connector.deploy', 'connector.rollback')
		THEN convert_from(payload, 'UTF8')::jsonb->>'identity_id' = $2 ELSE false END))`, tenantID, originalID, ConnectorTargetLanePrefix+targetID).Scan(&pending)
	return pending, err
}

// ValidateIdentityEndpointIssuer runs on the command before append. An
// enrollment may pin an unconfigured requested identity, but cannot repurpose an
// already managed identity or silently replace its owner or authority.
func ValidateIdentityEndpointIssuer(identity Identity, issuer IdentityEndpointIssuer) error {
	if err := validateEndpointIssuerFields(issuer); err != nil {
		return err
	}
	// The served identity API also accepts the historical "x509" spelling.
	if (identity.Kind != KindX509Certificate && identity.Kind != "x509") || identity.Status != "requested" || identity.OwnerID != issuer.OwnerID {
		return fmt.Errorf("%w: existing identity %s has kind %s, status %s and owner %s; enrollment requires a requested X.509 identity with the selected owner", ErrIdentityEnrollmentConflict, identity.ID, identity.Kind, identity.Status, identity.OwnerID)
	}
	var attributes map[string]json.RawMessage
	if len(identity.Attributes) > 0 {
		if err := json.Unmarshal(identity.Attributes, &attributes); err != nil {
			return fmt.Errorf("%w: invalid existing issuer metadata", ErrIdentityEnrollmentConflict)
		}
	}
	for key, want := range map[string]string{"issuing_authority_source": issuer.Source, "issuing_authority_id": issuer.ID} {
		if raw, exists := attributes[key]; exists {
			var got string
			if json.Unmarshal(raw, &got) != nil || (strings.TrimSpace(got) != "" && got != want) {
				return fmt.Errorf("%w: existing identity %s is pinned to a different issuer; create a separate replacement identity before changing CA", ErrIdentityEnrollmentConflict, identity.ID)
			}
		}
	}
	if issuer.SubjectKeyAlgorithm != "" {
		if raw, exists := attributes["subject_key_algorithm"]; exists {
			var got string
			if json.Unmarshal(raw, &got) != nil || (got != "" && got != issuer.SubjectKeyAlgorithm) {
				return fmt.Errorf("%w: existing subject algorithm differs; create a separate replacement before changing algorithms", ErrIdentityEnrollmentConflict)
			}
		}
	}
	return nil
}

// ValidateEndpointSubjectAlgorithm names the explicit host generators; omission
// retains the historical/default choice. It never maps one algorithm to another.
func ValidateEndpointSubjectAlgorithm(algorithm string) error {
	switch algorithm {
	case "", "ECDSA-P256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87":
		return nil
	default:
		return fmt.Errorf("%w: unsupported subject_key_algorithm %q; no algorithm substitution is authorized", ErrIdentityEnrollmentConflict, algorithm)
	}
}

func validateEndpointIssuerFields(issuer IdentityEndpointIssuer) error {
	if err := ValidateEndpointSubjectAlgorithm(issuer.SubjectKeyAlgorithm); err != nil {
		return err
	}
	if issuer.OwnerID == "" || issuer.ID == "" || issuer.Name == "" ||
		(issuer.Source != "platform" && issuer.Source != "private" && issuer.Source != "external") {
		return fmt.Errorf("%w: an exact owner and issuer are required", ErrIdentityEnrollmentConflict)
	}
	return nil
}

// BindIdentityEndpointIssuerTx replays accepted public authority metadata.
// Validate the immutable payload, not today's lifecycle: inline application may
// have already issued or revoked the identity before background catch-up reads
// the original binding event. New commands still validate owner, status, and CA
// under the identity lock before appending that event.
func (s *Store) BindIdentityEndpointIssuerTx(ctx context.Context, tx pgx.Tx, tenantID, identityID string, issuer IdentityEndpointIssuer) error {
	if err := validateEndpointIssuerFields(issuer); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE identities
		SET attributes = attributes || jsonb_build_object(
			'issuing_authority_source', $3::text, 'issuing_authority_id', $4::text,
			'issuing_authority_name', $5::text, 'endpoint_preview_sha256', $6::text)
            || CASE WHEN $7::text = '' THEN '{}'::jsonb ELSE jsonb_build_object('subject_key_algorithm', $7::text) END
		WHERE tenant_id = $1 AND id = $2`, tenantID, identityID, issuer.Source, issuer.ID, issuer.Name, issuer.PreviewFingerprint, issuer.SubjectKeyAlgorithm)
	return err
}
