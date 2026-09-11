// SPDX-License-Identifier: MPL-2.0

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
	OwnerID            string `json:"owner_id"`
	Source             string `json:"source"`
	ID                 string `json:"id"`
	Name               string `json:"name"`
	PreviewFingerprint string `json:"preview_fingerprint"`
}

var ErrIdentityEnrollmentConflict = errors.New("identity cannot be enrolled with this owner and issuer")

// ValidateIdentityEndpointIssuer runs before append and during projection. An
// enrollment may pin an unconfigured requested identity, but cannot repurpose an
// already managed identity or silently replace its owner or authority.
func ValidateIdentityEndpointIssuer(identity Identity, issuer IdentityEndpointIssuer) error {
	if issuer.OwnerID == "" || issuer.ID == "" || issuer.Name == "" ||
		(issuer.Source != "platform" && issuer.Source != "private" && issuer.Source != "external") {
		return fmt.Errorf("%w: an exact owner and issuer are required", ErrIdentityEnrollmentConflict)
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
	return nil
}

// BindIdentityEndpointIssuerTx projects only public authority metadata. The
// caller holds the same identity lock across validation and event application.
func (s *Store) BindIdentityEndpointIssuerTx(ctx context.Context, tx pgx.Tx, tenantID, identityID string, issuer IdentityEndpointIssuer) error {
	identity, _, err := s.IdentityApprovalTargetTx(ctx, tx, tenantID, identityID, true)
	if err != nil {
		return err
	}
	if err := ValidateIdentityEndpointIssuer(identity, issuer); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE identities
		SET attributes = attributes || jsonb_build_object(
			'issuing_authority_source', $3::text, 'issuing_authority_id', $4::text,
			'issuing_authority_name', $5::text, 'endpoint_preview_sha256', $6::text)
		WHERE tenant_id = $1 AND id = $2`, tenantID, identityID, issuer.Source, issuer.ID, issuer.Name, issuer.PreviewFingerprint)
	return err
}
