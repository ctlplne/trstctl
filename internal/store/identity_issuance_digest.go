// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// identityIssuanceDigestOmits are the identity attributes an issuance
// approval does not bind through its identity digest (A245-L5). The
// destination attributes (the deployment target and the names and route
// written from it) and the issuing-authority attributes are bound on their
// own, by target and revision and by issuer source and ID (A244); the
// authority's name is a label derived from its ID. A renewal pause holds one
// target's renewals and changes nothing an issuance produces.
var identityIssuanceDigestOmits = []string{
	"deployment_target_id", "deployment_target", "deployment_connector", "deployment_route",
	"connector", "target",
	"issuing_authority_source", "issuing_authority_id", "issuing_authority_name",
	identityRenewalPausedAttribute,
}

// IdentityIssuanceDigest is the hex SHA-256 of what an identity contributes
// to the certificate an issuance approval authorizes (A245-L5): its kind,
// name, issuer, validity window and every attribute (the requester's CSR,
// subject names, subject key algorithm, the reviewed endpoint preview and the
// rest) less identityIssuanceDigestOmits. Its owner is not part of it: an
// ownership change does not change what is issued, and ownership readiness
// governs the owner at deployment. The attributes are decoded with exact
// numbers and re-encoded with sorted keys, so the same row reads the same
// digest however it is fetched.
func IdentityIssuanceDigest(identity Identity) (string, error) {
	attributes := map[string]any{}
	if raw := bytes.TrimSpace(identity.Attributes); len(raw) != 0 && !bytes.Equal(raw, []byte("null")) {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&attributes); err != nil {
			return "", fmt.Errorf("store: identity %s attributes: %w", identity.ID, err)
		}
	}
	for _, key := range identityIssuanceDigestOmits {
		delete(attributes, key)
	}
	issuer := ""
	if identity.IssuerID != nil {
		issuer = *identity.IssuerID
	}
	instant := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format(time.RFC3339Nano)
	}
	canonical, err := json.Marshal(struct {
		Domain     string         `json:"domain"`
		Kind       string         `json:"kind"`
		Name       string         `json:"name"`
		IssuerID   string         `json:"issuer_id"`
		NotBefore  string         `json:"not_before"`
		NotAfter   string         `json:"not_after"`
		Attributes map[string]any `json:"attributes"`
	}{
		Domain: "trstctl.identity-issuance.v1", Kind: string(identity.Kind), Name: identity.Name,
		IssuerID: issuer, NotBefore: instant(identity.NotBefore), NotAfter: instant(identity.NotAfter),
		Attributes: attributes,
	})
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(canonical), nil
}
