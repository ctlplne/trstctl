// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
)

// EventSecretDeliveryReported is a consumer's report of the secret versions it
// wrote (injected) or its application proved it uses (verified) (A238).
const EventSecretDeliveryReported = "secret.delivery.reported" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)

// SecretDeliveryItem is one secret version in a report.
type SecretDeliveryItem struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// SecretDeliveryReported is the payload of secret.delivery.reported.
type SecretDeliveryReported struct {
	Consumer   string               `json:"consumer"`
	State      string               `json:"state"`
	Items      []SecretDeliveryItem `json:"items"`
	ReportedBy string               `json:"reported_by"`
}

func init() {
	knownSchemaVersions[EventSecretDeliveryReported] = map[int]bool{1: true}
}

func (p *Projector) applySecretDeliveryTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != EventSecretDeliveryReported {
		return false, nil
	}
	var pl SecretDeliveryReported
	if err := decode(e, &pl); err != nil {
		return true, err
	}
	if pl.Consumer == "" || len(pl.Items) == 0 || e.Time.IsZero() {
		return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
	}
	for _, item := range pl.Items {
		if err := p.store.ApplySecretDeliveryReportedTx(ctx, tx, e.TenantID, pl.Consumer, pl.State, item.Name, item.Version,
			pl.ReportedBy, e.Time, e.Sequence); err != nil {
			return true, err
		}
	}
	return true, nil
}

// addSecretDeliveryPrivacyPolicies: the reporter is an identity; consumer
// labels, names and versions are opaque.
func addSecretDeliveryPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	policies[privacyEventPolicyKey{EventSecretDeliveryReported, 1}] = privacyRules(
		privacyRule("/consumer", events.PrivacyFieldOpaqueExact), privacyRule("/state", events.PrivacyFieldOpaqueExact),
		privacyRule("/items/*/name", events.PrivacyFieldOpaqueExact), privacyRule("/items/*/version", events.PrivacyFieldOpaqueExact),
		privacyRule("/reported_by", events.PrivacyFieldIdentityExact))
}

func addSecretDeliveryPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventSecretDeliveryReported, 1}] = privacyPayloadShape[SecretDeliveryReported]()
}
