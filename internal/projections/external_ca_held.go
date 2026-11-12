// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// N1-L1: an external CA issuance the CA holds for a manager's approval (AD CS's
// "taken under submission"), recorded by the CA's own request id when the
// issuance gives up waiting, and how it was resolved once read back: the CA
// issued it, or refused it.
const (
	EventExternalCAIssueHeld    = "certificate.external_issue_held"
	EventExternalCAIssueResumed = "certificate.external_issue_resumed"
)

// ExternalCAIssueHeld is the payload of certificate.external_issue_held. The
// issue key, request binding and key origin are the held issuance's own, so a
// resumed certificate is recorded under the issuance its caller waits on.
type ExternalCAIssueHeld struct {
	AuthorityID    string   `json:"authority_id"`
	CARequestID    int      `json:"ca_request_id"`
	IssueKey       string   `json:"issue_key"`
	RequestBinding string   `json:"request_binding"`
	KeyOrigin      string   `json:"key_origin,omitempty"`
	DNSNames       []string `json:"dns_names,omitempty"`
}

// ExternalCAIssueResumed is the payload of certificate.external_issue_resumed.
type ExternalCAIssueResumed struct {
	AuthorityID string `json:"authority_id"`
	CARequestID int    `json:"ca_request_id"`
	Status      string `json:"status"`
	Serial      string `json:"serial,omitempty"`
}

// ValidateExternalCAIssueHeld checks a held issuance's closed shape.
func ValidateExternalCAIssueHeld(h ExternalCAIssueHeld) error {
	if h.AuthorityID == "" || h.CARequestID <= 0 || h.IssueKey == "" || h.RequestBinding == "" {
		return errors.New("projections: a held external CA issuance needs its authority, CA request id, issue key and request binding")
	}
	return nil
}

// ValidateExternalCAIssueResumed checks a resolution's closed shape.
func ValidateExternalCAIssueResumed(r ExternalCAIssueResumed) error {
	switch {
	case r.AuthorityID == "" || r.CARequestID <= 0:
		return errors.New("projections: a resumed external CA issuance needs its authority and CA request id")
	case r.Status == store.ExternalCAHeldIssueIssued && r.Serial == "":
		return errors.New("projections: an issued resumption names the certificate's serial")
	case r.Status != store.ExternalCAHeldIssueIssued && r.Status != store.ExternalCAHeldIssueDenied:
		return errors.New("projections: a resumed external CA issuance is issued or denied")
	}
	return nil
}

func init() {
	for _, typ := range []string{EventExternalCAIssueHeld, EventExternalCAIssueResumed} {
		knownSchemaVersions[typ] = map[int]bool{1: true}
	}
}

func (p *Projector) applyExternalCAHeldTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventExternalCAIssueHeld:
		var h ExternalCAIssueHeld
		if err := json.Unmarshal(e.Data, &h); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		if err := ValidateExternalCAIssueHeld(h); err != nil {
			return true, err
		}
		return true, p.store.ApplyExternalCAIssueHeldTx(ctx, tx, e.TenantID, store.ExternalCAHeldIssue{AuthorityID: h.AuthorityID,
			CARequestID: h.CARequestID, IssueKey: h.IssueKey, RequestBinding: h.RequestBinding, KeyOrigin: h.KeyOrigin,
			DNSNames: h.DNSNames, HeldAt: e.Time}, e.Sequence)
	case EventExternalCAIssueResumed:
		var r ExternalCAIssueResumed
		if err := json.Unmarshal(e.Data, &r); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		if err := ValidateExternalCAIssueResumed(r); err != nil {
			return true, err
		}
		return true, p.store.ApplyExternalCAIssueResumedTx(ctx, tx, e.TenantID, r.AuthorityID, r.CARequestID, r.Status, r.Serial, e.Time, e.Sequence)
	}
	return false, nil
}

func addExternalCAHeldPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		opaque = events.PrivacyFieldOpaqueExact
		token  = events.PrivacyFieldSubjectToken
	)
	policies[privacyEventPolicyKey{EventExternalCAIssueHeld, 1}] = privacyRules(
		privacyRule("/authority_id", opaque), privacyRule("/ca_request_id", opaque), privacyRule("/issue_key", opaque),
		privacyRule("/request_binding", opaque), privacyRule("/key_origin", opaque), privacyRule("/dns_names/*", token))
	policies[privacyEventPolicyKey{EventExternalCAIssueResumed, 1}] = privacyRules(
		privacyRule("/authority_id", opaque), privacyRule("/ca_request_id", opaque), privacyRule("/status", opaque),
		privacyRule("/serial", opaque))
}

func addExternalCAHeldPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventExternalCAIssueHeld, 1}] = privacyPayloadShape[ExternalCAIssueHeld]()
	shapes[privacyEventPolicyKey{EventExternalCAIssueResumed, 1}] = privacyPayloadShape[ExternalCAIssueResumed]()
}
