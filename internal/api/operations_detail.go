// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// One operation's causal chain (A245): the request, the authority that let it
// run, the external action, the receipt, the consumer's observation and, for a
// revoked identity, where its revocation report is — with the retry and
// rollback that apply to exactly this operation.

const (
	linkDone        = "done"
	linkPending     = "pending"
	linkFailed      = "failed"
	linkUncertain   = "uncertain"
	linkNotObserved = "not_observed"
)

var operationLinkStates = []string{linkDone, linkPending, linkFailed, linkUncertain, linkNotObserved}

type operationLink struct {
	// Step is request, authority, external_action, receipt, observation or
	// revocation.
	Step   string     `json:"step"`
	State  string     `json:"state"`
	Detail string     `json:"detail"`
	At     *time.Time `json:"at,omitempty"`
	Path   string     `json:"path,omitempty"`
}

type operationAction struct {
	// Action is retry or rollback.
	Action    string `json:"action"`
	Available bool   `json:"available"`
	// Scope says exactly what the action touches.
	Scope  string `json:"scope"`
	Reason string `json:"reason,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	// Body is the exact, value-free request an available action sends, and
	// PreviewPath the route that reviews that same request without effects
	// when one exists (A245-L4): the console runs the action in place,
	// through that review and the route's own approval, rather than linking
	// to another page.
	Body        json.RawMessage `json:"body,omitempty"`
	PreviewPath string          `json:"preview_path,omitempty"`
}

// operationActionBody is an action's request body.
func operationActionBody(fields map[string]any) json.RawMessage {
	raw, err := json.Marshal(fields)
	if err != nil {
		return nil
	}
	return raw
}

type operationDetail struct {
	operationLedgerItem
	Chain   []operationLink   `json:"chain"`
	Actions []operationAction `json:"actions"`
}

func parseOperationID(id string) (source, sourceID string, ok bool) {
	source, sourceID, found := strings.Cut(id, ":")
	if !found || !slices.Contains(operationSources, source) || !validUUIDText(sourceID) {
		return "", "", false
	}
	return source, sourceID, true
}

func validUUIDText(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
		default:
			return false
		}
	}
	return true
}

func (a *API) getOperationLedgerItem(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	source, sourceID, ok := parseOperationID(r.PathValue("id"))
	if !ok {
		a.writeError(w, errStatus(http.StatusNotFound, "resource not found"))
		return
	}
	row, err := a.store.GetOperationLedgerRow(r.Context(), tenantID, source, sourceID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	if !a.operationVisible(r, principal, tenantID, row) {
		a.writeError(w, errStatus(http.StatusNotFound, "resource not found"))
		return
	}
	item, err := a.operationLedgerItem(r, tenantID, row)
	if err != nil {
		a.writeError(w, err)
		return
	}
	detail := operationDetail{operationLedgerItem: item}
	if detail.Chain, err = a.operationChain(r, tenantID, row, item); err != nil {
		a.writeError(w, err)
		return
	}
	if detail.Actions, err = a.operationActions(r, tenantID, row, item); err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, detail)
}

func (a *API) operationChain(r *http.Request, tenantID string, row store.OperationLedgerRow, item operationLedgerItem) ([]operationLink, error) {
	created := row.CreatedAt
	chain := []operationLink{{Step: "request", State: linkDone, At: &created, Detail: firstNonEmpty(row.Origin, "requested")}}
	if row.Source == "approval" {
		state := linkPending
		switch row.Status {
		case "approved":
			state = linkDone
		case "denied", "expired", "superseded":
			state = linkFailed
		}
		chain = append(chain, operationLink{Step: "authority", State: state, Detail: "this approval: " + item.StateReason})
		return chain, nil
	}
	if row.SubjectID != "" {
		approval, found, err := a.store.ConsumedApprovalFor(r.Context(), tenantID, row.SubjectID, row.UpdatedAt)
		if err != nil {
			return nil, err
		}
		if found {
			at := approval.UpdatedAt
			chain = append(chain, operationLink{Step: "authority", State: linkDone, At: &at,
				Detail: fmt.Sprintf("authorized by approval %s (%s, %d of %d approvals)", approval.ID, approval.Action, approval.ApprovalCount, approval.RequiredApprovals)})
		} else {
			chain = append(chain, operationLink{Step: "authority", State: linkDone,
				Detail: "authorized by the caller's permission; no approval was asked for"})
		}
	}
	if row.OutboxID != nil {
		link := operationLink{Step: "external_action", Detail: fmt.Sprintf("command %d: %s after %d attempts", *row.OutboxID, firstNonEmpty(row.OutboxStatus, "retired"), row.OutboxAttempts)}
		switch {
		case row.Quarantined || row.OutboxLeaseExpired:
			link.State = linkUncertain
		case row.OutboxStatus == "delivered" || row.OutboxStatus == "":
			link.State = linkDone
		case row.OutboxStatus == "failed" || row.OutboxStatus == "dead":
			link.State = linkFailed
		default:
			link.State = linkPending
		}
		chain = append(chain, link)
	}
	updated := row.UpdatedAt
	receipt := operationLink{Step: "receipt", At: &updated, Detail: row.Source + " " + row.Status}
	if strings.TrimSpace(row.Detail) != "" {
		receipt.Detail += ": " + row.Detail
	}
	switch item.State {
	case opStateFailed:
		receipt.State = linkFailed
	case opStateQueued, opStateExecuting, opStateAwaitingApproval, opStateReviewed:
		receipt.State = linkPending
	case opStateUncertain:
		receipt.State = linkUncertain
	default:
		receipt.State = linkDone
	}
	chain = append(chain, receipt)
	observation := operationLink{Step: "observation", State: linkNotObserved, Detail: "no consumer has confirmed it"}
	switch item.State {
	case opStateVerified:
		observation = operationLink{Step: "observation", State: linkDone, Detail: item.StateReason}
	case opStateDelivered:
		observation.Detail = item.StateReason
	}
	chain = append(chain, observation)
	if row.SubjectID != "" && row.Source != "secret_rotation" {
		identity, err := a.store.GetIdentity(r.Context(), tenantID, row.SubjectID)
		if err == nil && (identity.Status == "revoked" || identity.Status == "retired") {
			chain = append(chain, operationLink{Step: "revocation", State: linkDone, Detail: "the identity is " + identity.Status + "; its revocation report separates the CA, the deployed material, new connections and open sessions",
				Path: "/api/v1/identities/" + identity.ID + "/revocation-report"})
		} else if err != nil && !store.IsNotFound(err) {
			return nil, err
		}
	}
	return chain, nil
}

func (a *API) operationActions(r *http.Request, tenantID string, row store.OperationLedgerRow, item operationLedgerItem) ([]operationAction, error) {
	actions := []operationAction{}
	targetID, identityStatus := "", ""
	if row.SubjectID != "" && (row.Source == "connector_delivery" || row.Source == "certificate_rotation") {
		identity, err := a.store.GetIdentity(r.Context(), tenantID, row.SubjectID)
		if err != nil && !store.IsNotFound(err) {
			return nil, err
		}
		var attrs struct {
			Target string `json:"deployment_target_id"`
		}
		if err == nil && len(identity.Attributes) > 0 {
			_ = json.Unmarshal(identity.Attributes, &attrs)
		}
		targetID = attrs.Target
		if err == nil {
			identityStatus = identity.Status
		}
	}
	failed := item.State == opStateFailed || item.State == opStateUncertain
	switch row.Source {
	case "connector_delivery":
		retry := operationAction{Action: "retry", Scope: fmt.Sprintf("deliver %s's active certificate to %s again", row.SubjectName, row.Target)}
		switch {
		case !failed:
			retry.Reason = "the delivery did not fail"
		case targetID == "":
			retry.Reason = "the identity is no longer bound to a destination"
		case identityStatus == "issued":
			// Never delivered: its first deployment can still be sent.
			retry.Available, retry.Method, retry.Path = true, http.MethodPost, "/api/v1/connectors/targets/"+targetID+"/deploy"
			retry.Body = operationActionBody(map[string]any{"identity_id": row.SubjectID, "reason": "retry of operation " + item.ID})
		case identityStatus == "deployed" || identityStatus == "renewal_failed":
			// A delivery can't be repeated: no private key is kept to deliver
			// again. The retry renews through the bound issuer and delivers the
			// new certificate (A245-L4).
			retry.Scope = fmt.Sprintf("renew %s through its bound issuer and deliver the new certificate to %s (no private key is kept to repeat a delivery)", row.SubjectName, row.Target)
			retry.Available, retry.Method, retry.Path = true, http.MethodPost, "/api/v1/identities/"+row.SubjectID+"/transitions"
			retry.PreviewPath = "/api/v1/identities/" + row.SubjectID + "/transitions/preview"
			retry.Body = operationActionBody(map[string]any{"to": "renewing", "reason": "retry of operation " + item.ID})
		default:
			retry.Reason = "the identity is " + firstNonEmpty(identityStatus, "gone") + "; only an issued, deployed or renewal-failed identity is retried"
		}
		rollback := operationAction{Action: "rollback", Scope: fmt.Sprintf("restore the certificate %s held before this delivery", row.Target)}
		switch {
		case row.RollbackRef == "":
			rollback.Reason = "no predecessor was recorded for this delivery"
		case targetID == "":
			rollback.Reason = "the identity is no longer bound to a destination"
		case row.Status != "delivered" && row.Status != "verified":
			rollback.Reason = "only a completed delivery can be rolled back"
		default:
			rollback.Available, rollback.Method, rollback.Path = true, http.MethodPost, "/api/v1/connectors/targets/"+targetID+"/rollback"
			rollback.Body = operationActionBody(map[string]any{"identity_id": row.SubjectID, "reason": "rollback of operation " + item.ID})
		}
		actions = append(actions, retry, rollback)
	case "certificate_rotation":
		retry := operationAction{Action: "retry", Scope: fmt.Sprintf("renew %s once, through its bound issuer and destination", row.SubjectName)}
		if failed {
			retry.Available, retry.Method, retry.Path = true, http.MethodPost, "/api/v1/identities/"+row.SubjectID+"/transitions"
			retry.PreviewPath = "/api/v1/identities/" + row.SubjectID + "/transitions/preview"
			retry.Body = operationActionBody(map[string]any{"to": "renewing", "reason": "retry of operation " + item.ID})
		} else {
			retry.Reason = "the rotation did not fail"
		}
		rollback := operationAction{Action: "rollback", Scope: fmt.Sprintf("restore %s's predecessor certificate at its destination", row.SubjectName)}
		switch {
		case row.RollbackRef == "":
			rollback.Reason = "no predecessor was recorded for this rotation"
		case targetID == "":
			rollback.Reason = "the identity is no longer bound to a destination"
		default:
			rollback.Available, rollback.Method, rollback.Path = true, http.MethodPost, "/api/v1/connectors/targets/"+targetID+"/rollback"
			rollback.Body = operationActionBody(map[string]any{"identity_id": row.SubjectID, "reason": "rollback of operation " + item.ID})
		}
		actions = append(actions, retry, rollback)
	case "secret_rotation":
		retry := operationAction{Action: "retry", Scope: fmt.Sprintf("rotate %s again at its provider", row.SubjectName)}
		if failed || item.State == opStateRecovered {
			command, err := a.store.GetSecretStaticRotationCommand(r.Context(), tenantID, row.ID)
			if err != nil && !store.IsNotFound(err) {
				return nil, err
			}
			if err != nil {
				retry.Reason = "the rotation's command is no longer recorded"
			} else {
				retry.Available, retry.Method, retry.Path = true, http.MethodPost, "/api/v1/secrets/rotations"
				retry.PreviewPath = "/api/v1/secrets/rotations/preview"
				retry.Body = operationActionBody(secretRotationRetryBody(command))
			}
		} else {
			retry.Reason = "the rotation did not fail"
		}
		actions = append(actions, retry, operationAction{Action: "rollback", Scope: fmt.Sprintf("return %s to its predecessor", row.SubjectName),
			Reason: "a failed rotation rolls back by itself; a completed one is undone by rotating again"})
	}
	return actions, nil
}

// secretRotationRetryBody is the request that rotates a failed rotation's
// secret again: the same provider, key and predecessor, lifetime, consumers
// and retirement gate (A245-L4).
func secretRotationRetryBody(c store.SecretStaticRotationCommand) map[string]any {
	body := map[string]any{"provider": c.Provider, "key": c.Key, "old_ref": c.OldRef}
	if c.TTLSeconds > 0 {
		body["ttl_seconds"] = c.TTLSeconds
	}
	if len(c.Consumers) > 0 {
		body["consumers"] = c.Consumers
	}
	if c.RetireAfterSeconds > 0 {
		body["retire_after_seconds"] = c.RetireAfterSeconds
	}
	if c.SinglePhaseAcknowledged {
		body["acknowledge_single_phase"] = true
	}
	return body
}
