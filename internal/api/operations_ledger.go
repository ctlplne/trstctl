// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// One operations view for rotation, revocation and proof (A245): every
// certificate rotation, connector delivery, secret rotation and approval in one
// normalized state, read from the projections that already record them.
// Verified needs consumer evidence — a connector readback, an endpoint seen
// presenting the certificate, or every named consumer reporting the new
// version — never an HTTP 200 or an outbox receipt alone.

const (
	opStateReviewed         = "reviewed"
	opStateAwaitingApproval = "awaiting_approval"
	opStateQueued           = "queued"
	opStateExecuting        = "executing"
	opStateDelivered        = "delivered"
	opStateVerified         = "verified"
	opStateFailed           = "failed"
	opStateUncertain        = "uncertain"
	opStateRecovered        = "recovered"
)

var operationStates = []string{opStateReviewed, opStateAwaitingApproval, opStateQueued, opStateExecuting,
	opStateDelivered, opStateVerified, opStateFailed, opStateUncertain, opStateRecovered}

var operationSources = []string{"certificate_rotation", "connector_delivery", "secret_rotation", "approval"}

type operationSubject struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

type operationOutbox struct {
	ID       int64  `json:"id"`
	Status   string `json:"status"`
	Attempts int    `json:"attempts"`
}

type operationLedgerItem struct {
	// ID is "<source>:<source id>".
	ID             string           `json:"id"`
	Source         string           `json:"source"`
	CredentialType string           `json:"credential_type"`
	Subject        operationSubject `json:"subject"`
	State          string           `json:"state"`
	StateReason    string           `json:"state_reason"`
	// SourceStatus is the source's own status or phase, unchanged.
	SourceStatus    string           `json:"source_status"`
	Fingerprint     string           `json:"fingerprint,omitempty"`
	Outbox          *operationOutbox `json:"outbox,omitempty"`
	ObservedVantage string           `json:"observed_vantage,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

type operationLedgerPage struct {
	Items      []operationLedgerItem `json:"items"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

// normalizeOperation maps one source row onto the shared states. adoption is
// a secret rotation's consumer adoption (not_requested, pending, adopted).
func normalizeOperation(r store.OperationLedgerRow, adoption string) (string, string) {
	inFlight := func() (string, string) {
		switch {
		case r.Quarantined:
			return opStateUncertain, "the external effect's outcome is unknown: its command is quarantined for reconciliation"
		case r.OutboxLeaseExpired:
			return opStateUncertain, "the worker's lease on the external effect ran out; its outcome is unknown until the command is reconciled"
		case r.OutboxStatus == "processing" || (r.OutboxStatus == "pending" && r.OutboxAttempts > 0):
			return opStateExecuting, "the external effect is running"
		default:
			return opStateQueued, "waiting for a worker"
		}
	}
	seen := func(what string) (string, string) {
		switch {
		case r.ReadBack:
			return opStateVerified, "the connector read the delivered certificate back"
		case r.ObservedVantage != "":
			return opStateVerified, "an endpoint was seen presenting it (" + r.ObservedVantage + " vantage)"
		default:
			return opStateDelivered, what + "; nothing has read it back or seen an endpoint present it"
		}
	}
	or := func(detail, fallback string) string {
		if strings.TrimSpace(detail) != "" {
			return detail
		}
		return fallback
	}
	switch r.Source {
	case "certificate_rotation":
		switch r.Status {
		case "running":
			return inFlight()
		case "succeeded":
			return seen("the renewed certificate was issued and delivered")
		case "cancelled":
			return opStateFailed, "cancelled"
		default:
			return opStateFailed, or(r.Detail, "the rotation failed")
		}
	case "connector_delivery":
		switch r.Status {
		case "queued", "rollback_queued", "rollback_recorded", "containment_queued", "purge_queued", "takedown_queued",
			"trust_anchor_removal_queued", "dry_run_queued":
			return inFlight()
		case "delivered":
			return seen("the connector reported the delivery")
		case "verified":
			return opStateVerified, "the connector read the delivered certificate back"
		case "rolled_back":
			return opStateRecovered, "rolled back to the predecessor"
		case "containment_stopped", "purged", "taken_down", "trust_anchor_removed":
			return opStateVerified, "the host's signed receipt confirms the removal"
		case "purge_absent", "takedown_absent", "trust_anchor_absent":
			return opStateVerified, "nothing was there to remove"
		case "containment_unverified":
			return opStateUncertain, "the stop was applied but no probe confirmed it"
		case "dry_run_planned", "config_validated", "test_succeeded":
			return opStateReviewed, "a zero-write check passed; nothing was changed"
		default:
			return opStateFailed, or(r.Detail, r.Status)
		}
	case "secret_rotation":
		switch r.Status {
		case store.SecretStaticRotationQueued:
			return inFlight()
		case store.SecretStaticRotationStaged, store.SecretStaticRotationCutover:
			if r.Quarantined || r.OutboxLeaseExpired {
				return inFlight()
			}
			return opStateExecuting, "rotating at the provider (" + r.Status + ")"
		case store.SecretStaticRotationVerified:
			return opStateDelivered, "the new credential works; the predecessor is not retired yet"
		case store.SecretStaticRotationCompleted:
			switch adoption {
			case consumerAdoptionAdopted:
				return opStateVerified, "every named consumer reported the new version"
			case consumerAdoptionPending:
				return opStateDelivered, "rotated; some named consumers have not reported the new version"
			default:
				return opStateDelivered, "rotated; no consumer was named to confirm the new version"
			}
		case store.SecretStaticRotationRolledBack:
			return opStateRecovered, "rolled back to the predecessor"
		case store.SecretStaticRotationRetirePending:
			return opStateFailed, "the new credential is live; retiring the predecessor needs the operator"
		default:
			return opStateFailed, or(r.Detail, "the rotation failed")
		}
	case "approval":
		switch r.Status {
		case "pending":
			return opStateAwaitingApproval, "waiting for approvers"
		case "approved":
			return opStateReviewed, "approved; not used yet"
		case "superseded":
			return opStateFailed, "superseded: what it approved changed before it was used"
		case "expired":
			return opStateFailed, "expired before it was used"
		default:
			return opStateFailed, r.Status
		}
	}
	return opStateUncertain, "unknown source"
}

func operationCredentialType(r store.OperationLedgerRow) string {
	switch r.Source {
	case "secret_rotation":
		return "secret"
	case "approval":
		return r.SubjectKind
	}
	if r.SubjectKind != "" {
		return r.SubjectKind
	}
	return "x509_certificate"
}

func encodeOperationCursor(r store.OperationLedgerRow) string {
	b, _ := json.Marshal(struct {
		T time.Time `json:"t"`
		K string    `json:"k"`
	}{r.UpdatedAt, r.Key()})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeOperationCursor(cursor string) (*store.OperationLedgerCursor, error) {
	if cursor == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return nil, errors.New("cursor is not valid")
	}
	var c struct {
		T time.Time `json:"t"`
		K string    `json:"k"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.T.IsZero() || !strings.Contains(c.K, ":") {
		return nil, errors.New("cursor is not valid")
	}
	return &store.OperationLedgerCursor{UpdatedAt: c.T, Key: c.K}, nil
}

// operationVisible reports whether the caller may read the row's domain:
// certificate rotations need lifecycle:read, deliveries connectors:read,
// secret rotations secrets:read, approvals their review domain.
func (a *API) operationVisible(r *http.Request, principal authz.Principal, tenantID string, row store.OperationLedgerRow) bool {
	scope := authz.Scope{TenantID: tenantID}
	switch row.Source {
	case "certificate_rotation":
		return principal.Can(authz.LifecycleRead, scope)
	case "connector_delivery":
		return principal.Can(authz.ConnectorsRead, scope)
	case "secret_rotation":
		return principal.Can(authz.SecretsRead, scope)
	case "approval":
		permission, ok := approvalRecordPermission(row.SubjectKind, row.Detail)
		return ok && a.approvalPermissionAuthorized(r, principal, tenantID, permission)
	}
	return false
}

func (a *API) listOperationLedger(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
		return
	}
	cursor, err := decodeOperationCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
		return
	}
	state, credentialType := r.URL.Query().Get("state"), r.URL.Query().Get("credential_type")
	if state != "" && !slices.Contains(operationStates, state) {
		a.writeError(w, errStatus(http.StatusBadRequest, "state must be one of "+strings.Join(operationStates, ", ")))
		return
	}
	rows, err := a.store.ListOperationLedgerRows(r.Context(), tenantID, cursor, limit+1)
	if err != nil {
		a.writeError(w, err)
		return
	}
	page := operationLedgerPage{Items: []operationLedgerItem{}}
	if len(rows) > limit {
		rows = rows[:limit]
		page.NextCursor = encodeOperationCursor(rows[len(rows)-1])
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	for _, row := range rows {
		if !a.operationVisible(r, principal, tenantID, row) {
			continue
		}
		item, err := a.operationLedgerItem(r, tenantID, row)
		if err != nil {
			a.writeError(w, err)
			return
		}
		if (state != "" && item.State != state) || (credentialType != "" && item.CredentialType != credentialType) {
			continue
		}
		page.Items = append(page.Items, item)
	}
	a.writeJSON(w, http.StatusOK, page)
}

func (a *API) operationLedgerItem(r *http.Request, tenantID string, row store.OperationLedgerRow) (operationLedgerItem, error) {
	adoption := consumerAdoptionNotRequested
	if row.Source == "secret_rotation" && row.Status == store.SecretStaticRotationCompleted && a.secrets != nil {
		cmd, err := a.store.GetSecretStaticRotationCommand(r.Context(), tenantID, row.ID)
		if err != nil {
			return operationLedgerItem{}, err
		}
		if len(cmd.Consumers) > 0 {
			adoption = consumerAdoptionPending
			if _, adopted, err := a.staticRotationConsumers(r.Context(), cmd); err != nil {
				return operationLedgerItem{}, err
			} else if adopted {
				adoption = consumerAdoptionAdopted
			}
		}
	}
	state, reason := normalizeOperation(row, adoption)
	item := operationLedgerItem{ID: row.Key(), Source: row.Source, CredentialType: operationCredentialType(row),
		Subject: operationSubject{ID: row.SubjectID, Name: row.SubjectName}, State: state, StateReason: reason,
		SourceStatus: row.Status, Fingerprint: row.Fingerprint, ObservedVantage: row.ObservedVantage,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
	if row.OutboxID != nil {
		item.Outbox = &operationOutbox{ID: *row.OutboxID, Status: row.OutboxStatus, Attempts: row.OutboxAttempts}
	}
	return item, nil
}

func operationLedgerRoutes(a *API) []route {
	return []route{
		{method: "GET", path: "/api/v1/operations/ledger", opID: "listOperationLedger",
			summary: "List rotations, deliveries, secret rotations and approvals in one normalized state, newest first: verified only on consumer evidence, never on an HTTP 200 or an outbox receipt alone",
			handler: a.listOperationLedger, query: operationLedgerQuery(), resSchema: "OperationLedgerPage", successCode: "200", perm: authz.LifecycleRead},
	}
}

func operationLedgerQuery() []param {
	return []param{
		{name: "limit", typ: "integer", desc: "maximum source rows read per page (1-100, default 20); a filtered page may hold fewer items"},
		{name: "cursor", typ: "string", desc: "opaque pagination cursor from a prior page"},
		{name: "state", typ: "string", desc: "Optional normalized state: " + strings.Join(operationStates, ", ") + "."},
		{name: "credential_type", typ: "string", desc: "Optional credential type, for example x509_certificate or secret."},
	}
}

func operationLedgerSchemas() map[string]*Schema {
	return map[string]*Schema{
		"OperationLedgerItem": object(map[string]*Schema{
			"id": str(), "source": {Type: "string", Enum: operationSources}, "credential_type": str(),
			"subject":          object(map[string]*Schema{"id": str(), "name": str()}, "name"),
			"state":            {Type: "string", Enum: operationStates},
			"state_reason":     str(),
			"source_status":    str(),
			"fingerprint":      str(),
			"outbox":           object(map[string]*Schema{"id": {Type: "integer"}, "status": str(), "attempts": {Type: "integer"}}, "id", "status", "attempts"),
			"observed_vantage": str(),
			"created_at":       timestamp(), "updated_at": timestamp(),
		}, "id", "source", "credential_type", "subject", "state", "state_reason", "source_status", "created_at", "updated_at"),
		"OperationLedgerPage": object(map[string]*Schema{
			"items": {Type: "array", Items: ref("OperationLedgerItem")}, "next_cursor": str(),
		}, "items"),
	}
}
