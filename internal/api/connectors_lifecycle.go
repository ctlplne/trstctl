package api

import (
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type connectorCatalogItem struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	DeliveryMode string `json:"delivery_mode"`
	Rollback     string `json:"rollback"`
}

type connectorCatalogResponse struct {
	Items []connectorCatalogItem `json:"items"`
}

type connectorDeliveryResponse struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	OutboxID       *int64    `json:"outbox_id,omitempty"`
	IdentityID     *string   `json:"identity_id,omitempty"`
	Destination    string    `json:"destination"`
	Connector      string    `json:"connector"`
	Target         string    `json:"target"`
	Fingerprint    string    `json:"fingerprint"`
	Status         string    `json:"status"`
	Attempts       int       `json:"attempts"`
	Reason         string    `json:"reason"`
	Detail         string    `json:"detail"`
	RollbackRef    string    `json:"rollback_ref"`
	IdempotencyKey string    `json:"idempotency_key"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type outboxCircuitResponse struct {
	TenantID    string     `json:"tenant_id"`
	Destination string     `json:"destination"`
	State       string     `json:"state"`
	Failures    int        `json:"failures"`
	OpenUntil   *time.Time `json:"open_until,omitempty"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastError   string     `json:"last_error,omitempty"`
}

type rotationRunResponse struct {
	ID                     string     `json:"id"`
	TenantID               string     `json:"tenant_id"`
	IdentityID             string     `json:"identity_id"`
	OutboxID               *int64     `json:"outbox_id,omitempty"`
	Status                 string     `json:"status"`
	Trigger                string     `json:"trigger"`
	Reason                 string     `json:"reason"`
	PredecessorFingerprint string     `json:"predecessor_fingerprint"`
	SuccessorFingerprint   string     `json:"successor_fingerprint"`
	RollbackRef            string     `json:"rollback_ref"`
	Error                  string     `json:"error"`
	IdempotencyKey         string     `json:"idempotency_key"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
	CompletedAt            *time.Time `json:"completed_at,omitempty"`
}

func toOutboxCircuitResponse(s orchestrator.CircuitSnapshot) outboxCircuitResponse {
	var openUntil *time.Time
	if !s.OpenUntil.IsZero() {
		t := s.OpenUntil
		openUntil = &t
	}
	return outboxCircuitResponse{
		TenantID: s.TenantID, Destination: s.Destination, State: string(s.State),
		Failures: s.Failures, OpenUntil: openUntil, UpdatedAt: s.UpdatedAt, LastError: s.LastError,
	}
}

func toConnectorDeliveryResponse(r store.ConnectorDeliveryReceipt) connectorDeliveryResponse {
	return connectorDeliveryResponse{
		ID: r.ID, TenantID: r.TenantID, OutboxID: r.OutboxID, IdentityID: r.IdentityID,
		Destination: r.Destination, Connector: r.Connector, Target: r.Target,
		Fingerprint: r.Fingerprint, Status: r.Status, Attempts: r.Attempts,
		Reason: r.Reason, Detail: r.Detail, RollbackRef: r.RollbackRef,
		IdempotencyKey: r.IdempotencyKey, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func toRotationRunResponse(r store.RotationRun) rotationRunResponse {
	return rotationRunResponse{
		ID: r.ID, TenantID: r.TenantID, IdentityID: r.IdentityID, OutboxID: r.OutboxID,
		Status: r.Status, Trigger: r.Trigger, Reason: r.Reason,
		PredecessorFingerprint: r.PredecessorFingerprint, SuccessorFingerprint: r.SuccessorFingerprint,
		RollbackRef: r.RollbackRef, Error: r.Error, IdempotencyKey: r.IdempotencyKey,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, CompletedAt: r.CompletedAt,
	}
}

var servedConnectorCatalog = []connectorCatalogItem{
	{Name: "nginx", Kind: "file/process", DeliveryMode: "signed plugin or connector outbox receipt", Rollback: "restore previous fullchain/key pair and reload nginx"},
	{Name: "apache", Kind: "file/process", DeliveryMode: "signed plugin or connector outbox receipt", Rollback: "restore previous SSLCertificateFile and graceful reload"},
	{Name: "haproxy", Kind: "file/process", DeliveryMode: "signed plugin or connector outbox receipt", Rollback: "restore previous bundle and reload HAProxy"},
	{Name: "iis", Kind: "windows", DeliveryMode: "signed plugin or connector outbox receipt", Rollback: "restore previous binding thumbprint"},
	{Name: "aws-acm", Kind: "cloud", DeliveryMode: "signed plugin or connector outbox receipt", Rollback: "repoint listener to previous ACM ARN"},
	{Name: "azure-keyvault", Kind: "cloud", DeliveryMode: "signed plugin or connector outbox receipt", Rollback: "reactivate prior certificate version"},
	{Name: "gcp-certificate-manager", Kind: "cloud", DeliveryMode: "signed plugin or connector outbox receipt", Rollback: "reattach prior certificate resource"},
	{Name: "java-keystore", Kind: "keystore", DeliveryMode: "signed plugin or connector outbox receipt", Rollback: "restore previous keystore object"},
	{Name: "f5", Kind: "appliance", DeliveryMode: "signed plugin or connector outbox receipt", Rollback: "swap virtual server back to previous cert/key object"},
	{Name: "netscaler", Kind: "appliance", DeliveryMode: "signed plugin or connector outbox receipt", Rollback: "bind previous certKey to the service group"},
	{Name: "cisco", Kind: "appliance", DeliveryMode: "signed plugin or connector outbox receipt", Rollback: "restore previous trustpoint binding"},
	{Name: "fortigate", Kind: "appliance", DeliveryMode: "signed plugin or connector outbox receipt", Rollback: "restore previous local certificate reference"},
	{Name: "paloalto", Kind: "appliance", DeliveryMode: "signed plugin or connector outbox receipt", Rollback: "revert candidate config to prior certificate object"},
}

func (a *API) listConnectorCatalog(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.tenant(r); !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	a.writeJSON(w, http.StatusOK, connectorCatalogResponse{Items: servedConnectorCatalog})
}

func (a *API) listOutboxCircuits(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.outboxCircuits == nil {
		a.writeJSON(w, http.StatusOK, listResponse{Items: []outboxCircuitResponse{}})
		return
	}
	items := []outboxCircuitResponse{}
	for _, snapshot := range a.outboxCircuits() {
		if snapshot.TenantID != tenantID {
			continue
		}
		items = append(items, toOutboxCircuitResponse(snapshot))
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

func (a *API) listConnectorDeliveries(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	identityID := r.URL.Query().Get("identity_id")
	rows, err := a.store.ListConnectorDeliveryReceiptsPage(r.Context(), tenantID, identityID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]connectorDeliveryResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toConnectorDeliveryResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getConnectorDelivery(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	row, err := a.store.GetConnectorDeliveryReceipt(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toConnectorDeliveryResponse(row))
}

func (a *API) listRotationRuns(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	identityID := r.URL.Query().Get("identity_id")
	rows, err := a.store.ListRotationRunsPage(r.Context(), tenantID, identityID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]rotationRunResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toRotationRunResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getRotationRun(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	row, err := a.store.GetRotationRun(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toRotationRunResponse(row))
}
