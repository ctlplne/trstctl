package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
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

type deploymentTargetRequest struct {
	Name      string          `json:"name"`
	Connector string          `json:"connector"`
	Config    json.RawMessage `json:"config"`
}

type deploymentTargetResponse struct {
	ID        string          `json:"id"`
	TenantID  string          `json:"tenant_id"`
	Name      string          `json:"name"`
	Connector string          `json:"connector"`
	Config    json.RawMessage `json:"config"`
	CreatedAt time.Time       `json:"created_at"`
}

type identityConnectorTargetRequest struct {
	TargetID string `json:"target_id"`
}

type connectorTargetActionRequest struct {
	IdentityID string `json:"identity_id"`
	Reason     string `json:"reason"`
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

func toDeploymentTargetResponse(t store.DeploymentTarget) deploymentTargetResponse {
	cfg := t.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage("{}")
	}
	return deploymentTargetResponse{
		ID: t.ID, TenantID: t.TenantID, Name: t.Name, Connector: t.Type, Config: cfg, CreatedAt: t.CreatedAt,
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
	{Name: "nginx", Kind: "file/process", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous fullchain/key pair and reload nginx"},
	{Name: "apache", Kind: "file/process", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous SSLCertificateFile and graceful reload"},
	{Name: "caddy", Kind: "file/process", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous watched cert/key files and reload Caddy"},
	{Name: "haproxy", Kind: "file/process", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous bundle and reload HAProxy"},
	{Name: "envoy", Kind: "file/process", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous SDS secret material"},
	{Name: "iis", Kind: "windows", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous binding thumbprint"},
	{Name: "postfix", Kind: "mail", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous Postfix/Dovecot certificate/key files"},
	{Name: "traefik", Kind: "file/process", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous file-provider cert/key files"},
	{Name: "aws-acm", Kind: "cloud", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "repoint listener to previous ACM ARN"},
	{Name: "azure-keyvault", Kind: "cloud", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "reactivate prior certificate version"},
	{Name: "gcp-certificate-manager", Kind: "cloud", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "reattach prior certificate resource"},
	{Name: "java-keystore", Kind: "keystore", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous keystore object"},
	{Name: "postgresql", Kind: "database", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous server certificate/key files"},
	{Name: "mysql", Kind: "database", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous server certificate/key files"},
	{Name: "rabbitmq", Kind: "messaging", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous broker certificate/key files"},
	{Name: "elasticsearch", Kind: "search", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous watched HTTP TLS files"},
	{Name: "tomcat", Kind: "application-server", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous connector certificate/key files"},
	{Name: "f5", Kind: "appliance", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "swap virtual server back to previous cert/key object"},
	{Name: "netscaler", Kind: "appliance", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "bind previous certKey to the service group"},
	{Name: "a10", Kind: "appliance", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous client-SSL template certificate/key binding"},
	{Name: "kemp", Kind: "appliance", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "rebind virtual service to previous certificate object"},
	{Name: "cisco", Kind: "appliance", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous trustpoint binding"},
	{Name: "fortigate", Kind: "appliance", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "restore previous local certificate reference"},
	{Name: "paloalto", Kind: "appliance", DeliveryMode: "native registry, signed plugin, or receipt", Rollback: "revert candidate config to prior certificate object"},
}

func (a *API) listConnectorCatalog(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.tenant(r); !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	a.writeJSON(w, http.StatusOK, connectorCatalogResponse{Items: servedConnectorCatalog})
}

//trstctl:mutation
func (a *API) createConnectorTarget(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		req, err := decodeDeploymentTargetRequest(r)
		if err != nil {
			return 0, nil, err
		}
		target, err := a.orch.UpsertDeploymentTarget(ctx, tenantID, store.DeploymentTarget{
			Name: req.Name, Type: req.Connector, Config: req.Config,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toDeploymentTargetResponse(target), nil
	})
}

func (a *API) listConnectorTargets(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	rows, err := a.store.ListDeploymentTargets(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]deploymentTargetResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toDeploymentTargetResponse(row))
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

func (a *API) getConnectorTarget(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	target, err := a.store.GetDeploymentTarget(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toDeploymentTargetResponse(target))
}

//trstctl:mutation
func (a *API) updateConnectorTarget(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		req, err := decodeDeploymentTargetRequest(r)
		if err != nil {
			return 0, nil, err
		}
		target, err := a.orch.UpsertDeploymentTarget(ctx, tenantID, store.DeploymentTarget{
			ID: id, Name: req.Name, Type: req.Connector, Config: req.Config,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toDeploymentTargetResponse(target), nil
	})
}

//trstctl:mutation
func (a *API) deleteConnectorTarget(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if _, err := a.store.GetDeploymentTarget(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		if err := a.orch.DeleteDeploymentTarget(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

//trstctl:mutation
func (a *API) bindIdentityConnectorTarget(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	identityID := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req identityConnectorTargetRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if strings.TrimSpace(req.TargetID) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "target_id is required")
		}
		if _, err := a.store.GetIdentity(ctx, tenantID, identityID); err != nil {
			return 0, nil, err
		}
		target, err := a.store.GetDeploymentTarget(ctx, tenantID, strings.TrimSpace(req.TargetID))
		if err != nil {
			return 0, nil, err
		}
		identity, err := a.orch.BindIdentityDeploymentTarget(ctx, tenantID, identityID, target)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toIdentityResponse(identity), nil
	})
}

//trstctl:mutation
func (a *API) testConnectorTarget(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	targetID := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		target, err := a.store.GetDeploymentTarget(ctx, tenantID, targetID)
		if err != nil {
			return 0, nil, err
		}
		receipt, err := a.orch.RecordConnectorDelivery(ctx, tenantID, store.ConnectorDeliveryReceipt{
			Destination: "connector.test", Connector: target.Type, Target: target.Name,
			Status: "test_succeeded", Attempts: 1, Reason: "target_config_validated",
			Detail:         "connector target metadata and credential references validated; external mutation still travels through connector.deploy outbox",
			IdempotencyKey: idempotencyKey,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toConnectorDeliveryResponse(receipt), nil
	})
}

//trstctl:mutation
func (a *API) deployConnectorTarget(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	targetID := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		req, err := decodeConnectorTargetActionRequest(r)
		if err != nil {
			return 0, nil, err
		}
		if strings.TrimSpace(req.IdentityID) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "identity_id is required")
		}
		target, err := a.store.GetDeploymentTarget(ctx, tenantID, targetID)
		if err != nil {
			return 0, nil, err
		}
		if _, err := a.orch.BindIdentityDeploymentTarget(ctx, tenantID, req.IdentityID, target); err != nil {
			return 0, nil, err
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = "connector target deploy"
		}
		if err := a.orch.Transition(ctx, tenantID, req.IdentityID, orchestrator.StateDeployed, reason); err != nil {
			return 0, nil, err
		}
		identity, err := a.store.GetIdentity(ctx, tenantID, req.IdentityID)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toIdentityResponse(identity), nil
	})
}

//trstctl:mutation
func (a *API) rollbackConnectorTarget(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	targetID := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		req, err := decodeConnectorTargetActionRequest(r)
		if err != nil {
			return 0, nil, err
		}
		target, err := a.store.GetDeploymentTarget(ctx, tenantID, targetID)
		if err != nil {
			return 0, nil, err
		}
		var identityID *string
		fingerprint := ""
		if strings.TrimSpace(req.IdentityID) != "" {
			identityID = &req.IdentityID
			identity, err := a.store.GetIdentity(ctx, tenantID, req.IdentityID)
			if err != nil {
				return 0, nil, err
			}
			certs, err := a.store.ListActiveIssuedCertificatesForIdentity(ctx, tenantID, identity.OwnerID, identity.Name)
			if err != nil {
				return 0, nil, err
			}
			if len(certs) > 0 {
				fingerprint = certs[len(certs)-1].Fingerprint
			}
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = "operator rollback"
		}
		receipt, err := a.orch.RecordConnectorDelivery(ctx, tenantID, store.ConnectorDeliveryReceipt{
			IdentityID: identityID, Destination: "connector.rollback", Connector: target.Type, Target: target.Name,
			Fingerprint: fingerprint, Status: "rollback_recorded", Attempts: 1, Reason: "rollback_recorded",
			Detail: reason, RollbackRef: "restore previous credential for " + target.Name, IdempotencyKey: idempotencyKey,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toConnectorDeliveryResponse(receipt), nil
	})
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

func decodeDeploymentTargetRequest(r *http.Request) (deploymentTargetRequest, error) {
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return deploymentTargetRequest{}, errWithStatus(http.StatusBadRequest, err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return deploymentTargetRequest{}, errStatus(http.StatusBadRequest, "request body must be a JSON object")
	}
	if containsInlineSecret(obj) {
		return deploymentTargetRequest{}, errStatus(http.StatusBadRequest, "connector targets accept credential references, not inline secret values")
	}
	var req deploymentTargetRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return deploymentTargetRequest{}, errStatus(http.StatusBadRequest, "invalid connector target request")
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Connector = strings.TrimSpace(req.Connector)
	if req.Name == "" {
		return deploymentTargetRequest{}, errStatus(http.StatusBadRequest, "name is required")
	}
	if req.Connector == "" {
		return deploymentTargetRequest{}, errStatus(http.StatusBadRequest, "connector is required")
	}
	if !servedConnectorName(req.Connector) {
		return deploymentTargetRequest{}, errStatus(http.StatusBadRequest, "connector must name a served connector catalog entry")
	}
	if len(req.Config) == 0 {
		req.Config = json.RawMessage("{}")
	}
	var cfg any
	if err := json.Unmarshal(req.Config, &cfg); err != nil {
		return deploymentTargetRequest{}, errStatus(http.StatusBadRequest, "config must be valid JSON")
	}
	if _, ok := cfg.(map[string]any); !ok {
		return deploymentTargetRequest{}, errStatus(http.StatusBadRequest, "config must be a JSON object")
	}
	return req, nil
}

func decodeConnectorTargetActionRequest(r *http.Request) (connectorTargetActionRequest, error) {
	if r.Body == nil {
		return connectorTargetActionRequest{}, nil
	}
	var req connectorTargetActionRequest
	if err := decodeJSON(r, &req); err != nil {
		return connectorTargetActionRequest{}, errWithStatus(http.StatusBadRequest, err)
	}
	req.IdentityID = strings.TrimSpace(req.IdentityID)
	req.Reason = strings.TrimSpace(req.Reason)
	return req, nil
}

func servedConnectorName(name string) bool {
	name = strings.TrimSpace(name)
	for _, item := range servedConnectorCatalog {
		if item.Name == name {
			return true
		}
	}
	return false
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
