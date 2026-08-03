// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

type connectorCatalogItem struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	DeliveryMode string `json:"delivery_mode"`
	Rollback     string `json:"rollback"`
	// B-6: the catalog described WHAT each connector deploys but not what it
	// is permitted to do or how it behaves on a redelivery — the two facts an
	// operator actually needs before authorizing a privileged deployment.
	// These are read from the live registry, never hardcoded beside the
	// description, so the catalog cannot drift from what the process will
	// enforce.
	//
	// Native is true when this build carries a native implementation;
	// otherwise delivery falls to a signed plugin or a receipt.
	Native bool `json:"native"`
	// Capabilities is the sandbox grant a native connector declares
	// (fs.read, fs.write, net.dial, process.exec). Empty means either a
	// factory-built connector whose grant is per-attempt, or no privileged
	// operation at all.
	Capabilities []string `json:"capabilities"`
	// ReplaySafety is the audited redelivery contract: "reconciled" when the
	// receiver converges on retry, "at-most-once" otherwise. It fails closed
	// to at-most-once for anything unregistered.
	ReplaySafety string `json:"replay_safety"`
	// TargetVantage is where this connector's deploy work executes (epic A3):
	// "host_agent" for services on a machine an agent can run on,
	// "network_relay" for appliances driven from inside their segment, and
	// "control_plane" for cloud stores — and for anything undeclared, because
	// unaudited work stays where it always ran. Read from the live registry
	// census, never hardcoded beside the description.
	TargetVantage string `json:"target_vantage"`
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

type endpointBindingRequest struct {
	OwnerID      string                   `json:"owner_id"`
	IdentityName string                   `json:"identity_name"`
	TargetID     string                   `json:"target_id"`
	Target       *deploymentTargetRequest `json:"target"`
	Reason       string                   `json:"reason"`
}

type endpointBindingResponse struct {
	Identity               identityResponse         `json:"identity"`
	Target                 deploymentTargetResponse `json:"target"`
	QueuedLifecycleIntents []string                 `json:"queued_lifecycle_intents"`
	RenewalIntent          string                   `json:"renewal_intent"`
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
	a.writeJSON(w, http.StatusOK, connectorCatalogResponse{Items: a.connectorCatalogWithSandbox()})
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
		// The target is not contacted here: this route resolves schema and
		// credential references locally and nothing else. The status says exactly
		// that (servedstatus.ConnectorConfigValidated) rather than claiming a
		// successful test — truth-integrity 3. Epic D5 turns this into a real
		// agent-executed dry-run that reaches the target and returns a mutation plan.
		receipt, err := a.orch.RecordConnectorDelivery(ctx, tenantID, store.ConnectorDeliveryReceipt{
			Destination: "connector.test", Connector: target.Type, Target: target.Name,
			Status: servedstatus.ConnectorConfigValidated, Attempts: 1, Reason: "target_config_validated",
			Detail:         "connector target metadata and credential references validated locally; the target was not contacted and nothing was changed. External mutation still travels through connector.deploy outbox",
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
		state, err := a.orch.State(ctx, tenantID, req.IdentityID)
		if err != nil {
			return 0, nil, err
		}
		switch state {
		case orchestrator.StateRequested:
			if err := a.orch.Transition(ctx, tenantID, req.IdentityID, orchestrator.StateIssued, reason); err != nil {
				return 0, nil, err
			}
		case orchestrator.StateIssued, orchestrator.StateRenewing:
			if err := a.orch.Transition(ctx, tenantID, req.IdentityID, orchestrator.StateDeployed, reason); err != nil {
				return 0, nil, err
			}
		case orchestrator.StateDeployed:
			// Already converged by the issuer's credential-bearing deploy path.
		default:
			if err := a.orch.Transition(ctx, tenantID, req.IdentityID, orchestrator.StateDeployed, reason); err != nil {
				return 0, nil, err
			}
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
		// Nothing is restored here. This records the operator's rollback intent in
		// the evidence chain; the predecessor credential is not put back on the
		// target and the target is not contacted — truth-integrity 4. The
		// RollbackRef states the outstanding action rather than describing it as
		// done. Epic D4 makes this a connector.rollback job the bound agent
		// executes from its local predecessor bundle, with a restore transcript.
		receipt, err := a.orch.RecordConnectorDelivery(ctx, tenantID, store.ConnectorDeliveryReceipt{
			IdentityID: identityID, Destination: "connector.rollback", Connector: target.Type, Target: target.Name,
			Fingerprint: fingerprint, Status: servedstatus.ConnectorRollbackRecorded, Attempts: 1, Reason: "rollback_attested_not_executed",
			Detail:      reason,
			RollbackRef: "pending manual restore of the previous credential for " + target.Name, IdempotencyKey: idempotencyKey,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toConnectorDeliveryResponse(receipt), nil
	})
}

//trstctl:mutation
func (a *API) createEndpointBinding(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		req, err := decodeEndpointBindingRequest(r)
		if err != nil {
			return 0, nil, err
		}
		if _, err := a.store.GetOwner(ctx, tenantID, req.OwnerID); err != nil {
			return 0, nil, err
		}
		if err := validateWildcardIdentityPolicy(req.IdentityName, nil); err != nil {
			return 0, nil, err
		}
		target, err := a.endpointBindingTarget(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		identity, err := a.orch.CreateIdentity(ctx, tenantID, store.Identity{
			Kind:    store.KindX509Certificate,
			Name:    req.IdentityName,
			OwnerID: req.OwnerID,
		})
		if err != nil {
			return 0, nil, err
		}
		identity, err = a.orch.BindIdentityDeploymentTarget(ctx, tenantID, identity.ID, target)
		if err != nil {
			return 0, nil, err
		}
		reason := req.Reason
		if reason == "" {
			reason = "endpoint binding automation"
		}
		if err := a.orch.Transition(ctx, tenantID, identity.ID, orchestrator.StateIssued, reason); err != nil {
			return 0, nil, err
		}
		identity, err = a.store.GetIdentity(ctx, tenantID, identity.ID)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, endpointBindingResponse{
			Identity:               toIdentityResponse(identity),
			Target:                 toDeploymentTargetResponse(target),
			QueuedLifecycleIntents: []string{"ca.issue", "connector.deploy"},
			RenewalIntent:          "ca.renew",
		}, nil
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

func decodeEndpointBindingRequest(r *http.Request) (endpointBindingRequest, error) {
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return endpointBindingRequest{}, errWithStatus(http.StatusBadRequest, err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return endpointBindingRequest{}, errStatus(http.StatusBadRequest, "request body must be a JSON object")
	}
	if targetRaw, ok := obj["target"]; ok && len(targetRaw) > 0 && string(targetRaw) != "null" {
		var targetObj map[string]json.RawMessage
		if err := json.Unmarshal(targetRaw, &targetObj); err != nil || targetObj == nil {
			return endpointBindingRequest{}, errStatus(http.StatusBadRequest, "target must be a JSON object")
		}
		if containsInlineSecret(targetObj) {
			return endpointBindingRequest{}, errStatus(http.StatusBadRequest, "connector targets accept credential references, not inline secret values")
		}
	}
	var req endpointBindingRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return endpointBindingRequest{}, errStatus(http.StatusBadRequest, "invalid endpoint binding request")
	}
	req.OwnerID = strings.TrimSpace(req.OwnerID)
	req.IdentityName = strings.TrimSpace(req.IdentityName)
	req.TargetID = strings.TrimSpace(req.TargetID)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.OwnerID == "" {
		return endpointBindingRequest{}, errStatus(http.StatusBadRequest, "owner_id is required")
	}
	if req.IdentityName == "" {
		return endpointBindingRequest{}, errStatus(http.StatusBadRequest, "identity_name is required")
	}
	if req.TargetID != "" && req.Target != nil {
		return endpointBindingRequest{}, errStatus(http.StatusBadRequest, "provide target_id or target, not both")
	}
	if req.TargetID == "" && req.Target == nil {
		return endpointBindingRequest{}, errStatus(http.StatusBadRequest, "target_id or target is required")
	}
	if req.Target != nil {
		target, err := validateDeploymentTargetRequest(*req.Target)
		if err != nil {
			return endpointBindingRequest{}, err
		}
		req.Target = &target
	}
	return req, nil
}

func (a *API) endpointBindingTarget(ctx context.Context, tenantID string, req endpointBindingRequest) (store.DeploymentTarget, error) {
	if req.TargetID != "" {
		return a.store.GetDeploymentTarget(ctx, tenantID, req.TargetID)
	}
	return a.orch.UpsertDeploymentTarget(ctx, tenantID, store.DeploymentTarget{
		Name: req.Target.Name, Type: req.Target.Connector, Config: req.Target.Config,
	})
}

func validateDeploymentTargetRequest(req deploymentTargetRequest) (deploymentTargetRequest, error) {
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
	if containsInlineSecret(cfg) {
		return deploymentTargetRequest{}, errStatus(http.StatusBadRequest, "connector targets accept credential references, not inline secret values")
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

// connectorCatalogWithSandbox annotates the static descriptions with the live
// registry's sandbox facts. Without a registry (an assembly that serves no
// native connectors) every row reports native=false and the conservative
// at-most-once contract rather than claiming a capability the process cannot
// enforce.
func (a *API) connectorCatalogWithSandbox() []connectorCatalogItem {
	out := make([]connectorCatalogItem, 0, len(servedConnectorCatalog))
	for _, item := range servedConnectorCatalog {
		item.Capabilities = []string{}
		item.ReplaySafety = replaySafetyLabel(connector.ReplaySafetyAtMostOnce)
		item.TargetVantage = string(connector.VantageControlPlane)
		if a.connectorRegistry != nil {
			item.Native = a.connectorRegistry.Has(item.Name)
			if caps := a.connectorRegistry.CapabilitiesFor(item.Name); len(caps) > 0 {
				item.Capabilities = caps
			}
			item.ReplaySafety = replaySafetyLabel(a.connectorRegistry.ReplaySafetyFor(item.Name))
			item.TargetVantage = string(a.connectorRegistry.TargetVantageFor(item.Name))
		}
		out = append(out, item)
	}
	return out
}

func replaySafetyLabel(safety connector.ReplaySafety) string {
	if safety == connector.ReplaySafetyReconciled {
		return "reconciled"
	}
	return "at-most-once"
}
