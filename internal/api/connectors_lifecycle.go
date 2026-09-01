// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/plugincensus"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

type connectorCatalogItem struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	DeliveryMode string `json:"delivery_mode"`
	Rollback     string `json:"rollback"`
	// ExecutesRollback reports whether trstctl can PERFORM the rollback above
	// rather than describe it (epic D4). It is read from the connector census,
	// never written beside the prose, because the prose is a procedure and this
	// is a claim about the binary — and an operator reading "we can roll this
	// back" during an incident and finding out otherwise is the specific
	// failure the truth-integrity work exists to prevent.
	ExecutesRollback bool `json:"executes_rollback"`
	// DeviceProven reports whether this family's deploy is exercised against a
	// faithful double of its device API in this repository (epic E1).
	//
	// Distinct from the conformance suite every connector passes. That suite
	// runs against an in-memory double that accepts any request, so it proves a
	// connector respects its capability grant and is replay-deterministic — and
	// proves nothing about whether the appliance would have accepted the call.
	// For an appliance family, whose entire implementation is an API
	// conversation, that is the only question that matters.
	//
	// False on a host connector is not a gap: there is no device API to emulate,
	// so this is simply not the proof that covers it.
	DeviceProven bool `json:"device_proven"`
	// Support is the attested support surface for this family (epic E3):
	// which management API it speaks, which operations are exercised against a
	// double of it, and what it cannot do. Absent for host connectors, whose
	// "API contract" is the filesystem.
	Support *connectorSupportRow `json:"support,omitempty"`
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
	// RelayParity is this family's position in the accepted E1 relay migration.
	// It is present for all thirteen source-plan families, including families
	// whose current runtime is host-agent or control-plane. Omitting those rows
	// would let implementation scope silently shrink product acceptance.
	RelayParity *connectorRelayParity `json:"relay_parity,omitempty"`
}

// connectorRelayParity is one appliance family's E1 gate status.
//
// Missing gates are named individually rather than summarised as a percentage.
// A number lets a reader believe the remainder is small and similar; the names
// say that cisco is held back by having no rollback and no readback, which is a
// different conversation from f5 being held back by HA-peer sync.
type connectorRelayParity struct {
	Met     []string `json:"met"`
	Missing []string `json:"missing"`
	// Disposition is the closed status: migrated, architecture_exception, or
	// unimplemented. It is authoritative; the booleans below remain for older
	// clients that predate AUD-33.
	Disposition string `json:"disposition"`
	// Outstanding are E1 deliverables that do not block migration but are not
	// built. Reported so a migrated family cannot read as a finished one.
	Outstanding   []string `json:"outstanding"`
	RelayMigrated bool     `json:"relay_migrated"`
	// CPRetained marks a family whose control-plane path remains an open
	// architecture exception because its device API cannot express the required
	// rollback/readback. ScopeNote carries the exact reason.
	CPRetained bool   `json:"cp_retained"`
	ScopeNote  string `json:"scope_note,omitempty"`
	Detail     string `json:"detail"`
}

// connectorSupportRow is what this repository can truthfully attest about a
// family (epic E3).
//
// Deliberately NOT a firmware compatibility range. A version range is a claim
// about hardware somebody ran, and nothing here runs against a device — so
// publishing one would be marketing in the shape of evidence, and an operator
// would plan a migration around it. What is published instead is the API
// contract, the operations exercised against a faithful double of it, and the
// limits, every part of which is backed by a test that runs in CI.
type connectorSupportRow struct {
	APIContract      string   `json:"api_contract"`
	ProvenOperations []string `json:"proven_operations"`
	KnownLimits      []string `json:"known_limits"`
	// HardwareTested is false for every family today. It is a field rather than
	// a footnote so the surface cannot quietly imply otherwise.
	HardwareTested bool `json:"hardware_tested"`
	// Detail is the sentence that stops a reader inferring more than is meant.
	Detail string `json:"detail"`
}

type connectorCatalogResponse struct {
	Items []connectorCatalogItem `json:"items"`
	// RelayPlugins is a bounded page of certificate-bound relay runtime views.
	// It is separate from Items because a third-party name need not be one of the
	// native catalog's static families, and because provenance/grants belong to
	// the exact relay that loaded the module.
	RelayPlugins           []relayPluginRuntime `json:"relay_plugins"`
	RelayPluginsNextCursor string               `json:"relay_plugins_next_cursor,omitempty"`
}

type relayPluginRuntime struct {
	AgentID           string               `json:"agent_id"`
	AgentName         string               `json:"agent_name"`
	AgentStatus       string               `json:"agent_status"`
	ReportedAt        string               `json:"reported_at"`
	SignerFingerprint string               `json:"signer_fingerprint"`
	SignatureVerified bool                 `json:"signature_verified"`
	MetadataOnly      bool                 `json:"metadata_only"`
	Plugins           []plugincensus.Entry `json:"plugins"`
}

// relayPluginResponseEntries preserves the array shapes promised by OpenAPI.
// A stored signed census may contain nil slices because nil and empty have the
// same signing meaning. JSON clients must still receive [] rather than null.
func relayPluginResponseEntries(entries []plugincensus.Entry) []plugincensus.Entry {
	out := make([]plugincensus.Entry, len(entries))
	for i, entry := range entries {
		out[i] = entry
		out[i].Grants = make([]plugincensus.Grant, len(entry.Grants))
		for j, grant := range entry.Grants {
			out[i].Grants[j] = grant
			out[i].Grants[j].Constraints = append([]string{}, grant.Constraints...)
		}
	}
	return out
}

type deploymentTargetRequest struct {
	Name      string          `json:"name"`
	Connector string          `json:"connector"`
	Config    json.RawMessage `json:"config"`
	Enabled   *bool           `json:"enabled,omitempty"`
}

type deploymentTargetResponse struct {
	ID        string          `json:"id"`
	TenantID  string          `json:"tenant_id"`
	Name      string          `json:"name"`
	Connector string          `json:"connector"`
	Config    json.RawMessage `json:"config"`
	Enabled   bool            `json:"enabled"`
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
		ID: t.ID, TenantID: t.TenantID, Name: t.Name, Connector: t.Type, Config: cfg, Enabled: t.Enabled, CreatedAt: t.CreatedAt,
	}
}

func deploymentTargetRequestEnabled(enabled *bool) bool {
	return enabled == nil || *enabled
}

func requireDeploymentTargetEnabled(target store.DeploymentTarget) error {
	if target.Enabled {
		return nil
	}
	return errStatus(http.StatusConflict,
		"deployment target is disabled; enable it only after its agent or relay and endpoint have been verified; nothing was queued or changed")
}

func requireIdentityConnectorCompatible(identity store.Identity, target store.DeploymentTarget) error {
	if len(identity.Attributes) == 0 {
		return nil
	}
	var attributes struct {
		IntendedConnector string `json:"intended_connector"`
	}
	if err := json.Unmarshal(identity.Attributes, &attributes); err != nil {
		return errStatus(http.StatusConflict,
			"identity connector intent could not be read; repair its metadata before selecting a destination; nothing was queued or changed")
	}
	intended := strings.TrimSpace(attributes.IntendedConnector)
	connectorName := strings.TrimSpace(target.Type)
	if intended == "" || strings.EqualFold(intended, connectorName) {
		return nil
	}
	return errStatus(http.StatusConflict,
		"identity is intended for "+intended+", but the selected destination uses "+connectorName+"; choose a matching destination; nothing was queued or changed")
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
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	// Spec and static-catalog tests intentionally construct an API without a
	// datastore. Keep the pre-E4 static surface usable in that narrow shape;
	// assembled servers always supply the tenant-scoped store.
	if a.store == nil {
		a.writeJSON(w, http.StatusOK, connectorCatalogResponse{
			Items: a.connectorCatalogWithSandbox(), RelayPlugins: []relayPluginRuntime{},
		})
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	afterID := store.ZeroUUID
	var afterCreatedAt *time.Time
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		createdAt, id, err := decodeAgentCursor(cursor)
		if err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid cursor"))
			return
		}
		afterCreatedAt, afterID = createdAt, id
	}
	agents, err := a.store.ListAgentsPage(r.Context(), tenantID, afterCreatedAt, afterID, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	relayPlugins := make([]relayPluginRuntime, 0, len(agents))
	for _, agent := range agents {
		if agent.RelayPluginsReportedAt == nil {
			continue
		}
		relayPlugins = append(relayPlugins, relayPluginRuntime{
			AgentID: agent.ID, AgentName: agent.Name, AgentStatus: agent.Status,
			ReportedAt:        agent.RelayPluginsReportedAt.UTC().Format(time.RFC3339),
			SignerFingerprint: agent.RelayPluginsSignerFingerprint,
			SignatureVerified: len(agent.RelayPluginsSignature) > 0 && agent.RelayPluginsStatement != "",
			MetadataOnly:      true, Plugins: relayPluginResponseEntries(agent.RelayPlugins),
		})
	}
	next := ""
	if len(agents) == limit {
		next = encodeAgentCursor(agents[len(agents)-1])
	}
	a.writeJSON(w, http.StatusOK, connectorCatalogResponse{
		Items: a.connectorCatalogWithSandbox(), RelayPlugins: relayPlugins,
		RelayPluginsNextCursor: next,
	})
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
			Enabled: deploymentTargetRequestEnabled(req.Enabled), EnabledSet: true,
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
		current, err := a.store.GetDeploymentTarget(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		enabled := current.Enabled
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		target, err := a.orch.UpsertDeploymentTarget(ctx, tenantID, store.DeploymentTarget{
			ID: id, Name: req.Name, Type: req.Connector, Config: req.Config,
			Enabled: enabled, EnabledSet: true,
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
		target, err := a.store.GetDeploymentTarget(ctx, tenantID, strings.TrimSpace(req.TargetID))
		if err != nil {
			return 0, nil, err
		}
		if err := requireDeploymentTargetEnabled(target); err != nil {
			return 0, nil, err
		}
		identity, err := a.store.GetIdentity(ctx, tenantID, identityID)
		if err != nil {
			return 0, nil, err
		}
		if err := requireIdentityConnectorCompatible(identity, target); err != nil {
			return 0, nil, err
		}
		identity, err = a.orch.BindIdentityDeploymentTarget(ctx, tenantID, identityID, target)
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
		if err := requireDeploymentTargetEnabled(target); err != nil {
			return 0, nil, err
		}
		// D5: when a relay can take the work, this enqueues a real dry-run that
		// reaches the target and returns a mutation plan. When it cannot — no
		// job ledger, or connector.test not enabled — it falls back to the
		// honest local answer rather than pretending, exactly as before.
		if a.enqueueConnectorTest != nil {
			queued, err := a.enqueueConnectorTest(ctx, tenantID, target, idempotencyKey)
			if err != nil {
				return 0, nil, err
			}
			if queued != nil {
				return http.StatusAccepted, toConnectorDeliveryResponse(*queued), nil
			}
		}
		// The target is not contacted here: this route resolves schema and
		// credential references locally and nothing else. The status says exactly
		// that (servedstatus.ConnectorConfigValidated) rather than claiming a
		// successful test — truth-integrity 3.
		receipt, err := a.orch.RecordConnectorDelivery(ctx, tenantID, store.ConnectorDeliveryReceipt{
			Destination: "connector.test", Connector: target.Type, Target: target.Name,
			Status: servedstatus.ConnectorConfigValidated, Attempts: 1, Reason: "target_config_validated",
			Detail:         "connector target metadata and credential references validated locally; no relay is enabled for connector.test, so the target was not contacted and nothing was changed",
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
		if err := requireDeploymentTargetEnabled(target); err != nil {
			return 0, nil, err
		}
		identity, err := a.store.GetIdentity(ctx, tenantID, req.IdentityID)
		if err != nil {
			return 0, nil, err
		}
		if err := requireIdentityConnectorCompatible(identity, target); err != nil {
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
		identity, err = a.store.GetIdentity(ctx, tenantID, req.IdentityID)
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
		if err := requireDeploymentTargetEnabled(target); err != nil {
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
			if err := requireIdentityConnectorCompatible(identity, target); err != nil {
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
		// D4/AUD32: this EXECUTES where it can.
		//
		// The predecessor is resolved from the certificate's own replacement
		// chain. Where the connector family can address an installed object
		// separately from uploading one, the rollback is queued as a real
		// connector.rollback job a network relay claims and performs as a
		// re-bind. A host connector instead routes to the exact host agent whose
		// encrypted local ledger holds the predecessor bundle; the control plane
		// never receives that bundle or its key.
		//
		// A family without either execution model is refused below; it never gets
		// a rollback-shaped success receipt.
		predecessor := resolvePredecessorCertificate(ctx, a.store, tenantID, identityID)
		var rollbackRef string
		if !connector.CanExecuteRollback(target.Type) {
			return 0, nil, errStatus(http.StatusConflict,
				"this connector family has no executable rollback route; no rollback receipt was recorded")
		}
		if a.orch == nil {
			return 0, nil, errors.New("connector rollback orchestrator is not configured")
		}
		status := servedstatus.ConnectorRollbackQueued
		statusReason := "rollback_queued_for_agent_execution"
		var requiredAgentID string
		if connector.CanRollbackOnHost(target.Type) {
			evidence, found, evidenceErr := a.store.LastSuccessfulHostDeployEvidence(ctx, tenantID, target.ID)
			err = evidenceErr
			if err != nil {
				return 0, nil, err
			}
			if !found {
				return 0, nil, errStatus(http.StatusConflict,
					"no successful enrolled host-agent deploy owns a predecessor for this target; no rollback was queued or recorded")
			}
			if strings.TrimSpace(req.IdentityID) != "" && evidence.IdentityID != strings.TrimSpace(req.IdentityID) {
				return 0, nil, errStatus(http.StatusConflict,
					"the latest host deploy belongs to a different identity; no rollback was queued or recorded")
			}
			requiredAgentID = evidence.AgentID
			fingerprint = evidence.Fingerprint
			p := a.store.ResolvePredecessorCertificateForFingerprint(ctx, tenantID, evidence.Fingerprint)
			predecessor = predecessorCertificate{Serial: p.Serial, Fingerprint: p.Fingerprint}
		}
		if predecessor.Fingerprint == "" {
			return 0, nil, errStatus(http.StatusConflict,
				"this target has no predecessor certificate to restore; no rollback receipt was recorded")
		}

		{
			// The SAME string a deploy routes on. target.Name is the display
			// name; the connectors derive their installed object from the
			// routing attribute, and using the display name here would make
			// every rollback look for an object that was never created.
			rollbackTarget := orchestrator.DeploymentRoute(target)
			if strings.TrimSpace(rollbackTarget) == "" {
				rollbackTarget = target.Name
			}
			queued, qErr := a.orch.RequestConnectorRollback(ctx, tenantID, orchestrator.ConnectorRollbackRequest{
				Connector: target.Type, Target: rollbackTarget, TargetID: target.ID,
				IdentityID: strings.TrimSpace(req.IdentityID), TargetConfig: target.Config,
				PredecessorFingerprint: predecessor.Fingerprint,
				PredecessorSerial:      predecessor.Serial,
				SuccessorFingerprint:   fingerprint,
				RequiredAgentID:        requiredAgentID,
				Reason:                 reason,
			})
			if qErr != nil {
				return 0, nil, qErr
			}
			// Only claim "queued" when a relay can actually pick it up. The
			// orchestrator re-arms a terminal row rather than silently finding
			// it, but if it could not, saying so beats telling an operator
			// mid-incident that a rollback is under way when nothing will run.
			if !queued.Queued {
				return 0, nil, errStatus(http.StatusConflict,
					"a rollback for this target and predecessor exists and could not be re-queued; "+
						"inspect the connector delivery receipts for its outcome before retrying")
			}
			if connector.CanRollbackOnHost(target.Type) {
				rollbackRef = "queued for exact enrolled host-agent execution on " + target.Name +
					": restore predecessor certificate serial " + predecessor.Serial +
					" (fingerprint " + predecessor.Fingerprint + ") from that agent's encrypted local ledger, outbox key " +
					queued.IdempotencyKey + ". The predecessor key never passes through the control plane. " +
					"The agent reloads the service and reverifies the configured listener; missing or mismatched local state fails closed."
			} else {
				// Deliberately does NOT assert the object is on the appliance. All
				// this side checked is its own replacement chain; whether the
				// fingerprint-named object is actually installed is something only
				// the relay can see, and it checks before binding. Stating it as
				// fact here would be the control plane vouching for a machine it
				// has never looked at.
				rollbackRef = "queued for enrolled network-relay execution on " + target.Name +
					": re-bind to the predecessor certificate serial " + predecessor.Serial +
					" (fingerprint " + predecessor.Fingerprint + "), outbox key " + queued.IdempotencyKey +
					". No key is uploaded. Whether that object is still installed on the target is " +
					"verified by the relay when it runs; if it is gone the rollback fails rather than " +
					"reporting success."
			}
		}

		receipt, err := a.orch.RecordConnectorDelivery(ctx, tenantID, store.ConnectorDeliveryReceipt{
			IdentityID: identityID, Destination: "connector.rollback", Connector: target.Type, Target: target.Name,
			Fingerprint: fingerprint, Status: status, Attempts: 1, Reason: statusReason,
			Detail:      reason,
			RollbackRef: rollbackRef, IdempotencyKey: idempotencyKey,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toConnectorDeliveryResponse(receipt), nil
	})
}

// predecessorCertificate is the credential a rollback binds back to.
type predecessorCertificate struct {
	Serial      string
	Fingerprint string
}

// resolvePredecessorCertificate adapts the store's chain walk to this
// package's local type. The walk itself lives in the store because the
// verification path (D2) resolves the same predecessor when it decides a
// rollback is warranted, and two copies would drift.
func resolvePredecessorCertificate(ctx context.Context, st *store.Store, tenantID string, identityID *string) predecessorCertificate {
	if st == nil || identityID == nil {
		return predecessorCertificate{}
	}
	p := st.ResolvePredecessorCertificate(ctx, tenantID, *identityID)
	return predecessorCertificate{Serial: p.Serial, Fingerprint: p.Fingerprint}
}

//trstctl:mutation
func (a *API) createEndpointBinding(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		req, err := decodeEndpointBindingRequest(r)
		if err != nil {
			return 0, nil, err
		}
		if req.Target != nil && !deploymentTargetRequestEnabled(req.Target.Enabled) {
			return 0, nil, errStatus(http.StatusConflict,
				"deployment target is disabled; enable it only after its agent or relay and endpoint have been verified; nothing was queued or changed")
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
		if err := requireDeploymentTargetEnabled(target); err != nil {
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
		Enabled: deploymentTargetRequestEnabled(req.Target.Enabled), EnabledSet: true,
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
		item.ExecutesRollback = connector.CanExecuteRollback(item.Name)
		item.DeviceProven = connector.DeviceProven(item.Name)
		if connector.IsE1Family(item.Name) {
			status := connector.ParityStatusFor(item.Name)
			item.RelayParity = &connectorRelayParity{
				Met:           parityGateNames(status.Met),
				Missing:       parityGateNames(status.Missing),
				Disposition:   string(status.Disposition),
				Outstanding:   parityGateNames(status.Outstanding),
				RelayMigrated: status.RelayMigrated,
				CPRetained:    status.CPRetained,
				ScopeNote:     status.ScopeNote,
				Detail: "E1's accepted denominator contains thirteen families. Migrated means every " +
					"gate is proven and the old path is refused; architecture_exception means a " +
					"documented control-plane path still keeps E1 open; unimplemented means the " +
					"family has no network-relay execution and refusal proof.",
			}
		}
		if row, ok := connector.SupportRowFor(item.Name); ok {
			detail := "These operations are exercised by this connector's repository tests. " +
				"No physical, vendor-hosted, or external target has been run, so this is not a firmware claim."
			if connector.DeviceProven(item.Name) {
				detail = "These operations are exercised against a faithful in-process double of " +
					"the named management API. No physical or vendor-hosted device has been run."
			}
			item.Support = &connectorSupportRow{
				APIContract:      row.APIContract,
				ProvenOperations: row.ProvenOperations,
				KnownLimits:      row.KnownLimits,
				HardwareTested:   row.HardwareTested,
				Detail:           detail,
			}
		}
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

// parityGateNames renders gates for the wire, never nil.
//
// An omitted array and an empty one decode differently in most clients, and
// "this family is missing nothing" is a claim worth transmitting explicitly.
func parityGateNames(gates []connector.ParityGate) []string {
	out := make([]string, 0, len(gates))
	for _, gate := range gates {
		out = append(out, string(gate))
	}
	return out
}
