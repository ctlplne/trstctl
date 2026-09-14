// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/plugincensus"
	"trstctl.com/trstctl/internal/protocols/acme"
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
	OwnerID            string                   `json:"owner_id"`
	ReplaceIdentityID  string                   `json:"replace_identity_id,omitempty"`
	IdentityName       string                   `json:"identity_name"`
	ProfileName        string                   `json:"profile_name,omitempty"`
	TargetID           string                   `json:"target_id"`
	Target             *deploymentTargetRequest `json:"target"`
	Issuer             endpointIssuerRequest    `json:"issuer"`
	Reason             string                   `json:"reason"`
	PreviewFingerprint string                   `json:"preview_fingerprint"`
}

type endpointBindingResponse struct {
	Identity               identityResponse         `json:"identity"`
	ReplacedIdentityID     string                   `json:"replaced_identity_id,omitempty"`
	Target                 deploymentTargetResponse `json:"target"`
	Issuer                 endpointIssuerSummary    `json:"issuer"`
	PreviewFingerprint     string                   `json:"preview_fingerprint"`
	QueuedLifecycleIntents []string                 `json:"queued_lifecycle_intents"`
	RenewalIntent          string                   `json:"renewal_intent"`
}

const (
	endpointIssuerPlatform = "platform"
	endpointIssuerPrivate  = "private"
	endpointIssuerExternal = "external"
	endpointPlatformCAID   = "trstctl-issuing-ca"
)

type endpointIssuerRequest struct {
	Source string `json:"source"`
	ID     string `json:"id"`
}

type endpointIssuerSummary struct {
	Source       string `json:"source"`
	ID           string `json:"id"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Availability string `json:"availability"`
	// upstreamDNS01 is in-process only: the authority needs a tenant DNS-01
	// provider config to validate names (see checkEndpointIssuerValidationPrerequisites).
	upstreamDNS01 bool
}

type endpointBindingTargetSummary struct {
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name"`
	Connector string          `json:"connector"`
	Config    json.RawMessage `json:"config"`
	Enabled   bool            `json:"enabled"`
	Revision  string          `json:"revision,omitempty"`
}

type endpointBindingCustody struct {
	KeyOrigin              string `json:"key_origin"`
	PrivateKeyControlPlane bool   `json:"private_key_enters_control_plane"`
	Detail                 string `json:"detail"`
}

type endpointBindingPreviewResponse struct {
	ExistingIdentityVersion uint64                                  `json:"existing_identity_version,omitempty"`
	Issuance                *store.OperationApprovalIssuanceBinding `json:"issuance"`
	ApprovalRequired        bool                                    `json:"approval_required"`
	Capability              string                                  `json:"capability"`
	Ready                   bool                                    `json:"ready"`
	EffectFree              bool                                    `json:"effect_free"`
	RequestFingerprint      string                                  `json:"request_fingerprint"`
	OwnerID                 string                                  `json:"owner_id"`
	IdentityName            string                                  `json:"identity_name"`
	ExistingIdentity        *identityResponse                       `json:"existing_identity,omitempty"`
	ReplacedIdentity        *identityResponse                       `json:"replaced_identity,omitempty"`
	ReplacedIdentityVersion uint64                                  `json:"replaced_identity_version,omitempty"`
	replacementSource       store.Identity
	Issuer                  endpointIssuerSummary        `json:"issuer"`
	Target                  endpointBindingTargetSummary `json:"target"`
	Custody                 endpointBindingCustody       `json:"custody"`
	Changes                 []string                     `json:"changes"`
	QueuedLifecycleIntents  []string                     `json:"queued_lifecycle_intents"`
	RecoverySteps           []string                     `json:"recovery_steps"`
	VerificationSteps       []string                     `json:"verification_steps"`
	PreviewWrites           []string                     `json:"preview_writes"`
	PreviewExternalEffects  []string                     `json:"preview_external_effects"`
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
	ID                     string                   `json:"id"`
	TenantID               string                   `json:"tenant_id"`
	IdentityID             string                   `json:"identity_id"`
	OutboxID               *int64                   `json:"outbox_id,omitempty"`
	Status                 string                   `json:"status"`
	Trigger                string                   `json:"trigger"`
	Reason                 string                   `json:"reason"`
	PredecessorFingerprint string                   `json:"predecessor_fingerprint"`
	SuccessorFingerprint   string                   `json:"successor_fingerprint"`
	RollbackRef            string                   `json:"rollback_ref"`
	Error                  string                   `json:"error"`
	IdempotencyKey         string                   `json:"idempotency_key"`
	CreatedAt              time.Time                `json:"created_at"`
	UpdatedAt              time.Time                `json:"updated_at"`
	CompletedAt            *time.Time               `json:"completed_at,omitempty"`
	HostJob                *rotationHostJobResponse `json:"host_job,omitempty"`
}

type rotationHostJobResponse struct {
	ID          int64      `json:"id"`
	Status      string     `json:"status"`
	Attempts    int        `json:"attempts"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
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

func identityDeploymentTargetID(identity store.Identity) string {
	if len(identity.Attributes) == 0 {
		return ""
	}
	var attributes struct {
		DeploymentTargetID string `json:"deployment_target_id"`
	}
	if err := json.Unmarshal(identity.Attributes, &attributes); err != nil {
		return ""
	}
	return strings.TrimSpace(attributes.DeploymentTargetID)
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
		if deploymentTargetRequestEnabled(req.Enabled) {
			if _, err := a.store.ValidateHostTargetAssignment(ctx, tenantID, req.Connector, req.Config); err != nil {
				return 0, nil, errWithStatus(http.StatusUnprocessableEntity, err)
			}
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
		if enabled {
			if _, err := a.store.ValidateHostTargetAssignment(ctx, tenantID, req.Connector, req.Config); err != nil {
				return 0, nil, errWithStatus(http.StatusUnprocessableEntity, err)
			}
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
		if _, err := a.store.ValidateHostTargetAssignment(ctx, tenantID, target.Type, target.Config); err != nil {
			return 0, nil, errWithStatus(http.StatusUnprocessableEntity, err)
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
			if err := requireEndpointIssuancePermission(ctx, tenantID); err != nil {
				return 0, nil, err
			}
			// Keep a retry on its existing destination. The full identity snapshot
			// participates in approval evidence and is checked again at issuance.
			if identityDeploymentTargetID(identity) != target.ID {
				if _, err := a.orch.BindIdentityDeploymentTarget(ctx, tenantID, req.IdentityID, target); err != nil {
					return 0, nil, err
				}
			}
			reviewedIdentity, version, err := a.store.IdentityApprovalTarget(ctx, tenantID, req.IdentityID)
			if err != nil {
				return 0, nil, err
			}
			principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
			if _, _, err := a.executeIdentityTransition(ctx, tenantID, principal, req.IdentityID,
				transitionRequest{To: string(orchestrator.StateIssued), Reason: reason, ExpectedVersion: &version, reviewedIdentity: &reviewedIdentity}, idempotencyKey); err != nil {
				return 0, nil, err
			}
		case orchestrator.StateIssued:
			return 0, nil, errStatus(http.StatusConflict,
				"this identity is issued, but issued state does not retain the private key needed for a new deployment; wait for its already-bound issuance delivery, or bind the target and start a renewal/reissue so fresh credential material reaches the executor; nothing was queued or changed")
		case orchestrator.StateRenewing:
			return 0, nil, errStatus(http.StatusConflict,
				"this identity is already renewing; wait for the successor credential and its bound connector delivery instead of queuing a keyless deploy; nothing was queued or changed")
		case orchestrator.StateRenewalFailed:
			return 0, nil, errStatus(http.StatusConflict,
				"the last renewal failed, so there is no successor credential to deploy; retry the renewal after repairing its failure; nothing was queued or changed")
		case orchestrator.StateRevoked, orchestrator.StateRetired:
			return 0, nil, errStatus(http.StatusConflict,
				"a revoked or retired identity cannot be deployed; issue an active replacement instead; nothing was queued or changed")
		case orchestrator.StateDeployed:
			if identityDeploymentTargetID(identity) != target.ID {
				return 0, nil, errStatus(http.StatusConflict,
					"this identity is already deployed to a different target, and trstctl does not retain its private key for copying elsewhere; bind the new target and renew/reissue first; nothing was queued or changed")
			}
			// Already converged by the issuer's credential-bearing deploy path.
		default:
			return 0, nil, errStatus(http.StatusConflict,
				"this identity state cannot safely produce a credential-bearing deployment; issue or renew it after binding the target; nothing was queued or changed")
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
			req.IdentityID = evidence.IdentityID
			if req.IdentityID != "" {
				identityID = &req.IdentityID
			}
			fingerprint = evidence.Fingerprint
			p := a.store.ResolvePredecessorCertificateForFingerprint(ctx, tenantID, evidence.Fingerprint)
			predecessor = predecessorCertificate{Serial: p.Serial, Fingerprint: p.Fingerprint}
		}
		if predecessor.Fingerprint == "" {
			return 0, nil, errStatus(http.StatusConflict,
				"this target has no predecessor certificate to restore; no rollback receipt was recorded")
		}

		// Execution uses the configured route; receipt text names the destination.
		rollbackTarget := orchestrator.DeploymentRoute(target)
		if strings.TrimSpace(rollbackTarget) == "" {
			rollbackTarget = target.Name
		}
		if connector.CanRollbackOnHost(target.Type) {
			rollbackRef = "queued for exact enrolled host-agent execution on " + target.Name +
				": restore predecessor certificate serial " + predecessor.Serial +
				" (fingerprint " + predecessor.Fingerprint + ") from that agent's encrypted local ledger. " +
				"The predecessor key never passes through the control plane. " +
				"The agent reloads the service and reverifies the configured listener; missing or mismatched local state fails closed."
		} else {
			rollbackRef = "queued for enrolled network-relay execution on " + target.Name +
				": re-bind to the predecessor certificate serial " + predecessor.Serial +
				" (fingerprint " + predecessor.Fingerprint + "). No key is uploaded. " +
				"Whether that object is still installed on the target is verified by the relay when it runs; " +
				"if it is gone the rollback fails rather than reporting success."
		}
		queued, receipt, err := a.orch.RequestConnectorRollbackWithReceipt(ctx, tenantID, orchestrator.ConnectorRollbackRequest{
			Connector: target.Type, Target: rollbackTarget, TargetID: target.ID,
			IdentityID: strings.TrimSpace(req.IdentityID), TargetConfig: target.Config,
			PredecessorFingerprint: predecessor.Fingerprint, PredecessorSerial: predecessor.Serial,
			SuccessorFingerprint: fingerprint, RequiredAgentID: requiredAgentID, Reason: reason,
		}, store.ConnectorDeliveryReceipt{
			IdentityID: identityID, Target: target.Name, Reason: statusReason, Detail: reason,
			RollbackRef: rollbackRef, IdempotencyKey: idempotencyKey,
		})
		if errors.Is(err, store.ErrUnsafeRollback) {
			return 0, nil, errStatus(http.StatusConflict, store.ErrUnsafeRollback.Error())
		}
		if err != nil {
			return 0, nil, err
		}
		if !queued.Queued {
			return 0, nil, errStatus(http.StatusConflict,
				"a rollback for this target and predecessor exists and could not be re-queued; "+
					"inspect the connector delivery receipts for its outcome before retrying")
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

func (a *API) previewEndpointBinding(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	req, err := decodeEndpointBindingRequest(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	preview, err := a.endpointBindingPreview(r.Context(), tenantID, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, preview)
}

func endpointBindingReason(req endpointBindingRequest) string {
	if req.Reason != "" {
		return req.Reason
	}
	return "endpoint binding automation"
}

func (a *API) endpointBindingPreview(ctx context.Context, tenantID string, req endpointBindingRequest) (endpointBindingPreviewResponse, error) {
	owner, err := a.store.GetOwner(ctx, tenantID, req.OwnerID)
	if err != nil {
		return endpointBindingPreviewResponse{}, err
	}
	// Mirror the lifecycle exactly: issued->deployed checks ownership readiness
	// only when an attestation cadence is configured, so the preview refuses
	// only what deployment would refuse.
	if cadence := a.ownershipAttestationCadence; cadence > 0 {
		if ready, why := ownerReadyForLifecycle(owner, time.Now().UTC(), cadence); !ready {
			return endpointBindingPreviewResponse{}, errStatus(http.StatusUnprocessableEntity,
				"owner "+strings.TrimSpace(owner.Name)+" is not ready to own a deployed credential: "+why+
					"; deployment would be refused after issuance. Complete the accountability record and use Ownership → Re-attest, then preview again; nothing was queued")
		}
	}
	if err := validateWildcardIdentityPolicy(req.IdentityName, nil); err != nil {
		return endpointBindingPreviewResponse{}, err
	}
	target, err := a.endpointBindingPreviewTarget(ctx, tenantID, req)
	if err != nil {
		return endpointBindingPreviewResponse{}, err
	}
	cfg, err := canonicalEndpointBindingConfig(target.Config)
	if err != nil {
		return endpointBindingPreviewResponse{}, err
	}
	target.Config = cfg
	if _, err := a.store.ValidateHostTargetAssignment(ctx, tenantID, target.Connector, target.Config); err != nil {
		return endpointBindingPreviewResponse{}, errWithStatus(http.StatusUnprocessableEntity, err)
	}
	if err := validateEndpointBindingVerificationName(req.IdentityName, target.Config); err != nil {
		return endpointBindingPreviewResponse{}, err
	}
	issuer, err := a.resolveEndpointIssuer(ctx, tenantID, req.Issuer)
	if err != nil {
		return endpointBindingPreviewResponse{}, err
	}
	if err := a.checkEndpointIssuerValidationPrerequisites(ctx, tenantID, issuer, req.IdentityName); err != nil {
		return endpointBindingPreviewResponse{}, err
	}
	if externalIssuerRequiresHostCustody(issuer.Source, target.Connector, target.Config) {
		return endpointBindingPreviewResponse{}, errStatus(http.StatusUnprocessableEntity,
			"selected external CA answers asynchronously, and destination "+target.Name+" ("+target.Connector+") executes on a host agent with control-plane key custody; "+
				"a slow CA answer would strand the certificate without its private key. Set \"executor\": \"agent\" on the destination so the enrolled host agent generates the key, submits only a CSR, installs the certificate, and verifies the listener; no CA was substituted and nothing was queued")
	}
	// DP2-019: discovery may already have claimed this DNS name into an identity.
	// Bind that identity instead of minting a twin, and say so in the preview; its
	// id is part of the request fingerprint so a change between preview and create
	// is caught like any other.
	var existingResp *identityResponse
	var existingVersion uint64
	var replacedResp *identityResponse
	var replaced store.Identity
	var replacedVersion uint64
	identityChange := "Create one X.509 identity for " + req.IdentityName + " owned by " + strings.TrimSpace(owner.Name) + " (" + req.OwnerID + ")."
	if req.ReplaceIdentityID != "" {
		replaced, replacedVersion, err = a.store.IdentityApprovalTarget(ctx, tenantID, req.ReplaceIdentityID)
		if err != nil {
			return endpointBindingPreviewResponse{}, err
		}
		if err := store.ValidateEndpointReplacementSource(replaced, req.IdentityName, req.TargetID); err != nil {
			return endpointBindingPreviewResponse{}, errWithStatus(http.StatusConflict, err)
		}
		resp := toIdentityResponse(replaced)
		replacedResp = &resp
		identityChange = "Create a separate replacement for X.509 identity " + replaced.ID + " at " + req.IdentityName + " owned by " + strings.TrimSpace(owner.Name) + " (" + req.OwnerID + "). Keep the original until the replacement is verified, then revoke and retire it. Renewal of the original is held once replacement issuance is queued."
	} else if existing, found, err := a.store.FindIdentityByName(ctx, tenantID, req.IdentityName); err != nil {
		return endpointBindingPreviewResponse{}, err
	} else if found {
		existing, existingVersion, err = a.store.IdentityApprovalTarget(ctx, tenantID, existing.ID)
		if err != nil {
			return endpointBindingPreviewResponse{}, err
		}
		if existing.Name != req.IdentityName {
			return endpointBindingPreviewResponse{}, errStatus(http.StatusConflict, "existing identity changed during preview; preview again")
		}
		if err := store.ValidateIdentityEndpointIssuer(existing, store.IdentityEndpointIssuer{
			OwnerID: req.OwnerID, Source: issuer.Source, ID: issuer.ID, Name: issuer.Name,
		}); err != nil {
			return endpointBindingPreviewResponse{}, errWithStatus(http.StatusConflict, err)
		}
		resp := toIdentityResponse(existing)
		existingResp = &resp
		identityChange = "Enroll existing X.509 identity " + existing.ID + " for " + req.IdentityName + " owned by " + strings.TrimSpace(owner.Name) + " (" + req.OwnerID + ")."
	}
	profileRequirement, err := a.endpointIssuanceRequirement(ctx, tenantID, existingResp, req.ProfileName)
	if err != nil {
		return endpointBindingPreviewResponse{}, err
	}
	if err := a.validateEndpointProfileMetadata(ctx, tenantID, req.IdentityName, profileRequirement); err != nil {
		return endpointBindingPreviewResponse{}, err
	}
	fingerprintInput := struct {
		ExistingIdentityVersion uint64                                  `json:"existing_identity_version,omitempty"`
		Issuance                *store.OperationApprovalIssuanceBinding `json:"issuance"`
		ApprovalRequired        bool                                    `json:"approval_required"`
		OwnerID                 string                                  `json:"owner_id"`
		IdentityName            string                                  `json:"identity_name"`
		Reason                  string                                  `json:"reason"`
		Issuer                  endpointIssuerSummary                   `json:"issuer"`
		Target                  endpointBindingTargetSummary            `json:"target"`
		ExistingIdentity        *identityResponse                       `json:"existing_identity,omitempty"`
		ReplacedIdentity        *identityResponse                       `json:"replaced_identity,omitempty"`
		ReplacedVersion         uint64                                  `json:"replaced_identity_version,omitempty"`
	}{existingVersion, profileRequirement.IssuanceBinding(), a.gate.RequireApproval || profileRequirement.RequiresApproval, req.OwnerID, req.IdentityName, endpointBindingReason(req), issuer, target, existingResp, replacedResp, replacedVersion}
	raw, err := json.Marshal(fingerprintInput)
	if err != nil {
		return endpointBindingPreviewResponse{}, err
	}
	fingerprint := crypto.SHA256Hex(raw)
	if replacedResp != nil {
		active, err := a.store.ActiveEndpointReplacement(ctx, tenantID, replaced.ID)
		if err != nil {
			return endpointBindingPreviewResponse{}, err
		}
		if active != "" && active != orchestrator.EndpointReplacementIdentityID(tenantID, replaced.ID, fingerprint) {
			return endpointBindingPreviewResponse{}, errStatus(http.StatusConflict,
				"original already has active replacement "+active+"; complete or revoke it before starting another; nothing was queued or changed")
		}
	}
	agentKeygen := custody.TargetExecutorIsAgent(target.Config)
	custodySummary := endpointBindingCustody{
		KeyOrigin:              "control_plane",
		PrivateKeyControlPlane: true,
		Detail:                 "trstctl generates the subject key in locked memory, retains a tenant-bound encrypted copy for delivery recovery, sends the key only to the selected connector, and wipes temporary plaintext buffers",
	}
	if agentKeygen {
		custodySummary = endpointBindingCustody{
			KeyOrigin:              "host_agent",
			PrivateKeyControlPlane: false,
			Detail:                 "the host agent generates the subject key, sends only a CSR, installs the returned certificate, and verifies the listener",
		}
	}
	return endpointBindingPreviewResponse{
		ExistingIdentityVersion: existingVersion,
		Issuance:                profileRequirement.IssuanceBinding(),
		ApprovalRequired:        a.gate.RequireApproval || profileRequirement.RequiresApproval,
		ExistingIdentity:        existingResp,
		ReplacedIdentity:        replacedResp,
		ReplacedIdentityVersion: replacedVersion,
		replacementSource:       replaced,
		Capability:              "endpoint_binding",
		Ready:                   true,
		EffectFree:              true,
		RequestFingerprint:      fingerprint,
		OwnerID:                 req.OwnerID,
		IdentityName:            req.IdentityName,
		Issuer:                  issuer,
		Target:                  target,
		Custody:                 custodySummary,
		Changes: []string{
			identityChange,
			"Pin issuance and renewal to " + issuer.Name + " (" + issuer.Source + ":" + issuer.ID + ").",
			"Bind the identity to " + target.Name + " through the " + target.Connector + " connector.",
		},
		QueuedLifecycleIntents: []string{"ca.issue", "connector.deploy"},
		RecoverySteps: []string{
			"Stop or disable the destination before retrying if deployment is unsafe.",
			"Use the connector delivery receipt and predecessor fingerprint for supported rollback.",
		},
		VerificationSteps: []string{
			"Wait for the issuance and connector delivery receipts to reach a terminal state.",
			"Open a fresh connection to the listener and compare hostname, fingerprint, chain, and application response.",
		},
		PreviewWrites:          []string{},
		PreviewExternalEffects: []string{},
	}, nil
}

// validateEndpointBindingVerificationName stops a deploy that is guaranteed to
// fail its own post-write TLS proof. A host connector's verify_server_name is
// the SNI/DNS name clients are expected to use. The single-name endpoint
// workflow must issue that same name; otherwise the connector can replace the
// files successfully and only discover the mistake after the listener reloads.
func validateEndpointBindingVerificationName(identityName string, raw json.RawMessage) error {
	var target struct {
		VerifyServerName string `json:"verify_server_name"`
	}
	if err := json.Unmarshal(raw, &target); err != nil {
		return errWithStatus(http.StatusBadRequest, err)
	}
	want := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target.VerifyServerName)), ".")
	got := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(identityName)), ".")
	if want == "" || got == want {
		return nil
	}
	return errStatus(http.StatusConflict,
		"requested DNS name "+identityName+" does not match destination verify_server_name "+target.VerifyServerName+
			"; use the exact hostname clients use or choose a destination configured for this hostname; nothing was queued or changed")
}

func (a *API) endpointBindingPreviewTarget(ctx context.Context, tenantID string, req endpointBindingRequest) (endpointBindingTargetSummary, error) {
	if req.TargetID != "" {
		target, err := a.store.GetDeploymentTarget(ctx, tenantID, req.TargetID)
		if err != nil {
			return endpointBindingTargetSummary{}, err
		}
		if err := requireDeploymentTargetEnabled(target); err != nil {
			return endpointBindingTargetSummary{}, err
		}
		return endpointBindingTargetSummary{
			ID: target.ID, Name: target.Name, Connector: target.Type, Config: target.Config,
			Enabled: target.Enabled, Revision: target.RevisionID,
		}, nil
	}
	if req.Target == nil || !deploymentTargetRequestEnabled(req.Target.Enabled) {
		return endpointBindingTargetSummary{}, errStatus(http.StatusConflict,
			"deployment target is disabled; enable it only after its agent or relay and endpoint have been verified; nothing was queued or changed")
	}
	return endpointBindingTargetSummary{
		Name: req.Target.Name, Connector: req.Target.Connector, Config: req.Target.Config, Enabled: true,
	}, nil
}

func (a *API) resolveEndpointIssuer(ctx context.Context, tenantID string, req endpointIssuerRequest) (endpointIssuerSummary, error) {
	switch req.Source {
	case endpointIssuerPlatform:
		if req.ID != endpointPlatformCAID {
			return endpointIssuerSummary{}, errStatus(http.StatusUnprocessableEntity,
				"platform issuer id must be trstctl-issuing-ca; no CA was selected")
		}
		return endpointIssuerSummary{Source: req.Source, ID: req.ID, Name: "trstctl built-in issuing CA", Type: "x509", Availability: "available"}, nil
	case endpointIssuerPrivate:
		if a.caHierarchy == nil {
			return endpointIssuerSummary{}, ErrCAHierarchyUnavailable
		}
		items, err := a.caHierarchy.ListAuthorities(ctx, tenantID)
		if err != nil {
			return endpointIssuerSummary{}, err
		}
		for _, item := range items {
			if item.ID != req.ID {
				continue
			}
			if item.Status != "active" || strings.TrimSpace(item.SignerHandle) == "" {
				return endpointIssuerSummary{}, errStatus(http.StatusConflict,
					"selected private CA is not active and signer-backed; no CA was substituted and nothing was queued")
			}
			return endpointIssuerSummary{Source: req.Source, ID: item.ID, Name: item.CommonName, Type: item.Kind, Availability: item.Status}, nil
		}
		return endpointIssuerSummary{}, errStatus(http.StatusUnprocessableEntity,
			"selected private CA is not configured for this tenant; no CA was substituted and nothing was queued")
	case endpointIssuerExternal:
		if a.externalCAs == nil {
			return endpointIssuerSummary{}, ErrExternalCAUnavailable
		}
		items, err := a.externalCAs.ListExternalCAs(ctx, tenantID)
		if err != nil {
			return endpointIssuerSummary{}, err
		}
		for _, item := range items {
			if item.ID != req.ID {
				continue
			}
			if item.Status != "available" {
				return endpointIssuerSummary{}, errStatus(http.StatusConflict,
					"selected external CA is unavailable; no CA was substituted and nothing was queued")
			}
			return endpointIssuerSummary{Source: req.Source, ID: item.ID, Name: item.Name, Type: item.Type, Availability: item.Status, upstreamDNS01: item.UpstreamDNS01}, nil
		}
		return endpointIssuerSummary{}, errStatus(http.StatusUnprocessableEntity,
			"selected external CA is not configured for this tenant; no CA was substituted and nothing was queued")
	default:
		return endpointIssuerSummary{}, errStatus(http.StatusBadRequest,
			"issuer.source must be platform, private, or external")
	}
}

// checkEndpointIssuerValidationPrerequisites fails the preview closed when the
// pinned authority cannot validate the requested name. An ACME authority with
// upstream DNS-01 publishes its challenge through a tenant DNS-01 provider
// config; without one covering the name (dns-01 allowed, wildcards where needed,
// allow_upstream_dv on) issuance would queue, fail asynchronously, and dead-letter
// while the identity reads "waiting to be issued". The preview promises
// readiness, so it must check the prerequisite the worker will enforce, using
// the same matching rule (acme.DNS01ZoneCovers).
func (a *API) checkEndpointIssuerValidationPrerequisites(ctx context.Context, tenantID string, issuer endpointIssuerSummary, identityName string) error {
	if issuer.Source != endpointIssuerExternal || !issuer.upstreamDNS01 {
		return nil
	}
	if a.store == nil {
		return nil
	}
	configs, err := a.store.ListACMEDNS01ProviderConfigs(ctx, tenantID)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(identityName)
	covered, consented := evaluateDNS01Coverage(configs, name)
	switch {
	case consented:
		return nil
	case covered:
		return errStatus(http.StatusUnprocessableEntity,
			"selected external CA "+issuer.Name+" validates "+name+" with DNS-01, and a tenant DNS-01 provider config covers that zone but none is enabled for upstream domain validation; set allow_upstream_dv on the config that should publish challenge records, then preview again; no CA was substituted and nothing was queued")
	default:
		return errStatus(http.StatusUnprocessableEntity,
			"selected external CA "+issuer.Name+" validates "+name+" with DNS-01, but no tenant DNS-01 provider config covers that zone; add one (POST /api/v1/acme/dns-01/provider-configs or `trstctl-cli acme dns-01 provider-configs`) with dns-01 allowed and allow_upstream_dv enabled, then preview again; no CA was substituted and nothing was queued")
	}
}

// evaluateDNS01Coverage reports whether any tenant DNS-01 provider config could
// publish a challenge for name (covered) and whether one of those is enabled for
// upstream domain validation (consented). It mirrors the worker's selection
// rule so the preview and order-time automation cannot disagree.
func evaluateDNS01Coverage(configs []store.ACMEDNS01ProviderConfig, name string) (covered, consented bool) {
	for _, cfg := range configs {
		if !stringInList(cfg.AllowedMethods, acme.ChallengeDNS01) {
			continue
		}
		if acme.IsWildcard(name) && !cfg.AllowWildcards {
			continue
		}
		if !acme.DNS01ZoneCovers(cfg.Zone, cfg.ChallengeDomain, name) {
			continue
		}
		covered = true
		if cfg.AllowUpstreamDV {
			return true, true
		}
	}
	return covered, false
}

// externalIssuerRequiresHostCustody is the custody rule the preview enforces for
// external authorities. An external CA is asynchronous from the control plane's
// point of view (an outbox worker submits the CSR and waits), while a
// control-plane-generated key lives only for one attempt (AN-8) and is wiped on
// timeout. If the CA answers after that attempt, the retry recovers the
// certificate by issuance key with no key to deploy: the identity reads issued,
// the listener never changes, and nothing errors. Host-executed connectors have
// the supported alternative — executor=agent, where the host generates the key,
// sends only a CSR, installs, and verifies — so the preview requires it.
func externalIssuerRequiresHostCustody(source, connector string, cfg json.RawMessage) bool {
	if source != endpointIssuerExternal {
		return false
	}
	if !relay.ExecutesOnHost(strings.TrimSpace(connector)) {
		return false
	}
	return !custody.TargetExecutorIsAgent(cfg)
}

// ownerReadyForLifecycle is the preview's copy of the rule the lifecycle enforces
// at issued->deployed (ownership readiness). Checking it before authorization
// turns a silent post-deploy refusal into an actionable 422 while nothing has
// been issued yet.
func ownerReadyForLifecycle(o store.Owner, now time.Time, cadence time.Duration) (bool, string) {
	switch {
	case !o.OwnershipComplete():
		return false, "the record has no application ID or environment"
	case !o.OwnershipAttested():
		return false, "no human has attested this ownership yet"
	case !o.OwnershipCurrent(now, cadence):
		return false, "the ownership attestation is stale or no longer matches the record"
	}
	return true, ""
}

func stringInList(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func canonicalEndpointBindingConfig(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return json.RawMessage("{}"), nil
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, errStatus(http.StatusBadRequest, "target config must be a JSON object")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonical, nil
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
	req.ReplaceIdentityID = strings.TrimSpace(req.ReplaceIdentityID)
	req.IdentityName = strings.TrimSpace(req.IdentityName)
	req.ProfileName = strings.TrimSpace(req.ProfileName)
	req.TargetID = strings.TrimSpace(req.TargetID)
	req.Issuer.Source = strings.ToLower(strings.TrimSpace(req.Issuer.Source))
	req.Issuer.ID = strings.TrimSpace(req.Issuer.ID)
	req.Reason = strings.TrimSpace(req.Reason)
	req.PreviewFingerprint = strings.ToLower(strings.TrimSpace(req.PreviewFingerprint))
	if req.OwnerID == "" {
		return endpointBindingRequest{}, errStatus(http.StatusBadRequest, "owner_id is required")
	}
	if req.IdentityName == "" {
		return endpointBindingRequest{}, errStatus(http.StatusBadRequest, "identity_name is required")
	}
	if req.Issuer.Source == "" || req.Issuer.ID == "" {
		return endpointBindingRequest{}, errStatus(http.StatusBadRequest, "issuer.source and issuer.id are required")
	}
	if req.TargetID != "" && req.Target != nil {
		return endpointBindingRequest{}, errStatus(http.StatusBadRequest, "provide target_id or target, not both")
	}
	if req.ReplaceIdentityID != "" && req.TargetID == "" {
		return endpointBindingRequest{}, errStatus(http.StatusBadRequest, "replacement requires the original destination's target_id")
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
	limit, afterUpdatedAt, after, err := a.connectorReceiptPageParams(r, tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	identityID := r.URL.Query().Get("identity_id")
	key := r.URL.Query().Get("idempotency_key")
	if len(key) > 2048 {
		a.writeError(w, errStatus(http.StatusBadRequest, "idempotency_key must not exceed 2048 bytes"))
		return
	}
	rows, err := a.store.ListConnectorDeliveryReceiptsNewestPage(r.Context(), tenantID, identityID, key, after, afterUpdatedAt, limit)
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
		next = encodeConnectorReceiptCursor(rows[len(rows)-1])
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
	response := toRotationRunResponse(row)
	job, err := a.store.RotationRunHostJob(r.Context(), tenantID, row)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if job != nil {
		response.HostJob = &rotationHostJobResponse{ID: job.ID, Status: job.Status, Attempts: job.Attempt, CompletedAt: job.CompletedAt}
	}
	a.writeJSON(w, http.StatusOK, response)
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
		if vantage, shipped := connector.ShippedTargetVantage(item.Name); shipped {
			item.TargetVantage = string(vantage)
		}
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
		if a.connectorRegistry != nil && a.connectorRegistry.Has(item.Name) {
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
