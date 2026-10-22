// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/rightsize"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// RightSizeMutation is independently read-back evidence that an entitlement API
// applied one connector.right_size intent.
type RightSizeMutation struct {
	MutationID     string
	RollbackRef    string
	ReadbackDigest string
}

// RightSizeMutator applies a usage-backed scope reduction to an external
// entitlement system. Implementations must be idempotent on Message.IdempotencyKey.
type RightSizeMutator interface {
	Mutate(context.Context, orchestrator.Message, projections.RemediationPlaybookRunRecorded) (RightSizeMutation, error)
}

type connectorRightSizeRuntime struct {
	bindings   map[string]config.ConnectorRightSizeBinding
	credential func(context.Context, string, string) ([]byte, func(), error)
	client     *http.Client
}

type connectorRightSizeScopeDelta struct {
	RemoveScopes      []string `json:"remove_scopes"`
	RecommendedScopes []string `json:"recommended_scopes"`
}

func (d *issuanceDispatcher) handleConnectorRightSize(ctx context.Context, message orchestrator.Message) error {
	var playbook projections.RemediationPlaybookRunRecorded
	if err := json.Unmarshal(message.Payload, &playbook); err != nil {
		return fmt.Errorf("server: decode connector right-size intent: %w", err)
	}
	if playbook.Action != "right_size" || strings.TrimSpace(playbook.Connector) == "" || strings.TrimSpace(playbook.Target) == "" {
		return fmt.Errorf("server: connector right-size intent is incomplete")
	}
	// A64: a binding that names a network relay hands the operation to the
	// relay. The row is stamped for the network role the first time the
	// control plane sees it (the projector that queued it knows no bindings)
	// and left pending for the relay to claim; no endpoint I/O happens here.
	if _, relayBound := d.relayRightSizeBinding(message.TenantID, playbook); relayBound {
		if message.RequiredAgentRole != "network" && d.store != nil {
			if _, err := d.store.StampOutboxAgentRole(ctx, message.TenantID, message.ID, "network"); err != nil {
				return orchestrator.DeferDelivery(err)
			}
		}
		return orchestrator.DeferDelivery(fmt.Errorf(
			"server: the %s right-size binding names a network relay, so this operation executes there, not in the control plane", playbook.Connector))
	}
	if d.connectorRightSize == nil {
		return fmt.Errorf("server: connector right-size outbox destination is not configured")
	}
	if playbook.RequestBinding != "" {
		return d.handleDurableConnectorRightSize(ctx, message, playbook)
	}
	return d.handleLegacyConnectorRightSize(ctx, message, playbook)
}

func (d *issuanceDispatcher) handleLegacyConnectorRightSize(ctx context.Context, message orchestrator.Message, playbook projections.RemediationPlaybookRunRecorded) error {
	deliveryID := evidenceID("connector-right-size", message.TenantID, message.IdempotencyKey, message.ID)
	if playbook.ConnectorDeliveryID != nil && strings.TrimSpace(*playbook.ConnectorDeliveryID) != "" {
		deliveryID = strings.TrimSpace(*playbook.ConnectorDeliveryID)
	}
	var identityID *string
	if value := strings.TrimSpace(playbook.TargetIdentityID); value != "" {
		identityID = &value
	}
	receipt := connectorDeliveryEvidence{
		ID: deliveryID, OutboxID: outboxPtr(message.ID), IdentityID: identityID,
		Destination: message.Destination, Connector: playbook.Connector, Target: playbook.Target,
		Attempts: message.Attempts, IdempotencyKey: playbook.IdempotencyKey,
	}
	// The durable outbox is the only caller of Mutate. Do not wrap the network
	// round trip in Idempotency.Do: that helper holds a PostgreSQL transaction
	// while fn runs, which would let a slow entitlement API consume a database
	// connection. The receiver gets the stable outbox idempotency key, so a crash
	// after PATCH but before receipt projection safely repeats the same mutation,
	// reads it back, and records the deterministic receipt.
	mutation, err := d.connectorRightSize.Mutate(ctx, message, playbook)
	if err != nil {
		// Legacy events still fail closed, but receiver-controlled error text never
		// enters the event log or receipt: an entitlement gateway may echo its token.
		receipt.Detail = "external entitlement mutation failed before verified readback"
		_ = d.recordConnectorDelivery(ctx, message.TenantID, receipt, "failed", "entitlement_mutation_failed")
		return err
	}
	receipt.Fingerprint = mutation.ReadbackDigest
	receipt.RollbackRef = mutation.RollbackRef
	receipt.Detail = "external entitlement mutation " + mutation.MutationID + " verified by readback sha256:" + mutation.ReadbackDigest
	return d.recordConnectorDelivery(ctx, message.TenantID, receipt, "delivered", "entitlements_mutated")
}

func (d *issuanceDispatcher) handleDurableConnectorRightSize(ctx context.Context, message orchestrator.Message, playbook projections.RemediationPlaybookRunRecorded) error {
	if d.store == nil || d.log == nil {
		return fmt.Errorf("server: durable connector right-size state is not configured")
	}
	identity := orchestrator.ConnectorRightSizeIdentityFor(message.TenantID, playbook.IdempotencyKey)
	expectedLane := orchestrator.DestinationConnectorRightSize + ":" + playbook.Connector + ":" + playbook.Target
	if playbook.ID != identity.OperationID || playbook.ConnectorDeliveryID == nil ||
		*playbook.ConnectorDeliveryID != identity.DeliveryID ||
		playbook.OutboxIdempotencyKey != identity.OutboxIdempotencyKey ||
		message.IdempotencyKey != identity.OutboxIdempotencyKey || message.EffectLane != expectedLane {
		return fmt.Errorf("server: connector right-size deterministic binding is invalid")
	}
	run, err := d.store.GetRemediationPlaybookRun(ctx, message.TenantID, identity.OperationID)
	if err != nil {
		return fmt.Errorf("server: load connector right-size operation: %w", err)
	}
	if run.RequestBinding == "" ||
		!crypto.ConstantTimeEqual([]byte(run.RequestBinding), []byte(playbook.RequestBinding)) ||
		run.ConnectorDeliveryID == nil || *run.ConnectorDeliveryID != identity.DeliveryID ||
		run.Connector != playbook.Connector || run.Target != playbook.Target {
		return fmt.Errorf("server: connector right-size operation does not match its outbox command")
	}
	switch run.Status {
	case "succeeded", "failed":
		// A terminal domain event is authoritative. This path is reached when boot
		// reconciliation recreated a GC'd outbox row or the worker crashed after
		// projection but before ACK; neither case may repeat receiver I/O.
		return nil
	case "queued":
		if run.OutboxID == nil || *run.OutboxID != message.ID {
			return fmt.Errorf("server: queued connector right-size operation does not match its outbox row")
		}
	default:
		return fmt.Errorf("server: connector right-size operation has invalid status %q", run.Status)
	}

	mutation, err := d.connectorRightSize.Mutate(ctx, message, playbook)
	if err != nil {
		// Retry bookkeeping belongs to the outbox. Persisting a raw provider error
		// here would both make the operation falsely terminal and retain receiver
		// data in a user-visible receipt.
		return err
	}
	if d.afterRightSizeSideEffects != nil {
		if err := d.afterRightSizeSideEffects(ctx); err != nil {
			return err
		}
	}
	return d.appendConnectorRightSizeTerminal(ctx, message, playbook, "delivered",
		"entitlements_mutated",
		"external entitlement mutation "+mutation.MutationID+" verified by readback sha256:"+mutation.ReadbackDigest,
		mutation.ReadbackDigest, mutation.RollbackRef)
}

func (d *issuanceDispatcher) failConnectorRightSizeTerminal(ctx context.Context, message orchestrator.Message) error {
	var playbook projections.RemediationPlaybookRunRecorded
	if err := json.Unmarshal(message.Payload, &playbook); err != nil {
		return fmt.Errorf("server: decode terminal connector right-size intent: %w", err)
	}
	if playbook.RequestBinding == "" {
		return nil // legacy requests recorded their terminal receipt in Deliver.
	}
	identity := orchestrator.ConnectorRightSizeIdentityFor(message.TenantID, playbook.IdempotencyKey)
	run, err := d.store.GetRemediationPlaybookRun(ctx, message.TenantID, identity.OperationID)
	if err != nil {
		return err
	}
	if run.Status == "succeeded" || run.Status == "failed" {
		return nil
	}
	rollbackRef := ""
	if len(run.RollbackRefs) > 0 {
		rollbackRef = run.RollbackRefs[0]
	}
	return d.appendConnectorRightSizeTerminal(ctx, message, playbook, "failed",
		"entitlement_mutation_retry_exhausted",
		"external entitlement mutation did not reach verified completion before the retry budget was exhausted",
		"", rollbackRef)
}

func (d *issuanceDispatcher) appendConnectorRightSizeTerminal(
	ctx context.Context,
	message orchestrator.Message,
	playbook projections.RemediationPlaybookRunRecorded,
	status, reason, detail, fingerprint, rollbackRef string,
) error {
	identity := orchestrator.ConnectorRightSizeIdentityFor(message.TenantID, playbook.IdempotencyKey)
	if message.ID == 0 || playbook.ID != identity.OperationID ||
		playbook.ConnectorDeliveryID == nil || *playbook.ConnectorDeliveryID != identity.DeliveryID {
		return fmt.Errorf("server: connector right-size terminal binding is invalid")
	}
	outboxID := message.ID
	payload, err := json.Marshal(projections.ConnectorDeliveryRecorded{
		ID: identity.DeliveryID, OutboxID: &outboxID, RemediationRunID: identity.OperationID,
		Destination: orchestrator.DestinationConnectorRightSize,
		Connector:   playbook.Connector, Target: playbook.Target, Fingerprint: fingerprint,
		Status: status, Attempts: message.Attempts, Reason: reason, Detail: detail,
		RollbackRef: rollbackRef, IdempotencyKey: identity.OutboxIdempotencyKey,
	})
	if err != nil {
		return err
	}
	ev, err := d.log.Append(ctx, events.Event{
		ID: identity.TerminalEventID, Type: projections.EventConnectorDeliveryRecorded,
		TenantID: message.TenantID, Time: time.Now().UTC(), Data: payload,
	})
	if err != nil {
		return err
	}
	if d.afterRightSizeTerminalAppend != nil {
		if err := d.afterRightSizeTerminalAppend(ctx); err != nil {
			return err
		}
	}
	return projections.New(d.store).Apply(ctx, ev)
}

// connectorRightSizeHandler is the production constructor reached from
// buildRunDeps. A binding is tenant-specific, so an outbox row can never select
// another tenant's entitlement endpoint or token reference.
func connectorRightSizeHandler(cfg config.Connectors, st *store.Store, kek seal.KeyWrapper, guard *egress.Guard, tenantCrypto ...tenantseal.Access) (RightSizeMutator, error) {
	if len(cfg.RightSize) == 0 {
		return nil, nil
	}
	if st == nil || kek == nil {
		return nil, fmt.Errorf("connector right-size bindings require the tenant secret-store runtime")
	}
	client, err := connectorHTTPClientFromConfig(cfg, guard)
	if err != nil {
		return nil, err
	}
	var access tenantseal.Access
	if len(tenantCrypto) > 0 {
		access = tenantCrypto[0]
	}
	runtime := &connectorRightSizeRuntime{
		bindings: make(map[string]config.ConnectorRightSizeBinding, len(cfg.RightSize)),
		client:   client,
		credential: func(ctx context.Context, tenantID, ref string) ([]byte, func(), error) {
			lease := &connectorCredentialLease{store: st, kek: kek, crypto: access, tenantID: tenantID}
			value, err := lease.require(ctx, ref)
			if err != nil {
				lease.Close()
				return nil, nil, err
			}
			return value, lease.Close, nil
		},
	}
	for index, binding := range cfg.RightSize {
		binding.TenantID = strings.TrimSpace(binding.TenantID)
		binding.Connector = strings.TrimSpace(binding.Connector)
		binding.Endpoint = strings.TrimRight(strings.TrimSpace(binding.Endpoint), "/")
		binding.TokenRef = strings.TrimSpace(binding.TokenRef)
		if binding.TenantID == "" || binding.Connector == "" {
			return nil, fmt.Errorf("connector right-size binding %d requires tenant_id and connector", index)
		}
		if err := validateConnectorEndpoint(binding.Endpoint, cfg); err != nil {
			return nil, fmt.Errorf("connector right-size binding %d endpoint: %w", index, err)
		}
		if _, _, err := parseConnectorSecretRef(binding.TokenRef); err != nil {
			return nil, fmt.Errorf("connector right-size binding %d token_ref: %w", index, err)
		}
		key := rightSizeBindingKey(binding.TenantID, binding.Connector)
		if _, exists := runtime.bindings[key]; exists {
			return nil, fmt.Errorf("duplicate connector right-size binding for tenant %s connector %s", binding.TenantID, binding.Connector)
		}
		runtime.bindings[key] = binding
	}
	return runtime, nil
}

func rightSizeBindingKey(tenantID, connectorName string) string {
	return tenantID + "\x00" + connectorName
}

// rightSizeBindingMap indexes the operator's bindings by tenant and connector.
func rightSizeBindingMap(bindings []config.ConnectorRightSizeBinding) map[string]config.ConnectorRightSizeBinding {
	out := make(map[string]config.ConnectorRightSizeBinding, len(bindings))
	for _, binding := range bindings {
		binding.TenantID = strings.TrimSpace(binding.TenantID)
		binding.Connector = strings.TrimSpace(binding.Connector)
		binding.Endpoint = strings.TrimRight(strings.TrimSpace(binding.Endpoint), "/")
		binding.TokenRef = strings.TrimSpace(binding.TokenRef)
		if binding.TenantID == "" || binding.Connector == "" {
			continue
		}
		out[rightSizeBindingKey(binding.TenantID, binding.Connector)] = binding
	}
	return out
}

// relayRightSizeBinding reports the binding a queued operation falls under
// when that binding names a network relay as its executor (A64).
func (d *issuanceDispatcher) relayRightSizeBinding(tenantID string, playbook projections.RemediationPlaybookRunRecorded) (config.ConnectorRightSizeBinding, bool) {
	binding, ok := d.rightSizeBindings[rightSizeBindingKey(tenantID, strings.TrimSpace(playbook.Connector))]
	if !ok || !binding.ExecutesOnRelay() {
		return config.ConnectorRightSizeBinding{}, false
	}
	return binding, true
}

// completeRelayRightSize records a relay's verified right-size mutation as the
// operation's deterministic terminal receipt, exactly as the control-plane
// worker would after its own readback (A64). The evidence is the relay's: the
// server verified the signed report's shape and digest, not the endpoint.
func (d *issuanceDispatcher) completeRelayRightSize(ctx context.Context, tenantID string, jobID int64, attempt int, payload []byte, result relay.RightSizeReport) error {
	var playbook projections.RemediationPlaybookRunRecorded
	if err := json.Unmarshal(payload, &playbook); err != nil {
		return fmt.Errorf("server: decode relay right-size intent: %w", err)
	}
	if _, relayBound := d.relayRightSizeBinding(tenantID, playbook); !relayBound {
		return errors.New("server: right-size binding no longer names a network relay; the result is not recorded")
	}
	message := orchestrator.Message{ID: jobID, TenantID: tenantID, Destination: orchestrator.DestinationConnectorRightSize,
		IdempotencyKey: playbook.OutboxIdempotencyKey, Attempts: attempt}
	return d.appendConnectorRightSizeTerminal(ctx, message, playbook, "delivered",
		"entitlements_mutated",
		"external entitlement mutation "+result.MutationID+" verified by network-relay readback sha256:"+result.ReadbackDigest,
		result.ReadbackDigest, result.RollbackRef)
}

// failRelayRightSize closes the operation after a relay reported that the
// endpoint refused or failed the mutation.
func (d *issuanceDispatcher) failRelayRightSize(ctx context.Context, tenantID string, jobID int64, attempt int, payload []byte, reason string) error {
	var playbook projections.RemediationPlaybookRunRecorded
	if err := json.Unmarshal(payload, &playbook); err != nil {
		return fmt.Errorf("server: decode relay right-size intent: %w", err)
	}
	rollbackRef := ""
	if len(playbook.RollbackRefs) > 0 {
		rollbackRef = playbook.RollbackRefs[0]
	}
	message := orchestrator.Message{ID: jobID, TenantID: tenantID, Destination: orchestrator.DestinationConnectorRightSize,
		IdempotencyKey: playbook.OutboxIdempotencyKey, Attempts: attempt}
	return d.appendConnectorRightSizeTerminal(ctx, message, playbook, "failed",
		"entitlement_mutation_failed_on_relay",
		"the network relay reported: "+reason, "", rollbackRef)
}

func (r *connectorRightSizeRuntime) Mutate(ctx context.Context, message orchestrator.Message, playbook projections.RemediationPlaybookRunRecorded) (RightSizeMutation, error) {
	if message.Destination != orchestrator.DestinationConnectorRightSize || playbook.Action != "right_size" {
		return RightSizeMutation{}, fmt.Errorf("connector right-size handler received an invalid intent")
	}
	binding, ok := r.bindings[rightSizeBindingKey(message.TenantID, strings.TrimSpace(playbook.Connector))]
	if !ok {
		return RightSizeMutation{}, fmt.Errorf("connector right-size binding is not configured for tenant and connector")
	}
	if strings.TrimSpace(playbook.Target) == "" {
		return RightSizeMutation{}, fmt.Errorf("connector right-size intent has no target")
	}
	token, cleanup, err := r.credential(ctx, message.TenantID, binding.TokenRef)
	if err != nil {
		return RightSizeMutation{}, fmt.Errorf("resolve connector right-size credential: %w", err)
	}
	defer cleanup()
	// The conversation itself lives in internal/rightsize so a network relay
	// runs the same bytes against the same contract (A64).
	mutation, err := rightsize.Apply(ctx, r.client, rightsize.Input{
		Endpoint: binding.Endpoint, Token: token, TenantID: message.TenantID, IdempotencyKey: message.IdempotencyKey,
		Connector: playbook.Connector, Target: strings.TrimSpace(playbook.Target), InventoryID: playbook.InventoryID,
		TargetIdentityID: playbook.TargetIdentityID, Reason: playbook.Reason, ScopeDelta: playbook.ScopeDelta,
	})
	if err != nil {
		return RightSizeMutation{}, err
	}
	return RightSizeMutation{MutationID: mutation.MutationID, RollbackRef: mutation.RollbackRef, ReadbackDigest: mutation.ReadbackDigest}, nil
}

// readRightSizeResponse keeps the package-local name the tests exercise; the
// bounded, wiping reader is the shared one.
func readRightSizeResponse(response *http.Response) ([]byte, error) {
	return rightsize.ReadResponse(response)
}

// relayRightSizeResult is the agent channel's hook for a relay's right-size
// report: a verified report completes the operation, a failure closes it.
func (s *Server) relayRightSizeResult(ctx context.Context, tenantID string, jobID int64, attempt int, payload []byte, result *relay.RightSizeReport, failure string) error {
	dispatcher, ok := s.obHandler.(*issuanceDispatcher)
	if !ok || dispatcher == nil {
		return errors.New("server: right-size receipt receiver is not the issuance dispatcher")
	}
	if result != nil {
		return dispatcher.completeRelayRightSize(ctx, tenantID, jobID, attempt, payload, *result)
	}
	return dispatcher.failRelayRightSize(ctx, tenantID, jobID, attempt, payload, failure)
}
