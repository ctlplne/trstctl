// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secrettext"
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

type connectorRightSizeRequest struct {
	SchemaVersion     int      `json:"schema_version"`
	TenantID          string   `json:"tenant_id"`
	Connector         string   `json:"connector"`
	Target            string   `json:"target"`
	InventoryID       string   `json:"inventory_id,omitempty"`
	TargetIdentityID  string   `json:"target_identity_id,omitempty"`
	RemoveScopes      []string `json:"remove_scopes"`
	RecommendedScopes []string `json:"recommended_scopes"`
	Reason            string   `json:"reason,omitempty"`
}

type connectorRightSizeResponse struct {
	Status        secretjson.StringBytes   `json:"status"`
	MutationID    secretjson.StringBytes   `json:"mutation_id"`
	RemovedScopes []secretjson.StringBytes `json:"removed_scopes"`
	RollbackRef   secretjson.StringBytes   `json:"rollback_ref"`
}

type connectorRightSizeReadback struct {
	Scopes []secretjson.StringBytes `json:"scopes"`
}

func (d *issuanceDispatcher) handleConnectorRightSize(ctx context.Context, message orchestrator.Message) error {
	if d.connectorRightSize == nil {
		return fmt.Errorf("server: connector right-size outbox destination is not configured")
	}
	var playbook projections.RemediationPlaybookRunRecorded
	if err := json.Unmarshal(message.Payload, &playbook); err != nil {
		return fmt.Errorf("server: decode connector right-size intent: %w", err)
	}
	if playbook.Action != "right_size" || strings.TrimSpace(playbook.Connector) == "" || strings.TrimSpace(playbook.Target) == "" {
		return fmt.Errorf("server: connector right-size intent is incomplete")
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

func (r *connectorRightSizeRuntime) Mutate(ctx context.Context, message orchestrator.Message, playbook projections.RemediationPlaybookRunRecorded) (RightSizeMutation, error) {
	if message.Destination != orchestrator.DestinationConnectorRightSize || playbook.Action != "right_size" {
		return RightSizeMutation{}, fmt.Errorf("connector right-size handler received an invalid intent")
	}
	binding, ok := r.bindings[rightSizeBindingKey(message.TenantID, strings.TrimSpace(playbook.Connector))]
	if !ok {
		return RightSizeMutation{}, fmt.Errorf("connector right-size binding is not configured for tenant and connector")
	}
	target := strings.TrimSpace(playbook.Target)
	if target == "" {
		return RightSizeMutation{}, fmt.Errorf("connector right-size intent has no target")
	}
	var delta connectorRightSizeScopeDelta
	if err := json.Unmarshal(playbook.ScopeDelta, &delta); err != nil {
		return RightSizeMutation{}, fmt.Errorf("decode connector right-size scope delta: %w", err)
	}
	remove, err := normalizedRightSizeScopes(delta.RemoveScopes, true)
	if err != nil {
		return RightSizeMutation{}, fmt.Errorf("connector right-size remove_scopes: %w", err)
	}
	recommended, err := normalizedRightSizeScopes(delta.RecommendedScopes, false)
	if err != nil {
		return RightSizeMutation{}, fmt.Errorf("connector right-size recommended_scopes: %w", err)
	}
	for _, scope := range recommended {
		if containsRightSizeScope(remove, scope) {
			return RightSizeMutation{}, fmt.Errorf("connector right-size scope %q cannot be both removed and recommended", scope)
		}
	}

	requestBody, err := json.Marshal(connectorRightSizeRequest{
		SchemaVersion: 1, TenantID: message.TenantID, Connector: playbook.Connector,
		Target: target, InventoryID: playbook.InventoryID, TargetIdentityID: playbook.TargetIdentityID,
		RemoveScopes: remove, RecommendedScopes: recommended, Reason: playbook.Reason,
	})
	if err != nil {
		return RightSizeMutation{}, err
	}
	endpoint := binding.Endpoint + "/v1/entitlements/" + url.PathEscape(target)
	token, cleanup, err := r.credential(ctx, message.TenantID, binding.TokenRef)
	if err != nil {
		return RightSizeMutation{}, fmt.Errorf("resolve connector right-size credential: %w", err)
	}
	defer cleanup()

	applyRequest, err := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return RightSizeMutation{}, err
	}
	setRightSizeHeaders(applyRequest, token, message)
	applyResponse, err := r.client.Do(applyRequest)
	if err != nil {
		return RightSizeMutation{}, fmt.Errorf("connector right-size mutation request: %w", err)
	}
	applyBody, err := readRightSizeResponse(applyResponse)
	if err != nil {
		return RightSizeMutation{}, err
	}
	defer secret.Wipe(applyBody)
	if rightSizeResponseContainsCredential(applyBody, token) {
		return RightSizeMutation{}, fmt.Errorf("connector right-size mutation response reflected the request credential")
	}
	var applied connectorRightSizeResponse
	defer applied.wipe()
	if err := json.Unmarshal(applyBody, &applied); err != nil {
		return RightSizeMutation{}, fmt.Errorf("connector right-size mutation returned invalid JSON")
	}
	if applied.containsCredential(token) {
		return RightSizeMutation{}, fmt.Errorf("connector right-size mutation response reflected the request credential")
	}
	mutationID := bytes.TrimSpace(applied.MutationID)
	rollbackRef := bytes.TrimSpace(applied.RollbackRef)
	if !bytes.Equal(applied.Status, []byte("applied")) || !validRightSizeReceiptRef(mutationID) || !validRightSizeReceiptRef(rollbackRef) || !equalRightSizeByteScopes(applied.RemovedScopes, remove) {
		return RightSizeMutation{}, fmt.Errorf("connector right-size mutation response did not attest the requested scope removal")
	}

	readbackRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return RightSizeMutation{}, err
	}
	setRightSizeHeaders(readbackRequest, token, message)
	readbackResponse, err := r.client.Do(readbackRequest)
	if err != nil {
		return RightSizeMutation{}, fmt.Errorf("connector right-size readback request: %w", err)
	}
	readbackBody, err := readRightSizeResponse(readbackResponse)
	if err != nil {
		return RightSizeMutation{}, err
	}
	defer secret.Wipe(readbackBody)
	if rightSizeResponseContainsCredential(readbackBody, token) {
		return RightSizeMutation{}, fmt.Errorf("connector right-size readback response reflected the request credential")
	}
	var readback connectorRightSizeReadback
	defer readback.wipe()
	if err := json.Unmarshal(readbackBody, &readback); err != nil {
		return RightSizeMutation{}, fmt.Errorf("connector right-size readback returned invalid JSON")
	}
	if readback.containsCredential(token) {
		return RightSizeMutation{}, fmt.Errorf("connector right-size readback response reflected the request credential")
	}
	if !validRightSizeByteScopes(readback.Scopes) {
		return RightSizeMutation{}, fmt.Errorf("connector right-size readback returned invalid scopes")
	}
	for _, scope := range remove {
		if containsRightSizeByteScope(readback.Scopes, scope) {
			return RightSizeMutation{}, fmt.Errorf("connector right-size readback still contains removed scope %q", scope)
		}
	}
	if len(recommended) > 0 && !equalRightSizeByteScopes(readback.Scopes, recommended) {
		return RightSizeMutation{}, fmt.Errorf("connector right-size readback does not match recommended scopes")
	}
	return RightSizeMutation{
		MutationID: string(mutationID), RollbackRef: string(rollbackRef),
		ReadbackDigest: crypto.SHA256Hex(readbackBody),
	}, nil
}

func (r *connectorRightSizeResponse) wipe() {
	secret.Wipe(r.Status)
	secret.Wipe(r.MutationID)
	for _, scope := range r.RemovedScopes {
		secret.Wipe(scope)
	}
	secret.Wipe(r.RollbackRef)
}

func (r connectorRightSizeResponse) containsCredential(token []byte) bool {
	fields := make([]secretjson.StringBytes, 0, 3+len(r.RemovedScopes))
	fields = append(fields, r.Status, r.MutationID, r.RollbackRef)
	fields = append(fields, r.RemovedScopes...)
	return rightSizeFieldsContainCredential(fields, token)
}

func (r *connectorRightSizeReadback) wipe() {
	for _, scope := range r.Scopes {
		secret.Wipe(scope)
	}
}

func (r connectorRightSizeReadback) containsCredential(token []byte) bool {
	return rightSizeFieldsContainCredential(r.Scopes, token)
}

func rightSizeResponseContainsCredential(body, token []byte) bool {
	if len(token) == 0 {
		return false
	}
	quoted := secretjson.QuoteBytes(token)
	defer secret.Wipe(quoted)
	base64Quoted := secretjson.QuoteBase64(token)
	defer secret.Wipe(base64Quoted)
	return bytes.Contains(body, token) || bytes.Contains(body, quoted[1:len(quoted)-1]) || bytes.Contains(body, base64Quoted[1:len(base64Quoted)-1])
}

func rightSizeFieldsContainCredential(fields []secretjson.StringBytes, token []byte) bool {
	if len(token) == 0 {
		return false
	}
	base64Quoted := secretjson.QuoteBase64(token)
	defer secret.Wipe(base64Quoted)
	encoded := base64Quoted[1 : len(base64Quoted)-1]
	for _, field := range fields {
		if bytes.Contains(field, token) || bytes.Contains(field, encoded) {
			return true
		}
	}
	return false
}

func validRightSizeReceiptRef(value []byte) bool {
	if len(value) == 0 || len(value) > 1024 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validRightSizeByteScopes(values []secretjson.StringBytes) bool {
	for index, value := range values {
		if len(value) == 0 || !bytes.Equal(value, bytes.TrimSpace(value)) {
			return false
		}
		for previous := 0; previous < index; previous++ {
			if bytes.Equal(value, values[previous]) {
				return false
			}
		}
	}
	return true
}

func containsRightSizeByteScope(values []secretjson.StringBytes, want string) bool {
	for _, value := range values {
		if bytes.Equal(value, []byte(want)) {
			return true
		}
	}
	return false
}

func equalRightSizeByteScopes(values []secretjson.StringBytes, wanted []string) bool {
	if len(values) != len(wanted) || !validRightSizeByteScopes(values) {
		return false
	}
	for _, want := range wanted {
		if !containsRightSizeByteScope(values, want) {
			return false
		}
	}
	return true
}

func setRightSizeHeaders(request *http.Request, token []byte, message orchestrator.Message) {
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+secrettext.String(token))
	request.Header.Set("Idempotency-Key", message.IdempotencyKey)
	request.Header.Set("X-Trstctl-Tenant", message.TenantID)
}

func readRightSizeResponse(response *http.Response) ([]byte, error) {
	if response == nil {
		return nil, fmt.Errorf("connector right-size endpoint returned no response")
	}
	defer func() { _ = response.Body.Close() }()
	body, err := secret.ReadBounded(response.Body, (1<<20)+1)
	if err != nil {
		return nil, fmt.Errorf("read connector right-size response: %w", err)
	}
	if len(body) > 1<<20 {
		secret.Wipe(body)
		return nil, fmt.Errorf("connector right-size response exceeds 1 MiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		secret.Wipe(body)
		return nil, fmt.Errorf("connector right-size endpoint returned HTTP %d", response.StatusCode)
	}
	return body, nil
}

func normalizedRightSizeScopes(values []string, required bool) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			return nil, fmt.Errorf("scope must not be empty")
		}
		if seen[scope] {
			return nil, fmt.Errorf("scope %q is duplicated", scope)
		}
		seen[scope] = true
		out = append(out, scope)
	}
	if required && len(out) == 0 {
		return nil, fmt.Errorf("at least one scope is required")
	}
	sort.Strings(out)
	return out, nil
}

func containsRightSizeScope(values []string, want string) bool {
	index := sort.SearchStrings(values, want)
	return index < len(values) && values[index] == want
}
