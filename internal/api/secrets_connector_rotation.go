// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/rotation"
	"trstctl.com/trstctl/internal/store"
)

const (
	secretConnectorRotationPrefix            = "connector:"
	secretDynamicLeaseRotationPrefix         = "dynamic-lease:"
	connectorRotationTargetRequiredDetail    = "connector rotation target is required"
	connectorRotationTargetUnavailableDetail = "secret sync target is not configured"
	connectorRotationOldRefInvalidDetail     = "connector rotation old_ref must be version:<n>"
	connectorRotationOldRefStaleDetail       = "connector rotation old_ref does not name the current version"
	connectorRotationDeliveryFailedDetail    = "connector delivery failed"
	dynamicLeaseRotationUnavailableDetail    = "dynamic-lease rotation is unavailable until its issue, delivery, and predecessor retirement phases share one durable worker command"
	manualStaticRotationUnavailableDetail    = "manual static-provider rotation is unavailable until a durable worker owns stage, cutover, verification, rollback, and retirement"
	scheduledStaticRotationUnavailableDetail = "scheduled static-provider rotation is unavailable until a durable worker owns stage, cutover, verification, rollback, and retirement"
)

var errTerminalConnectorRotationDelivery = errors.New("api: connector rotation delivery is terminal")

func isConnectorSecretRotation(provider string) bool {
	provider = strings.TrimSpace(provider)
	return strings.HasPrefix(provider, secretConnectorRotationPrefix) &&
		strings.TrimSpace(strings.TrimPrefix(provider, secretConnectorRotationPrefix)) != ""
}

func normalizeSecretRotationRequest(req *secretRotationRequest) error {
	req.Provider = strings.TrimSpace(req.Provider)
	req.Key = strings.TrimSpace(req.Key)
	req.OldRef = strings.TrimSpace(req.OldRef)
	req.Target = strings.TrimSpace(req.Target)
	req.RemoteKey = strings.TrimSpace(req.RemoteKey)
	if req.Provider == "" || req.Key == "" || req.OldRef == "" {
		return errStatus(http.StatusBadRequest, "provider, key, and old_ref are required")
	}
	return nil
}

// previewStaticSecretRotation describes the exact connector-backed mutation
// without generating replacement material, opening a connector, writing an
// event/outbox row, or changing the application-secret store. Unsupported
// provider modes return a blocked plan so operators can review why execution is
// unavailable without triggering the mutation route.
func (a *API) previewStaticSecretRotation(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	var req secretRotationRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if err := normalizeSecretRotationRequest(&req); err != nil {
		a.writeError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}

	canonical := struct {
		Domain     string `json:"domain"`
		TenantID   string `json:"tenant_id"`
		Provider   string `json:"provider"`
		Key        string `json:"key"`
		OldRef     string `json:"old_ref"`
		Target     string `json:"target,omitempty"`
		RemoteKey  string `json:"remote_key,omitempty"`
		TTLSeconds *int   `json:"ttl_seconds,omitempty"`
	}{
		Domain: "trstctl.api.secret-rotation-preview.f37.v1", TenantID: tenantID,
		Provider: req.Provider, Key: req.Key, OldRef: req.OldRef,
		Target: req.Target, RemoteKey: req.RemoteKey, TTLSeconds: req.TTLSeconds,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		a.writeError(w, err)
		return
	}
	fingerprint := "sha256:" + crypto.SHA256Hex(encoded)
	secret.Wipe(encoded)
	plan := secretRotationPreviewResponse{
		Capability: "F37", EffectFree: true,
		Provider: req.Provider, Key: req.Key, OldRef: req.OldRef,
		RequiredPermission: "secrets:write", RequestFingerprint: fingerprint,
		Blockers: []string{}, PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteExternalEffects: []string{},
		ExecuteWrites: []string{
			"append one immutable secret.rotated event",
			"project one sealed successor in the tenant secret store",
			"commit one sealed connector-delivery job and outbox intent in the same transaction",
		},
		RecoverySteps: []string{
			"retry the same command with the same Idempotency-Key after a transient failure",
			"inspect the durable connector delivery receipt before changing the command",
			"keep the predecessor version available for point-in-time recovery",
		},
		DataHandling: "Preview reads tenant-scoped secret metadata only; it never decrypts, generates, returns, logs, or sends secret material.",
	}
	if !isConnectorSecretRotation(req.Provider) {
		blocker := manualStaticRotationUnavailableDetail
		if strings.HasPrefix(req.Provider, secretDynamicLeaseRotationPrefix) {
			blocker = dynamicLeaseRotationUnavailableDetail
		}
		plan.Blockers = append(plan.Blockers, blocker)
		a.writeJSON(w, http.StatusOK, plan)
		return
	}
	if req.TTLSeconds != nil {
		plan.Blockers = append(plan.Blockers, "ttl_seconds is unsupported for connector rotation")
	}
	targetID, remoteKey, targetErr := connectorSecretRotationTarget(req)
	if targetErr != nil {
		plan.Blockers = append(plan.Blockers, connectorRotationTargetRequiredDetail)
	} else {
		plan.Target = targetID
		plan.RemoteKey = remoteKey
		plan.ExecuteExternalEffects = []string{"send the generated successor value to connector target " + targetID + " at remote key " + remoteKey}
		if a.secrets.syncTargets(tenantID)[targetID] == nil {
			plan.Blockers = append(plan.Blockers, connectorRotationTargetUnavailableDetail)
		}
	}
	oldVersion, versionErr := parseSecretVersionRef(req.OldRef)
	if versionErr != nil {
		plan.Blockers = append(plan.Blockers, connectorRotationOldRefInvalidDetail)
	}
	current, getErr := a.secrets.be.Store.GetSecret(r.Context(), tenantID, req.Key)
	if getErr != nil {
		if errors.Is(getErr, store.ErrSecretNotFound) {
			plan.Blockers = append(plan.Blockers, "application secret was not found")
		} else {
			a.writeError(w, getErr)
			return
		}
	} else {
		plan.CurrentVersion = current.Version
		plan.NextVersion = current.Version + 1
		if versionErr == nil && current.Version != oldVersion {
			plan.Blockers = append(plan.Blockers, connectorRotationOldRefStaleDetail)
		}
	}
	plan.Ready = len(plan.Blockers) == 0
	a.writeJSON(w, http.StatusOK, plan)
}

func unavailableDirectSecretRotationRequestBinding(principal string, req secretRotationRequest) (string, error) {
	operation := "static-secret.rotation.unavailable"
	if strings.HasPrefix(req.Provider, secretDynamicLeaseRotationPrefix) {
		// Preserve the existing binding domain for already-attempted dynamic-lease
		// commands; the static refusal joins the same shape under a disjoint domain.
		operation = "dynamic-secret.rotation"
	}
	canonical := struct {
		Operation  string `json:"operation"`
		Principal  string `json:"principal"`
		Provider   string `json:"provider"`
		Role       string `json:"role"`
		OldRef     string `json:"old_ref"`
		Target     string `json:"target"`
		RemoteKey  string `json:"remote_key"`
		TTLSeconds *int   `json:"ttl_seconds,omitempty"`
	}{
		Operation: operation, Principal: principal,
		Provider: req.Provider, Role: req.Key, OldRef: req.OldRef,
		Target: req.Target, RemoteKey: req.RemoteKey, TTLSeconds: req.TTLSeconds,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(encoded)
	return crypto.SHA256Hex(encoded), nil
}

func isTerminalConnectorRotationScheduleError(err error) bool {
	if errors.Is(err, store.ErrSecretNotFound) || errors.Is(err, errTerminalApplicationSecretApproval) ||
		errors.Is(err, errTerminalConnectorRotationDelivery) {
		return true
	}
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.detail {
	case connectorRotationTargetRequiredDetail,
		connectorRotationTargetUnavailableDetail,
		connectorRotationOldRefInvalidDetail,
		connectorRotationOldRefStaleDetail:
		return true
	default:
		return false
	}
}

func connectorSecretRotationTarget(req secretRotationRequest) (targetID, remoteKey string, err error) {
	targetID = strings.TrimSpace(req.Target)
	if strings.HasPrefix(req.Provider, secretConnectorRotationPrefix) {
		targetID = strings.TrimSpace(strings.TrimPrefix(req.Provider, secretConnectorRotationPrefix))
	}
	if targetID == "" {
		return "", "", errStatus(http.StatusBadRequest, connectorRotationTargetRequiredDetail)
	}
	remoteKey = strings.TrimSpace(req.RemoteKey)
	if remoteKey == "" {
		remoteKey = strings.TrimSpace(req.Key)
	}
	return targetID, remoteKey, nil
}

func connectorRotationSyncAAD(tenantID, target, id, key string) []byte {
	return []byte(tenantID + "/secret-sync/" + target + "/" + id + "/" + key)
}

// executeConnectorApplicationSecretRotation turns the connector path into one
// canonical application-secret command. The projector changes secret_store and
// writes the sealed delivery job/outbox in the same PostgreSQL transaction. Only
// the outbox worker contacts the connector; request handling returns the durable
// queued result and never performs a second compensating secret write.
func (a *API) executeConnectorApplicationSecretRotation(
	ctx context.Context,
	tenantID, idempotencyKey, requestBinding string,
	req secretRotationRequest,
) (rotation.Report, error) {
	targetID, remoteKey, err := connectorSecretRotationTarget(req)
	if err != nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
	}
	oldVersion, err := parseSecretVersionRef(req.OldRef)
	if err != nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
	}
	tenantEpoch, err := a.applicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
	}
	key := []byte(idempotencyKey)
	keyDigest := crypto.SHA256Hex(key)
	secret.Wipe(key)
	eventID := applicationSecretMutationEventID(tenantID, tenantEpoch, req.Key, "rotate", keyDigest)
	if receipt, ok, receiptErr := a.applicationSecretMaterializedResult(
		ctx, tenantID, eventID, requestBinding, req.Key, "rotate"); receiptErr != nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, receiptErr
	} else if ok {
		return a.connectorApplicationSecretRotationReport(ctx, tenantID, eventID,
			req.Key, req.OldRef, receipt.ResultVersion)
	}
	target := a.secrets.syncTargets(tenantID)[targetID]
	if target == nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef},
			errStatus(http.StatusServiceUnavailable, connectorRotationTargetUnavailableDetail)
	}
	fence, payload, prepared, err := a.applicationSecretMutationFence(
		ctx, tenantID, req.Key, "rotate", eventID, requestBinding)
	if err != nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
	}
	current, err := a.secrets.be.Store.GetSecret(ctx, tenantID, req.Key)
	if err != nil {
		if errors.Is(err, store.ErrSecretNotFound) {
			return rotation.Report{Key: req.Key, OldRef: req.OldRef}, store.ErrSecretNotFound
		}
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
	}
	if current.Version != oldVersion {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef},
			errStatus(http.StatusConflict, connectorRotationOldRefStaleDetail)
	}
	if !prepared {
		random, randomErr := crypto.RandomBytes(32)
		if randomErr != nil {
			return rotation.Report{Key: req.Key, OldRef: req.OldRef}, randomErr
		}
		value := make([]byte, 0, len("rotated-")+hex.EncodedLen(len(random)))
		value = append(value, "rotated-"...)
		encoded := make([]byte, hex.EncodedLen(len(random)))
		hex.Encode(encoded, random)
		value = append(value, encoded...)
		secret.Wipe(encoded)
		secret.Wipe(random)
		defer secret.Wipe(value)

		commandKeyDigest, commandEvidence, commandErr := a.applicationSecretCommandEvidence(
			tenantID, idempotencyKey, canonicalApplicationSecretCommand{
				Domain: "trstctl.api.application-secret-command.v2", TenantEpoch: tenantEpoch,
				Action: "rotate", Name: req.Key, Surface: "rotation", Provider: req.Provider,
				Target: targetID, RemoteKey: remoteKey, OldRef: req.OldRef,
				ExpectedVersion: current.Version, ResultVersion: current.Version + 1, Value: value,
			})
		if commandErr != nil {
			return rotation.Report{Key: req.Key, OldRef: req.OldRef}, commandErr
		}
		if commandKeyDigest != keyDigest {
			return rotation.Report{Key: req.Key, OldRef: req.OldRef}, errors.New("api: connector rotation idempotency digest changed")
		}
		sealed, sealErr := a.secrets.seal(ctx, tenantID, value, sealAAD(tenantID, req.Key))
		if sealErr != nil {
			return rotation.Report{Key: req.Key, OldRef: req.OldRef}, sealErr
		}
		jobID := store.DurableSecretSyncJobID(tenantID, eventID)
		syncSealed, sealErr := a.secrets.seal(ctx, tenantID, value,
			connectorRotationSyncAAD(tenantID, targetID, jobID, remoteKey))
		if sealErr != nil {
			return rotation.Report{Key: req.Key, OldRef: req.OldRef}, sealErr
		}
		payload = projections.ApplicationSecretMutation{
			TenantEpoch: tenantEpoch, Action: "rotate", Name: req.Key,
			ExpectedVersion: current.Version, ResultVersion: current.Version + 1, Sealed: sealed,
			IdempotencyKeyDigest: keyDigest, RequestBinding: requestBinding,
			CommandEvidence: commandEvidence, Surface: "rotation",
			Sync: &projections.SecretSyncQueued{
				ID: jobID, SecretName: req.Key, SecretVersion: int64(current.Version + 1),
				Target: targetID, RemoteKey: remoteKey, ValueDigest: crypto.SHA256Hex(value),
				IdempotencyKey: store.SecretSyncOutboxIdempotencyKey(targetID, jobID),
				RequestBinding: requestBinding, Sealed: syncSealed,
			},
		}
		fence, payload, err = a.claimApplicationSecretMutationFence(ctx, tenantID, req.Key,
			"rotate", eventID, projections.EventApplicationSecretRotated, requestBinding, payload)
		if err != nil {
			return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
		}
	}
	fence, payload, err = a.finalizeApplicationSecretMutationFence(ctx, tenantID, fence, payload)
	if err != nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
	}
	_, canonical, err := a.appendAndProjectApplicationSecretMutation(ctx, tenantID, fence, payload, prepared)
	if err != nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, err
	}
	if canonical.Sync == nil {
		return rotation.Report{Key: req.Key, OldRef: req.OldRef}, errors.New("api: connector rotation canonical event omitted sync intent")
	}
	// The API commits only the canonical event + projected sync intent. The bounded
	// outbox worker is the sole owner of the external connector call (AN-6).
	return a.connectorApplicationSecretRotationReport(ctx, tenantID, eventID,
		req.Key, req.OldRef, canonical.ResultVersion)
}

func (a *API) connectorApplicationSecretRotationReport(
	ctx context.Context,
	tenantID, eventID, key, oldRef string,
	resultVersion int,
) (rotation.Report, error) {
	report := rotation.Report{
		Key: key, OldRef: oldRef, NewRef: "version:" + strconv.Itoa(resultVersion),
	}
	jobID := store.DurableSecretSyncJobID(tenantID, eventID)
	job, err := a.secrets.be.Store.GetSecretSyncJob(ctx, tenantID, jobID)
	if err != nil {
		return report, fmt.Errorf("api: load connector rotation delivery job: %w", err)
	}
	switch job.Status {
	case store.SecretSyncJobPending:
		report.Queued = true
	case store.SecretSyncJobDelivered:
		report.Completed = true
	case store.SecretSyncJobFailed:
		report.FailedPhase = "delivery"
		// LastError is provider-controlled operational diagnostics. Collapse it at
		// this boundary so neither the direct mutation response nor the durable
		// scheduler receipts can accidentally serialize it.
		return report, errTerminalConnectorRotationDelivery
	default:
		return report, fmt.Errorf("api: connector rotation delivery job has invalid status %q", job.Status)
	}
	return report, nil
}

func parseSecretVersionRef(ref string) (int, error) {
	const prefix = "version:"
	if !strings.HasPrefix(ref, prefix) {
		return 0, errStatus(http.StatusBadRequest, connectorRotationOldRefInvalidDetail)
	}
	version, err := strconv.Atoi(strings.TrimPrefix(ref, prefix))
	if err != nil || version <= 0 {
		return 0, errStatus(http.StatusBadRequest, connectorRotationOldRefInvalidDetail)
	}
	return version, nil
}
