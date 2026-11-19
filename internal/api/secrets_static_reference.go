// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"

	runtimeconfig "trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/hostedkey"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const staticReferenceReviewDetail = "rotation reference requires verified public vendor metadata or vendor-admin recovery"

func staticReferenceProviderType(provider dynsecret.Provider) string {
	if kind := dynsecret.HostedReferenceProviderType(provider); kind != "" {
		return kind
	}
	return store.SecretRotationScheduleNativeReference
}

// staticRotationQueueReferenceType verifies a reference admission against the
// exact immutable source of the projected command.
func (a *API) staticRotationQueueReferenceType(ctx context.Context, cmd store.SecretStaticRotationCommand) (string, error) {
	kind, _, err := a.staticRotationQueueReferenceEvidence(ctx, cmd)
	return kind, err
}

func (a *API) staticRotationQueueReferenceEvidence(ctx context.Context, cmd store.SecretStaticRotationCommand) (string, *projections.SecretStaticRotationBoundQueued, error) {
	if a.log == nil {
		return "", nil, nil
	}
	event, found, err := a.log.EventByID(ctx, cmd.ID)
	if err != nil || !found {
		return "", nil, err
	}
	// Queue schema versions belong to their event types. Coordinated rotations
	// use the dependent parent as their canonical command source.
	switch event.Type {
	case projections.EventServiceDependentRotationQueued:
		_, err := decodeDependentRotationQueueSource(event, cmd)
		return "", nil, err
	case projections.EventSecretStaticRotationQueued:
	default:
		return "", nil, store.ErrIdempotencyConflict
	}
	var bound *projections.SecretStaticRotationBoundQueued
	var queued projections.SecretStaticRotationQueued
	var kind string
	switch event.SchemaVersion {
	case projections.SecretStaticRotationBoundQueueSchemaVersion:
		var native projections.SecretStaticRotationBoundQueued
		native, err = projections.DecodeSecretStaticRotationBoundQueueSource(event)
		bound = &native
		queued, kind = native.SecretStaticRotationQueued, store.SecretRotationScheduleNativeReference
	case projections.SecretStaticRotationReferenceQueueSchemaVersion:
		queued, kind, err = projections.DecodeSecretStaticRotationQueueSource(event)
	default:
		return "", nil, nil
	}
	if err != nil || event.TenantID != cmd.TenantID || event.ID != cmd.ID || event.Time.IsZero() || event.SensitiveErased ||
		queued.ID != cmd.ID || queued.TenantEpoch != cmd.TenantEpoch || queued.Provider != cmd.Provider || queued.Key != cmd.Key ||
		queued.OldRef != cmd.OldRef || queued.RequestBinding != cmd.RequestBinding || queued.ScheduleID != cmd.ScheduleID ||
		queued.ExpectedVersion != cmd.ExpectedVersion || queued.IdempotencyKeyDigest != cmd.IdempotencyKeyDigest {
		return "", nil, store.ErrIdempotencyConflict
	}
	return kind, bound, nil
}

func staticRotationAuthority(provider dynsecret.Provider, key string) string {
	if authority, ok := provider.(dynsecret.StaticRotationAuthority); ok {
		return authority.StaticRotationAuthority(key)
	}
	// In-process providers without an operator configuration are identified by
	// their Go type in addition to the tenant, provider ID and role on the event.
	return crypto.SHA256Hex([]byte(reflect.TypeOf(provider).String()))
}

func staticRotationReceiverRequiresBinding(provider dynsecret.Provider) bool {
	receiver, ok := provider.(dynsecret.StaticRotationReceiverAuthority)
	return ok && receiver.StaticRotationRequiresReceiverBinding()
}

func resolveStaticRotationReceiverAuthority(ctx context.Context, provider dynsecret.Provider) (string, error) {
	receiver, ok := provider.(dynsecret.StaticRotationReceiverAuthority)
	if !ok || !receiver.StaticRotationRequiresReceiverBinding() {
		return "", nil
	}
	binding, err := receiver.ResolveStaticRotationReceiverAuthority(ctx)
	if err != nil || len(binding) != 64 {
		return "", errStatus(http.StatusConflict, staticReferenceReviewDetail)
	}
	return binding, nil
}

func nativeStaticRotationMatchesSecret(bound *projections.SecretStaticRotationBoundQueued, current store.Secret) bool {
	return bound.ExpectedVersion == current.Version && bound.SecretCreatedAt.Equal(current.CreatedAt) && bound.SecretUpdatedAt.Equal(current.UpdatedAt)
}

func staticRotationReceiptMatchesSecret(receipt store.ApplicationSecretMutationReceipt, current store.Secret) bool {
	return receipt.ResultVersion == current.Version && receipt.ResultCreatedAt.Equal(current.CreatedAt) && receipt.ResultUpdatedAt.Equal(current.UpdatedAt)
}

func staticRotationRecordedNativeType(cmd store.SecretStaticRotationCommand) bool {
	_, hosted := hostedkey.Providers[cmd.ProviderType]
	return cmd.ProviderBinding != "" || !hosted && runtimeconfig.StaticRotationProviderTypes[cmd.ProviderType]
}

func staticRotationProviderKeepsReferenceAuthority(cmd store.SecretStaticRotationCommand, provider dynsecret.Provider, currentKind, queuedKind string, nativeBound bool) bool {
	if cmd.Phase == store.SecretStaticRotationQueued && cmd.ProviderBinding == "" && cmd.ProviderType == "" && !nativeBound &&
		(queuedKind == "" || queuedKind == store.SecretRotationScheduleNativeReference) {
		return false
	}
	if _, wasHosted := hostedkey.Providers[cmd.ProviderType]; wasHosted && cmd.ProviderType != currentKind {
		return false
	}
	if currentKind == store.SecretRotationScheduleNativeReference {
		if typed, ok := provider.(interface{ DynamicSecretProviderType() string }); ok && cmd.ProviderType != "" && cmd.ProviderType != typed.DynamicSecretProviderType() {
			return false
		}
		return queuedKind == currentKind || staticRotationRecordedNativeType(cmd) || !strings.Contains(cmd.OldRef, "/")
	}
	if staticRotationRecordedNativeType(cmd) {
		return false
	}
	for _, reference := range []string{cmd.OldRef, cmd.NewRef} {
		if reference != "" && reference != staticRotationNoPredecessor {
			if _, err := dynsecret.NormalizeHostedReference(provider, cmd.Key, reference); err != nil {
				return false
			}
		}
	}
	return true
}

// liveRotationReference resolves the exact command and published secret
// version that could supply the next automatic predecessor.
func (a *API) liveRotationReference(
	ctx context.Context, tenantID, provider, key string, command store.SecretStaticRotationCommand,
) (string, error) {
	if command.TenantID != tenantID || command.Provider != provider || command.Key != key {
		return "", nil
	}
	reference := staticRotationLiveRef(command)
	if reference == "" || reference == staticRotationNoPredecessor {
		return "", nil
	}
	epoch, err := a.applicationSecretTenantEpoch(ctx, tenantID)
	if err != nil || command.TenantEpoch != epoch {
		return "", err
	}
	version := command.ResultVersion
	switch command.Phase {
	case store.SecretStaticRotationFailed:
		version = command.ExpectedVersion
	case store.SecretStaticRotationRolledBack:
		version = command.RestoredVersion
	}
	current, err := a.secrets.be.Store.GetSecret(ctx, tenantID, key)
	if err != nil || version <= 0 || current.Version != version {
		return "", err
	}
	return reference, nil
}

func (a *API) liveStaticRotationPredecessor(
	ctx context.Context, tenantID, key string, provider dynsecret.Provider, command store.SecretStaticRotationCommand,
) (string, error) {
	current, err := a.secrets.be.Store.GetSecret(ctx, tenantID, key)
	if err != nil {
		return "", err
	}
	return a.liveStaticRotationPredecessorForSecret(ctx, tenantID, current, provider, command, "")
}

func (a *API) liveStaticRotationPredecessorForSecret(
	ctx context.Context, tenantID string, current store.Secret, provider dynsecret.Provider, command store.SecretStaticRotationCommand, receiverAuthority string,
) (string, error) {
	reference := staticRotationLiveRef(command)
	if command.TenantID != tenantID || command.Provider != provider.Name() || command.Key != current.Name || reference == "" || reference == staticRotationNoPredecessor {
		return "", nil
	}
	epoch, err := a.applicationSecretTenantEpoch(ctx, tenantID)
	if err != nil || command.TenantEpoch != epoch {
		return "", err
	}
	queueKind, bound, err := a.staticRotationQueueReferenceEvidence(ctx, command)
	if err != nil {
		return "", err
	}
	kind := staticReferenceProviderType(provider)
	if queueKind == "" {
		if staticRotationRecordedNativeType(command) {
			queueKind = store.SecretRotationScheduleNativeReference
		} else if _, hosted := hostedkey.Providers[command.ProviderType]; hosted {
			queueKind = command.ProviderType
		}
	}
	if queueKind != kind || !staticRotationProviderKeepsReferenceAuthority(command, provider, kind, queueKind, bound != nil) {
		return "", nil
	}
	if bound != nil && bound.ProviderAuthority != staticRotationAuthority(provider, current.Name) {
		return "", nil
	}
	if receiverAuthority != "" && (bound == nil || bound.ReceiverAuthority != receiverAuthority) {
		return "", nil
	}
	version, step := command.ResultVersion, "cutover"
	switch command.Phase {
	case store.SecretStaticRotationFailed:
		version, step = command.ExpectedVersion, ""
	case store.SecretStaticRotationRolledBack:
		version, step = command.RestoredVersion, "rollback"
	}
	if version <= 0 || current.Version != version {
		return "", nil
	}
	if kind == store.SecretRotationScheduleNativeReference {
		if step == "" {
			if bound == nil || !nativeStaticRotationMatchesSecret(bound, current) {
				return "", nil
			}
		} else {
			receipt, found, err := a.staticRotationPublicationReceipt(ctx, command, step)
			if err != nil || !found || !staticRotationReceiptMatchesSecret(receipt, current) {
				return "", err
			}
		}
	}
	predecessor := command.Phase == store.SecretStaticRotationFailed || command.Phase == store.SecretStaticRotationRolledBack
	return a.authorizeStaticRotationReference(ctx, command, provider, predecessor)
}

func (a *API) staticRotationReferenceView(ctx context.Context, cmd store.SecretStaticRotationCommand) (store.SecretStaticRotationCommand, error) {
	if store.SecretRotationScheduleHasNamespacedReference(cmd.Provider) {
		return cmd, nil
	}
	kind, err := a.staticRotationQueueReferenceType(ctx, cmd)
	if err != nil {
		return cmd, err
	}
	if kind == store.SecretRotationScheduleNativeReference || kind == "" && staticRotationRecordedNativeType(cmd) {
		return cmd, nil
	}
	view := cmd
	if kind == "" && view.OldRef != staticRotationNoPredecessor {
		view.OldRef = ""
	}
	if view.NewRef != "" {
		proven, err := a.guardedStaticStage(ctx, cmd, cmd.ProviderType, cmd.NewRef)
		if err != nil {
			return cmd, err
		}
		if !proven {
			view.NewRef = ""
		}
	}
	if cmd.ProviderType == "litellm" {
		if provider, _, err := a.staticRotationProvider(cmd.TenantID, cmd.Provider, cmd.Key); err == nil &&
			dynsecret.HostedReferenceProviderType(provider) == cmd.ProviderType {
			if view.OldRef == "" {
				view.OldRef, _ = dynsecret.NormalizeHostedReference(provider, cmd.Key, cmd.OldRef)
			}
			if view.NewRef == "" {
				view.NewRef, _ = dynsecret.NormalizeHostedReference(provider, cmd.Key, cmd.NewRef)
			}
		}
	}
	return view, nil
}

func (a *API) staticRotationCachedReferenceView(provider, key, binding string) mutationResponseView {
	return func(ctx context.Context, tenantID string, raw []byte, classified bool) ([]byte, error) {
		if classified {
			return raw, nil
		}
		var response secretRotationResponse
		if err := json.Unmarshal(raw, &response); err != nil {
			return nil, err
		}
		old, next := "", ""
		if response.OldRef == staticRotationNoPredecessor {
			old = response.OldRef
		}
		if response.CommandID != "" && response.Key == key {
			current, err := a.store.GetSecretStaticRotationCommand(ctx, tenantID, response.CommandID)
			if err != nil && !errors.Is(err, store.ErrSecretStaticRotationCommandNotFound) {
				return nil, err
			}
			if err == nil && current.Provider == provider && current.Key == key && current.RequestBinding == binding {
				view, err := a.staticRotationReferenceView(ctx, current)
				if err != nil {
					return nil, err
				}
				old = cachedRotationReference(response.OldRef, current.OldRef, view.OldRef)
				next = cachedRotationReference(response.NewRef, current.NewRef, view.NewRef)
			}
		}
		return renderCachedRotationReferences(raw, response.OldRef, old, "new_ref", response.NewRef, next)
	}
}

func (a *API) scheduleCachedReferenceView(expectedID, action, key, binding string) mutationResponseView {
	return func(ctx context.Context, tenantID string, raw []byte, classified bool) ([]byte, error) {
		if classified && action == "" {
			return raw, nil
		}
		var response secretRotationScheduleResponse
		if err := json.Unmarshal(raw, &response); err != nil {
			return nil, err
		}
		if action != "" {
			if response.ID != expectedID {
				return nil, errStatus(http.StatusConflict, "retained schedule control differs from the requested schedule")
			}
			// The authenticated receipt can outlive its schedule row. Its provider
			// still needs today's write grant if that provider is configured.
			if isStaticSecretRotation(response.Provider) {
				if err := a.requireStaticRotationProviderWrite(ctx, tenantID, response.Provider); err != nil {
					return nil, err
				}
			}
		}
		if classified || store.SecretRotationScheduleHasNamespacedReference(response.Provider) {
			return raw, nil
		}
		old, next := "", ""
		if response.OldRef == staticRotationNoPredecessor {
			old = response.OldRef
		}
		if response.ID != "" && (expectedID == "" || response.ID == expectedID) {
			if action != "" {
				retained, found, err := a.orch.ReadRetainedSecretRotationScheduleControl(ctx, tenantID, response.ID, action, key, binding)
				if err != nil {
					return nil, err
				}
				if found && retained.ReferenceViewVersion != 0 && retained.Key == response.Key && retained.Provider == response.Provider {
					old = cachedRotationReference(response.OldRef, retained.OldRef, retained.OldRef)
					next = cachedRotationReference(response.LastNewRef, retained.LastNewRef, retained.LastNewRef)
				}
			} else {
				scheduled, err := a.store.GetSecretRotationSchedule(ctx, tenantID, response.ID)
				if err != nil && !store.IsNotFound(err) {
					return nil, err
				}
				if err == nil && scheduled.Key == response.Key && scheduled.Provider == response.Provider {
					view := store.SecretRotationScheduleReferenceView(scheduled)
					old = cachedRotationReference(response.OldRef, scheduled.OldRef, view.OldRef)
					next = cachedRotationReference(response.LastNewRef, scheduled.LastNewRef, view.LastNewRef)
				}
			}
		}
		return renderCachedRotationReferences(raw, response.OldRef, old, "last_new_ref", response.LastNewRef, next)
	}
}

func cachedRotationReference(value, original, safe string) string {
	if value != "" && (value == original || value == safe) {
		return safe
	}
	return ""
}

func renderCachedRotationReferences(raw []byte, old, safeOld, nextField, next, safeNext string) ([]byte, error) {
	if old == safeOld && next == safeNext {
		return raw, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	if old != safeOld {
		fields["old_ref"], _ = json.Marshal(safeOld)
	}
	if next != safeNext {
		if nextField == "last_new_ref" && safeNext == "" {
			delete(fields, nextField)
		} else {
			fields[nextField], _ = json.Marshal(safeNext)
		}
	}
	return json.Marshal(fields)
}

func (a *API) previewStaticRotationReference(tenantID string, req secretRotationRequest) string {
	if req.OldRef == staticRotationNoPredecessor {
		return req.OldRef
	}
	provider, _, err := a.staticRotationProvider(tenantID, req.Provider, req.Key)
	if err != nil {
		return ""
	}
	switch dynsecret.HostedReferenceProviderType(provider) {
	case "":
		return req.OldRef
	case "litellm":
		reference, _ := dynsecret.NormalizeHostedReference(provider, req.Key, req.OldRef)
		return reference
	default:
		return ""
	}
}

func (a *API) admitStaticRotationPredecessor(
	ctx context.Context, tenantID, epoch string, current store.Secret,
	provider dynsecret.Provider, reference, receiverAuthority string,
) (string, error) {
	kind := dynsecret.HostedReferenceProviderType(provider)
	if kind == "" {
		if err := a.checkNativeStaticRotationPredecessor(ctx, tenantID, current.Name, provider, reference, receiverAuthority, &current); err != nil {
			return "", err
		}
		return reference, nil
	}
	if reference == staticRotationNoPredecessor {
		return reference, nil
	}
	refused := errStatus(http.StatusConflict, staticReferenceReviewDetail)
	canonical, err := dynsecret.NormalizeHostedReference(provider, current.Name, reference)
	if err != nil {
		return "", refused
	}
	if kind == "litellm" {
		return canonical, nil
	}
	latest, found, err := a.store.LatestSecretStaticRotationCommandForKey(ctx, tenantID, current.Name)
	if err != nil {
		return "", err
	}
	if found && latest.Terminal() && latest.TenantEpoch == epoch && latest.Provider == provider.Name() &&
		latest.ResultVersion == current.Version && latest.NewRef == canonical {
		if proven, err := a.guardedStaticStage(ctx, latest, kind, canonical); err != nil {
			return "", err
		} else if proven {
			return canonical, nil
		}
	}
	if kind == "openrouter" || kind == "cloudflare-r2" {
		return "", refused
	}
	opened, err := a.secrets.open(ctx, tenantID, current.Sealed, sealAAD(tenantID, current.Name))
	defer secret.Wipe(opened)
	if err != nil || dynsecret.ValidateIssuedHostedReference(provider, current.Name, canonical, opened) != nil {
		return "", refused
	}
	return canonical, nil
}

// checkNativeStaticRotationPredecessor reads only local authority. A generated
// principal is bound by a command for this secret's currently published version.
func (a *API) checkNativeStaticRotationPredecessor(ctx context.Context, tenantID, key string, provider dynsecret.Provider, reference, receiverAuthority string, current *store.Secret) error {
	if owned, err := staticRotationRolePredecessor(provider, key, reference); owned || err != nil {
		return err
	}
	prior, found, err := a.store.LatestSecretStaticRotationCommandForKey(ctx, tenantID, key)
	if err != nil {
		return err
	}
	if found && prior.Terminal() && staticRotationLiveRef(prior) == reference {
		if current == nil {
			snapshot, err := a.secrets.be.Store.GetSecret(ctx, tenantID, key)
			if err != nil {
				return err
			}
			current = &snapshot
		}
		live, err := a.liveStaticRotationPredecessorForSecret(ctx, tenantID, *current, provider, prior, receiverAuthority)
		if err == nil && live == reference {
			return nil
		}
		if err != nil && !errors.Is(err, errNativeStaticRotationPredecessorUnproved) {
			return err
		}
	}
	return errStatus(http.StatusConflict, staticRotationUnboundOldRefDetail)
}

var errNativeStaticRotationPredecessorUnproved = errors.New(staticRotationUnboundOldRefDetail)

func (a *API) guardedStaticStage(ctx context.Context, command store.SecretStaticRotationCommand, kind, reference string) (bool, error) {
	if a.log == nil {
		return false, nil
	}
	id := staticRotationEventID(command, store.SecretStaticRotationStaged)
	event, found, err := a.log.EventByID(ctx, id)
	if err != nil || !found || event.SchemaVersion != projections.SecretStaticRotationHostedStageSchemaVersion {
		return false, err
	}
	stage, err := projections.DecodeSecretStaticRotationHostedStage(event)
	if err != nil || event.ID != id || event.TenantID != command.TenantID || event.Time.IsZero() || event.SensitiveErased ||
		stage.TenantEpoch != command.TenantEpoch || stage.ID != command.ID ||
		stage.ProviderType != kind || stage.NewRef != reference {
		return false, store.ErrIdempotencyConflict
	}
	if bytes.Equal(stage.SealedNew, command.SealedNew) {
		return true, nil
	}
	// The key-domain rewrapper can change the encryption of the DEK while
	// preserving the exact authenticated payload. Prove that identity and
	// verify current custody before using the retained reference admission.
	issued, issueErr := seal.PayloadCiphertext(stage.SealedNew)
	current, currentErr := seal.PayloadCiphertext(command.SealedNew)
	if issueErr != nil || currentErr != nil || !bytes.Equal(issued, current) {
		return false, store.ErrIdempotencyConflict
	}
	opened, err := a.secrets.open(ctx, command.TenantID, command.SealedNew,
		staticRotationAAD(command.TenantID, command.ID, "new"))
	defer secret.Wipe(opened)
	return err == nil && len(opened) != 0, nil
}

func (a *API) recoverStaticRotationQueueSource(
	ctx context.Context, tenantID, epoch, id, digest, binding, scheduleID string, req secretRotationRequest,
) (store.SecretStaticRotationCommand, bool, error) {
	if a.log == nil {
		return store.SecretStaticRotationCommand{}, false, errors.New("api: static rotation source is unavailable")
	}
	event, found, err := a.log.EventByID(ctx, id)
	if err != nil || !found {
		return store.SecretStaticRotationCommand{}, found, err
	}
	source, _, err := projections.DecodeSecretStaticRotationQueueSource(event)
	var actor *events.Actor
	if expected, ok := events.ActorFromContext(ctx); ok {
		actor = &expected
	}
	if err != nil || event.ID != id || event.TenantID != tenantID || event.Time.IsZero() ||
		event.SensitiveErased || !reflect.DeepEqual(event.Actor, actor) ||
		source.ID != id || source.TenantEpoch != epoch || source.Provider != req.Provider || source.Key != req.Key ||
		source.IdempotencyKeyDigest != digest || source.RequestBinding != binding || source.ScheduleID != scheduleID {
		return store.SecretStaticRotationCommand{}, true, store.ErrIdempotencyConflict
	}
	if err := projections.New(a.store).Apply(ctx, event); err != nil {
		return store.SecretStaticRotationCommand{}, true, err
	}
	command, err := a.store.GetSecretStaticRotationCommand(ctx, tenantID, id)
	return command, true, err
}

func (a *API) recoverHostedStaticStage(ctx context.Context, command store.SecretStaticRotationCommand, kind string) (bool, error) {
	id := staticRotationEventID(command, store.SecretStaticRotationStaged)
	event, found, err := a.log.EventByID(ctx, id)
	if err != nil || !found {
		return found, err
	}
	var stage projections.SecretStaticRotationAdvanced
	var actor *events.Actor
	if expected, ok := events.ActorFromContext(ctx); ok {
		actor = &expected
	}
	if event.ID != id || event.Type != projections.EventSecretStaticRotationAdvanced ||
		event.TenantID != command.TenantID || event.Time.IsZero() || event.SensitiveErased ||
		!reflect.DeepEqual(event.Actor, actor) || json.Unmarshal(event.Data, &stage) != nil ||
		stage.ID != command.ID || stage.TenantEpoch != command.TenantEpoch ||
		stage.FromPhase != command.Phase || stage.Phase != store.SecretStaticRotationStaged ||
		stage.ProviderType != kind || stage.NewRef == "" || len(stage.SealedNew) == 0 {
		return true, store.ErrIdempotencyConflict
	}
	return true, projections.New(a.store).Apply(ctx, event)
}

func (a *API) revokeStaticRotationReference(
	ctx context.Context, command store.SecretStaticRotationCommand, provider dynsecret.Provider, predecessor bool,
) error {
	reference, err := a.authorizeStaticRotationReference(ctx, command, provider, predecessor)
	if err != nil {
		return err
	}
	if revoker, ok := provider.(dynsecret.StaticRotationCredentialRevoker); ok {
		return revoker.RevokeStaticRotationCredential(ctx, command.Key, reference)
	}
	return provider.Revoke(ctx, reference)
}

func (a *API) authorizeStaticRotationReference(
	ctx context.Context, command store.SecretStaticRotationCommand, provider dynsecret.Provider, predecessor bool,
) (string, error) {
	reference := command.NewRef
	if predecessor {
		reference = command.OldRef
	}
	kind := dynsecret.HostedReferenceProviderType(provider)
	if kind == "" {
		if _, wasHosted := hostedkey.Providers[command.ProviderType]; wasHosted {
			return "", errors.New(staticReferenceReviewDetail)
		}
		owned, err := staticRotationRolePredecessor(provider, command.Key, reference)
		if err != nil {
			return "", errNativeStaticRotationPredecessorUnproved
		}
		_, bound, err := a.staticRotationQueueReferenceEvidence(ctx, command)
		if err != nil {
			return "", err
		}
		if bound != nil && bound.ProviderAuthority != staticRotationAuthority(provider, command.Key) || predecessor && !owned && bound == nil {
			return "", errNativeStaticRotationPredecessorUnproved
		}
		return reference, nil
	}
	if command.ProviderType != "" && command.ProviderType != kind {
		return "", errors.New(staticReferenceReviewDetail)
	}
	canonical, err := dynsecret.NormalizeHostedReference(provider, command.Key, reference)
	if err != nil {
		return "", errors.New(staticReferenceReviewDetail)
	}
	if predecessor {
		queuedKind, err := a.staticRotationQueueReferenceType(ctx, command)
		if err != nil {
			return "", err
		}
		if queuedKind != "" {
			if queuedKind != kind || canonical != command.OldRef {
				return "", store.ErrIdempotencyConflict
			}
			return canonical, nil
		}
	} else if proven, err := a.guardedStaticStage(ctx, command, kind, canonical); err != nil {
		return "", err
	} else if proven {
		return canonical, nil
	}

	switch kind {
	case "litellm":
		return canonical, nil
	case "openrouter", "cloudflare-r2":
		return "", errors.New(staticReferenceReviewDetail)
	}
	sealed := command.SealedNew
	aad := staticRotationAAD(command.TenantID, command.ID, "new")
	if predecessor {
		sealed = command.SealedOld
		aad = staticRotationAAD(command.TenantID, command.ID, "old")
		if len(sealed) == 0 {
			old, err := a.secrets.be.Store.GetSecretVersion(ctx, command.TenantID, command.Key, command.ExpectedVersion)
			if err != nil {
				return "", errors.New(staticReferenceReviewDetail)
			}
			sealed, aad = old.Sealed, sealAAD(command.TenantID, command.Key)
		}
	}
	opened, err := a.secrets.open(ctx, command.TenantID, sealed, aad)
	defer secret.Wipe(opened)
	if err != nil || dynsecret.ValidateIssuedHostedReference(provider, command.Key, canonical, opened) != nil {
		return "", errors.New(staticReferenceReviewDetail)
	}
	return canonical, nil
}

func (a *API) recoverFencedRotationSchedule(
	ctx context.Context, tenantID string, schedule store.SecretRotationSchedule, leaseToken string, unstarted bool,
) (secretRotationScheduleRunResponse, *store.SecretRotationScheduleCommandLeaseRelease, error) {
	runID := orchestrator.SecretRotationScheduleRunID(tenantID, schedule.TenantRegistrationEventSequence, schedule.ID, schedule.NextRunAt)
	deferred := secretRotationScheduleDeferredError{
		reason: store.SecretRotationScheduleReferenceReviewRequired,
		cause:  errors.New(staticReferenceReviewDetail),
	}
	command, err := a.store.GetSecretRotationScheduleCommand(ctx, tenantID, schedule.ID, runID)
	if store.IsNotFound(err) {
		_, found, err := a.log.EventByID(ctx, orchestrator.SecretRotationScheduleRunEventID(runID))
		if err != nil {
			return secretRotationScheduleRunResponse{}, nil, err
		}
		if found {
			return secretRotationScheduleRunResponse{}, nil, store.ErrSecretRotationScheduleCommandConflict
		}
		return secretRotationScheduleRunResponse{}, nil, deferred
	}
	if err != nil {
		return secretRotationScheduleRunResponse{}, nil, err
	}
	if err := command.ValidateScheduleSnapshot(schedule); err != nil {
		return secretRotationScheduleRunResponse{}, nil, err
	}
	run, found, err := a.orch.ReconcileSecretRotationScheduleSnapshotRun(ctx, schedule, runID)
	if err != nil {
		return secretRotationScheduleRunResponse{}, nil, err
	}
	if found {
		view := secretRotationScheduleRunResponseFromReceipt(schedule, run, true)
		if view.Rotation.OldRef != staticRotationNoPredecessor {
			view.Rotation.OldRef = ""
		}
		view.Rotation.NewRef = ""
		return view, nil, nil
	}
	var release *store.SecretRotationScheduleCommandLeaseRelease
	if !unstarted && command.LeaseToken == leaseToken {
		release = &store.SecretRotationScheduleCommandLeaseRelease{
			ScheduleID: schedule.ID, RunID: runID, LeaseToken: leaseToken,
		}
	}
	return secretRotationScheduleRunResponse{}, release, deferred
}

func (a *API) scheduledStaticProviderMatches(tenantID string, schedule store.SecretRotationSchedule) bool {
	if !isStaticSecretRotation(schedule.Provider) || schedule.ReferenceProviderType == "" {
		return true
	}
	provider, _, err := a.staticRotationProvider(tenantID, schedule.Provider, schedule.Key)
	if err != nil {
		return schedule.ReferenceProviderType == store.SecretRotationScheduleNativeReference
	}
	kind := dynsecret.HostedReferenceProviderType(provider)
	if kind == "" {
		kind = store.SecretRotationScheduleNativeReference
	}
	return kind == schedule.ReferenceProviderType
}

func (a *API) authorizeScheduledStaticReferences(
	ctx context.Context, tenantID string, schedule store.SecretRotationSchedule, commandKey, binding, oldReference, newReference string,
	legacyNativeUnsupported bool,
) error {
	if !isStaticSecretRotation(schedule.Provider) || schedule.ReferenceProviderType == store.SecretRotationScheduleNativeReference {
		return nil
	}
	// The frozen tick admitted this plain native predecessor. An unsupported
	// terminal reuses that exact tuple and establishes no successor.
	if legacyNativeUnsupported && oldReference == schedule.OldRef && !strings.Contains(oldReference, "/") && newReference == "" {
		return nil
	}
	oldProven := oldReference == "" || oldReference == staticRotationNoPredecessor ||
		schedule.ReferenceProviderType != "" && oldReference == schedule.OldRef
	if oldProven && newReference == "" {
		return nil
	}
	refused := secretRotationScheduleDeferredError{
		reason: store.SecretRotationScheduleReferenceReviewRequired, cause: errors.New(staticReferenceReviewDetail),
	}
	provider, _, err := a.staticRotationProvider(tenantID, schedule.Provider, schedule.Key)
	if err != nil {
		return refused
	}
	epoch, err := a.applicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return err
	}
	digest := crypto.SHA256Hex([]byte(commandKey))
	id := applicationSecretMutationEventID(tenantID, epoch, schedule.Key, "static-rotate", digest)
	command, err := a.store.GetSecretStaticRotationCommand(ctx, tenantID, id)
	if errors.Is(err, store.ErrSecretStaticRotationCommandNotFound) {
		return refused
	}
	if err != nil {
		return err
	}
	if command.TenantEpoch != epoch || command.Provider != schedule.Provider || command.Key != schedule.Key ||
		command.ScheduleID != schedule.ID || command.RequestBinding != binding {
		return refused
	}
	if !oldProven {
		ref, err := a.authorizeStaticRotationReference(ctx, command, provider, true)
		if err != nil || ref != oldReference {
			return refused
		}
	}
	if newReference != "" {
		ref, err := a.authorizeStaticRotationReference(ctx, command, provider, false)
		if err != nil || ref != newReference {
			return refused
		}
	}
	return nil
}
