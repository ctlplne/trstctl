// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Static-provider rotation (A14/A15).
//
// A static rotation replaces a long-lived provider credential that an
// application secret publishes: it mints the successor at the provider, writes
// it as the next secret version, proves it works, and only then retires the
// predecessor. The HTTP request commits one durable command (an immutable
// queued event, its projected row and one outbox intent) and returns queued
// evidence; the secret-integrations outbox drives the phases through
// AdvanceStaticSecretRotation, so every provider effect happens in a bounded
// worker and a crash resumes from the persisted phase (AN-5/AN-6). The staged
// credential and the predecessor value are tenant-sealed between phases (AN-8).

const (
	staticRotationSurface                   = "static-rotation"
	staticRotationProviderUnavailableDetail = "static rotation is not configured for this provider: set allow_static_rotation on a postgresql, mysql or aws-iam dynamic-secret provider whose allowed_roles lists the secret name"
	staticRotationInFlightDetail            = "a static rotation for this secret is still in flight"
	staticRotationVersionMovedDetail        = "secret version changed before cutover; nothing was published"
	staticRotationVerifyFailedDetail        = "verification failed; predecessor restored"
	staticRotationVerifyFailedRevokeDetail  = "verification failed; predecessor restored; successor revocation pending"
	staticRotationRestoreFailedDetail       = "verification failed and the predecessor could not be restored"
	staticRotationRetryExhaustedDetail      = "external delivery exhausted its retry budget"
	staticRotationRetireExhaustedDetail     = "successor is live; predecessor retirement exhausted its retry budget"
	staticRotationUnresolvedDetail          = "the previous static rotation could not restore its predecessor; resolve that command before scheduling another"
	staticRotationTwoUserOldRefDetail       = "a two-user rotation's old_ref must name the account its consumers use now: %s or %s"
	// staticRotationVerifyAttempts is how many worker attempts a failing
	// verification gets before the command rolls back: a transient provider
	// outage should not undo a good cutover on its first flap.
	staticRotationVerifyAttempts = 3
	// staticRotationNoPredecessor lets a first rotation skip retirement when
	// the credential being replaced was never minted through trstctl.
	staticRotationNoPredecessor = "none"
)

func isStaticSecretRotation(provider string) bool {
	provider = strings.TrimSpace(provider)
	return provider != "" && !isConnectorSecretRotation(provider) && !strings.HasPrefix(provider, secretDynamicLeaseRotationPrefix)
}

// staticRotationProvider resolves a tenant's configured provider that may mint
// and verify static credentials for role. Anything else fails closed with the
// same 503 the route always used for unavailable provider modes.
func (a *API) staticRotationProvider(tenantID, providerID, role string) (dynsecret.Provider, dynsecret.StaticRotationProvider, error) {
	if a.secrets == nil {
		return nil, nil, errStatus(http.StatusServiceUnavailable, staticRotationProviderUnavailableDetail)
	}
	for _, p := range a.secrets.dynamicProviders(tenantID) {
		if p == nil || p.Name() != providerID {
			continue
		}
		sp, ok := p.(dynsecret.StaticRotationProvider)
		if !ok || !sp.AllowsStaticRotation(role) {
			return nil, nil, errStatus(http.StatusServiceUnavailable, staticRotationProviderUnavailableDetail)
		}
		return p, sp, nil
	}
	return nil, nil, errStatus(http.StatusServiceUnavailable, staticRotationProviderUnavailableDetail)
}

// staticRotationTwoUserAccounts returns role's account pair when its provider
// rotates it between two fixed accounts (A240).
func staticRotationTwoUserAccounts(provider dynsecret.Provider, role string) ([2]string, bool) {
	twoUser, ok := provider.(dynsecret.TwoUserRotationProvider)
	if !ok {
		return [2]string{}, false
	}
	return twoUser.RotationAccounts(role)
}

// checkStaticRotationPredecessor refuses a two-user rotation whose old_ref is
// not one of the role's accounts: the rotation stages the other account, so
// old_ref must name the one consumers use now, never "none" or a guess.
func checkStaticRotationPredecessor(provider dynsecret.Provider, role, oldRef string) error {
	pair, ok := staticRotationTwoUserAccounts(provider, role)
	if !ok || oldRef == pair[0] || oldRef == pair[1] {
		return nil
	}
	return errStatus(http.StatusBadRequest, fmt.Sprintf(staticRotationTwoUserOldRefDetail, pair[0], pair[1]))
}

func staticRotationAAD(tenantID, commandID, part string) []byte {
	return []byte(tenantID + "/" + staticRotationSurface + "/" + commandID + "/" + part)
}

func staticRotationEventID(cmd store.SecretStaticRotationCommand, phase string) string {
	return applicationSecretMutationEventID(cmd.TenantID, cmd.TenantEpoch, cmd.Key, "static-rotation:"+phase, cmd.ID)
}

// queueStaticSecretRotation commits the durable command for one request. The
// command id is deterministic from the tenant epoch, secret and Idempotency-Key
// digest, so a retried request finds its own command; a different request
// binding under the same key is a conflict, never a second rotation.
func (a *API) queueStaticSecretRotation(
	ctx context.Context,
	tenantID, idempotencyKey, requestBinding, scheduleID string,
	req secretRotationRequest,
) (store.SecretStaticRotationCommand, error) {
	provider, _, err := a.staticRotationProvider(tenantID, req.Provider, req.Key)
	if err != nil {
		return store.SecretStaticRotationCommand{}, err
	}
	if err := checkStaticRotationPredecessor(provider, req.Key, req.OldRef); err != nil {
		return store.SecretStaticRotationCommand{}, err
	}
	if err := validateStaticRotationRetirement(req.Consumers, req.RetireAfterSeconds); err != nil {
		return store.SecretStaticRotationCommand{}, err
	}
	if err := checkStaticRotationPhase(provider, req.Key, req.AcknowledgeSinglePhase); err != nil {
		return store.SecretStaticRotationCommand{}, err
	}
	approvedBy := ""
	if len(req.Consumers) > 0 || req.RetireAfterSeconds > 0 {
		if approvedBy, err = requestPrincipalSubject(ctx); err != nil {
			return store.SecretStaticRotationCommand{}, err
		}
	}
	epoch, err := a.applicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return store.SecretStaticRotationCommand{}, err
	}
	key := []byte(idempotencyKey)
	keyDigest := crypto.SHA256Hex(key)
	secret.Wipe(key)
	id := applicationSecretMutationEventID(tenantID, epoch, req.Key, "static-rotate", keyDigest)
	existing, err := a.store.GetSecretStaticRotationCommand(ctx, tenantID, id)
	switch {
	case err == nil:
		if !crypto.ConstantTimeEqual([]byte(existing.RequestBinding), []byte(requestBinding)) {
			return store.SecretStaticRotationCommand{}, fmt.Errorf("%w: static rotation command binding differs", store.ErrIdempotencyConflict)
		}
		return existing, nil
	case !errors.Is(err, store.ErrSecretStaticRotationCommandNotFound):
		return store.SecretStaticRotationCommand{}, err
	}
	current, err := a.secrets.be.Store.GetSecret(ctx, tenantID, req.Key)
	if err != nil {
		return store.SecretStaticRotationCommand{}, err
	}
	if latest, found, err := a.store.LatestSecretStaticRotationCommandForKey(ctx, tenantID, req.Key); err != nil {
		return store.SecretStaticRotationCommand{}, err
	} else if found && !latest.Terminal() {
		return store.SecretStaticRotationCommand{}, errStatus(http.StatusConflict, staticRotationInFlightDetail)
	}
	payload := projections.SecretStaticRotationQueued{
		ID: id, TenantEpoch: epoch, Provider: req.Provider, Key: req.Key, OldRef: req.OldRef,
		ExpectedVersion: current.Version, IdempotencyKeyDigest: keyDigest, RequestBinding: requestBinding,
		ScheduleID: scheduleID, Consumers: req.Consumers, RetireAfterSeconds: req.RetireAfterSeconds, RetireApprovedBy: approvedBy,
		SinglePhaseAcknowledged: req.AcknowledgeSinglePhase && staticRotationPhase(provider, req.Key) == dynsecret.RotationSinglePhase,
	}
	if err := a.appendAndProjectStaticRotation(ctx, tenantID, id, projections.EventSecretStaticRotationQueued, payload); err != nil {
		return store.SecretStaticRotationCommand{}, err
	}
	return a.store.GetSecretStaticRotationCommand(ctx, tenantID, id)
}

// appendAndProjectStaticRotation appends one deterministic-id event and
// projects it. A replay of the same id lands on an idempotent projection.
func (a *API) appendAndProjectStaticRotation(ctx context.Context, tenantID, eventID, eventType string, payload any) error {
	if a.log == nil || a.store == nil {
		return errors.New("api: event-sourced static rotation is unavailable")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	defer secret.Wipe(raw)
	ev := events.Event{ID: eventID, Type: eventType, TenantID: tenantID, Time: time.Now().UTC(), SchemaVersion: 1, Data: raw}
	if actor, ok := events.ActorFromContext(ctx); ok {
		ev.Actor = &actor
	}
	canonical, err := a.log.Append(ctx, ev)
	if err != nil {
		return err
	}
	return projections.New(a.store).Apply(ctx, canonical)
}

func (a *API) advanceStaticRotation(ctx context.Context, cmd store.SecretStaticRotationCommand, adv projections.SecretStaticRotationAdvanced) error {
	adv.ID = cmd.ID
	adv.TenantEpoch = cmd.TenantEpoch
	adv.FromPhase = cmd.Phase
	return a.appendAndProjectStaticRotation(ctx, cmd.TenantID, staticRotationEventID(cmd, adv.Phase), projections.EventSecretStaticRotationAdvanced, adv)
}

// AdvanceStaticSecretRotation runs every remaining phase of one command. It is
// the secret-integrations outbox's handler for the command's single outbox
// row: a nil return means the command is terminal; an error leaves it at its
// persisted phase for the outbox to retry with backoff. attempt is the outbox
// delivery attempt, used only to give a failing verification a few tries
// before the command rolls back.
func (a *API) AdvanceStaticSecretRotation(ctx context.Context, tenantID, commandID string, attempt int) error {
	if a.secrets == nil {
		return errors.New("api: secrets are disabled")
	}
	ctx = events.ContextWithActor(ctx, events.Actor{Subject: "static-rotation:" + commandID, Roles: []string{"worker"}})
	for {
		cmd, err := a.store.GetSecretStaticRotationCommand(ctx, tenantID, commandID)
		if err != nil {
			return err
		}
		if cmd.Terminal() {
			return nil
		}
		if cmd.CloudChangeID != "" && cmd.Phase != store.SecretStaticRotationVerified {
			if _, err := a.cloudReplacementStageParent(ctx, cmd); err != nil {
				if cleanupErr := a.failDynamicLeaseRotation(ctx, cmd); cleanupErr != nil {
					return cleanupErr
				}
				continue
			}
		}
		if isDynamicLeaseRotation(cmd.Provider) {
			if err := a.stepDynamicLeaseRotation(ctx, cmd, attempt); err != nil {
				return err
			}
			continue
		}
		provider, verifier, err := a.staticRotationProvider(tenantID, cmd.Provider, cmd.Key)
		if err != nil {
			return err
		}
		switch cmd.Phase {
		case store.SecretStaticRotationQueued:
			err = a.stageStaticRotation(ctx, cmd, provider)
		case store.SecretStaticRotationStaged:
			err = a.cutoverStaticRotation(ctx, cmd, provider)
		case store.SecretStaticRotationCutover:
			err = a.verifyStaticRotation(ctx, cmd, provider, verifier, attempt)
		case store.SecretStaticRotationVerified:
			err = a.retireStaticRotation(ctx, cmd, provider)
		default:
			return fmt.Errorf("api: static rotation command %s has unknown phase %q", cmd.ID, cmd.Phase)
		}
		if err != nil {
			return err
		}
	}
}

// FailStaticSecretRotation is the outbox's terminal-failure hook: the retry
// budget is spent, so the command ends in the safest truthful state for its
// phase. Nothing published yet fails outright; a published but unverified
// successor rolls back; a verified successor stays live with retirement
// pending for the operator.
func (a *API) FailStaticSecretRotation(ctx context.Context, tenantID, commandID string) error {
	if a.secrets == nil {
		return errors.New("api: secrets are disabled")
	}
	ctx = events.ContextWithActor(ctx, events.Actor{Subject: "static-rotation:" + commandID, Roles: []string{"worker"}})
	cmd, err := a.store.GetSecretStaticRotationCommand(ctx, tenantID, commandID)
	if err != nil {
		return err
	}
	if cmd.Terminal() {
		return nil
	}
	if isDynamicLeaseRotation(cmd.Provider) {
		return a.failDynamicLeaseRotation(ctx, cmd)
	}
	provider, _, providerErr := a.staticRotationProvider(tenantID, cmd.Provider, cmd.Key)
	switch cmd.Phase {
	case store.SecretStaticRotationQueued:
		return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationFailed, Error: staticRotationRetryExhaustedDetail})
	case store.SecretStaticRotationStaged:
		if providerErr == nil && cmd.NewRef != "" {
			_ = provider.Revoke(ctx, cmd.NewRef) // best effort: the successor was never published
		}
		return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationFailed, Error: staticRotationRetryExhaustedDetail})
	case store.SecretStaticRotationCutover:
		if providerErr != nil {
			return providerErr
		}
		return a.rollbackStaticRotation(ctx, cmd, provider)
	case store.SecretStaticRotationVerified:
		return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationRetirePending, Error: staticRotationRetireExhaustedDetail})
	}
	return nil
}

// stageStaticRotation mints the successor. LeaseID pins the provider-side
// identity to the command, so a retry after a crash between the provider call
// and the staged event replaces the same principal instead of leaking one. A
// two-user role stages the account its predecessor does not name instead.
func (a *API) stageStaticRotation(ctx context.Context, cmd store.SecretStaticRotationCommand, provider dynsecret.Provider) error {
	cred, err := provider.Generate(ctx, dynsecret.GenerateRequest{Role: cmd.Key, LeaseID: cmd.ID, Static: true, Predecessor: cmd.OldRef})
	if err != nil {
		return fmt.Errorf("api: static rotation stage: %w", err)
	}
	defer secret.Wipe(cred.Secret)
	if cred.BackendRef == "" || len(cred.Secret) == 0 {
		return errors.New("api: static rotation stage: provider returned no credential")
	}
	sealed, err := a.secrets.seal(ctx, cmd.TenantID, cred.Secret, staticRotationAAD(cmd.TenantID, cmd.ID, "new"))
	if err != nil {
		return err
	}
	return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{
		Phase: store.SecretStaticRotationStaged, ProviderType: cred.Metadata["provider_type"],
		NewRef: cred.BackendRef, SealedNew: sealed,
	})
}

// cutoverStaticRotation publishes the successor as the next secret version and
// keeps the predecessor value sealed for a possible rollback.
func (a *API) cutoverStaticRotation(ctx context.Context, cmd store.SecretStaticRotationCommand, provider dynsecret.Provider) error {
	value, err := a.secrets.open(ctx, cmd.TenantID, cmd.SealedNew, staticRotationAAD(cmd.TenantID, cmd.ID, "new"))
	if err != nil {
		return err
	}
	defer secret.Wipe(value)
	current, err := a.secrets.be.Store.GetSecret(ctx, cmd.TenantID, cmd.Key)
	if err != nil {
		return err
	}
	if current.Version != cmd.ExpectedVersion {
		// Someone else moved the secret: do not publish over their version.
		_ = provider.Revoke(ctx, cmd.NewRef)
		return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationFailed, Error: staticRotationVersionMovedDetail})
	}
	old, err := a.secrets.open(ctx, cmd.TenantID, current.Sealed, sealAAD(cmd.TenantID, cmd.Key))
	if err != nil {
		return err
	}
	sealedOld, err := a.secrets.seal(ctx, cmd.TenantID, old, staticRotationAAD(cmd.TenantID, cmd.ID, "old"))
	secret.Wipe(old)
	if err != nil {
		return err
	}
	resultVersion, err := a.writeStaticRotationSecretVersion(ctx, cmd, "cutover", value, cmd.ExpectedVersion)
	if err != nil {
		return err
	}
	return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{
		Phase: store.SecretStaticRotationCutover, ResultVersion: resultVersion, SealedOld: sealedOld,
	})
}

func (a *API) verifyStaticRotation(ctx context.Context, cmd store.SecretStaticRotationCommand, provider dynsecret.Provider, verifier dynsecret.StaticRotationProvider, attempt int) error {
	value, err := a.secrets.open(ctx, cmd.TenantID, cmd.SealedNew, staticRotationAAD(cmd.TenantID, cmd.ID, "new"))
	if err != nil {
		return err
	}
	mode, verifyErr := verifier.VerifyStaticCredential(ctx, cmd.NewRef, value)
	secret.Wipe(value)
	if verifyErr == nil {
		if mode == "" {
			mode = "not_available"
		}
		// A240: the approved deadline runs from verification.
		notBefore := time.Now().UTC().Add(time.Duration(cmd.RetireAfterSeconds) * time.Second)
		return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{
			Phase: store.SecretStaticRotationVerified, VerifyMode: mode, RetireNotBefore: &notBefore,
		})
	}
	if attempt < staticRotationVerifyAttempts {
		return fmt.Errorf("api: static rotation verify (attempt %d): %w", attempt, verifyErr)
	}
	return a.rollbackStaticRotation(ctx, cmd, provider)
}

// rollbackStaticRotation restores the predecessor value as a new version and
// revokes the unverified successor. The restore is the part consumers depend
// on, so it decides the terminal state; a failed successor revocation is
// recorded, not fatal.
func (a *API) rollbackStaticRotation(ctx context.Context, cmd store.SecretStaticRotationCommand, provider dynsecret.Provider) error {
	old, err := a.secrets.open(ctx, cmd.TenantID, cmd.SealedOld, staticRotationAAD(cmd.TenantID, cmd.ID, "old"))
	if err != nil {
		return err
	}
	held, err := secret.NewFrom(old)
	secret.Wipe(old)
	if err != nil {
		return err
	}
	defer held.Destroy()
	old = held.Bytes()
	intent, restoreErr := a.prepareStaticRotationSecretVersion(ctx, cmd, "rollback", old, cmd.ResultVersion)
	if restoreErr != nil {
		secret.Wipe(old)
		if errors.Is(restoreErr, store.ErrApplicationSecretMutationInFlight) || errors.Is(restoreErr, errPendingApplicationSecretApproval) {
			return restoreErr
		}
		return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationRollbackFailed, Error: staticRotationRestoreFailedDetail})
	}
	restorer, nativeRestore := provider.(dynsecret.StaticCredentialRestorer)
	nativeRestore = nativeRestore && staticRotationPhase(provider, cmd.Key) == dynsecret.RotationSinglePhase
	if nativeRestore && intent.ResultVersion == 0 {
		if err := restorer.RestoreStaticCredential(ctx, cmd.Key, cmd.OldRef, old); err != nil {
			secret.Wipe(old)
			return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationRollbackFailed, Error: staticRotationRestoreFailedDetail})
		}
	}
	restored, restoreErr := a.commitStaticRotationSecretVersion(ctx, cmd, intent)
	secret.Wipe(old)
	if restoreErr != nil {
		if nativeRestore {
			return restoreErr
		} // retry the retained native result and publication receipt

		if errors.Is(restoreErr, store.ErrApplicationSecretMutationInFlight) || errors.Is(restoreErr, errPendingApplicationSecretApproval) {
			return restoreErr // retry the restore rather than declaring it lost
		}
		return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationRollbackFailed, Error: staticRotationRestoreFailedDetail})
	}
	detail := staticRotationVerifyFailedDetail
	if err := provider.Revoke(ctx, cmd.NewRef); err != nil {
		detail = staticRotationVerifyFailedRevokeDetail
	}
	return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{
		Phase: store.SecretStaticRotationRolledBack, RestoredVersion: restored, Error: detail,
	})
}

func (a *API) retireStaticRotation(ctx context.Context, cmd store.SecretStaticRotationCommand, provider dynsecret.Provider) error {
	if err := a.holdStaticRotationRetirement(ctx, cmd); err != nil {
		return err
	}
	if cmd.OldRef != staticRotationNoPredecessor {
		if err := provider.Revoke(ctx, cmd.OldRef); err != nil {
			return fmt.Errorf("api: static rotation retire: %w", err)
		}
	}
	return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationCompleted})
}

// writeStaticRotationSecretVersion publishes value as the next version of the
// command's secret through the same fenced, event-sourced application-secret
// mutation every HTTP write uses. The step name makes the idempotency key, so a
// crash after the version committed recovers the receipt instead of writing a
// second version.
func (a *API) writeStaticRotationSecretVersion(ctx context.Context, cmd store.SecretStaticRotationCommand, step string, value []byte, expectedVersion int) (int, error) {
	intent, err := a.prepareStaticRotationSecretVersion(ctx, cmd, step, value, expectedVersion)
	if err != nil {
		return 0, err
	}
	return a.commitStaticRotationSecretVersion(ctx, cmd, intent)
}

// ---- served views ---------------------------------------------------------

type secretStaticRotationView struct {
	ID              string     `json:"id"`
	Provider        string     `json:"provider"`
	ProviderType    string     `json:"provider_type,omitempty"`
	Key             string     `json:"key"`
	OldRef          string     `json:"old_ref"`
	NewRef          string     `json:"new_ref"`
	Phase           string     `json:"phase"`
	Terminal        bool       `json:"terminal"`
	ExpectedVersion int        `json:"expected_version"`
	ResultVersion   int        `json:"result_version"`
	RestoredVersion int        `json:"restored_version"`
	VerifyMode      string     `json:"verify_mode,omitempty"`
	Error           string     `json:"error,omitempty"`
	ScheduleID      string     `json:"schedule_id,omitempty"`
	TTLSeconds      int        `json:"ttl_seconds,omitempty"`
	NewExpiresAt    *time.Time `json:"new_expires_at,omitempty"`
	// The retirement gate (A240): credential_valid is the successor's own
	// verification; consumer_adoption is the named consumers' evidence.
	Consumers          []string                      `json:"consumers,omitempty"`
	RetireAfterSeconds int                           `json:"retire_after_seconds,omitempty"`
	RetireApprovedBy   string                        `json:"retire_approved_by,omitempty"`
	RetireNotBefore    *time.Time                    `json:"retire_not_before,omitempty"`
	CredentialValid    bool                          `json:"credential_valid"`
	ConsumerAdoption   string                        `json:"consumer_adoption"`
	ConsumerStates     []staticRotationConsumerState `json:"consumer_states,omitempty"`
	// RotationPhase is the provider's phase model; a single-phase rotation
	// ran only with SinglePhaseAcknowledged (A240).
	RotationPhase           string     `json:"rotation_phase,omitempty"`
	SinglePhaseAcknowledged bool       `json:"single_phase_acknowledged,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
	TerminalAt              *time.Time `json:"terminal_at,omitempty"`
}

func toSecretStaticRotationView(cmd store.SecretStaticRotationCommand) secretStaticRotationView {
	return secretStaticRotationView{
		ID: cmd.ID, Provider: cmd.Provider, ProviderType: cmd.ProviderType, Key: cmd.Key, OldRef: cmd.OldRef, NewRef: cmd.NewRef,
		Phase: cmd.Phase, Terminal: cmd.Terminal(), ExpectedVersion: cmd.ExpectedVersion, ResultVersion: cmd.ResultVersion,
		RestoredVersion: cmd.RestoredVersion, VerifyMode: cmd.VerifyMode, Error: cmd.Error, ScheduleID: cmd.ScheduleID,
		TTLSeconds: cmd.TTLSeconds, NewExpiresAt: cmd.NewExpiresAt,
		Consumers: cmd.Consumers, RetireAfterSeconds: cmd.RetireAfterSeconds, RetireApprovedBy: cmd.RetireApprovedBy,
		RetireNotBefore: cmd.RetireNotBefore, CredentialValid: staticRotationCredentialValid(cmd),
		SinglePhaseAcknowledged: cmd.SinglePhaseAcknowledged,
		ConsumerAdoption:        consumerAdoptionNotRequested,
		CreatedAt:               cmd.CreatedAt, UpdatedAt: cmd.UpdatedAt, TerminalAt: cmd.TerminalAt,
	}
}

// toStaticSecretRotationResponse renders a command in the rotation response
// shape so the manual route, the scheduler and the console read one contract.
func toStaticSecretRotationResponse(cmd store.SecretStaticRotationCommand) secretRotationResponse {
	resp := secretRotationResponse{
		Key: cmd.Key, OldRef: cmd.OldRef, NewRef: cmd.NewRef, Queued: !cmd.Terminal(),
		Completed: cmd.Phase == store.SecretStaticRotationCompleted,
		Error:     cmd.Error, CommandID: cmd.ID, Phase: cmd.Phase,
	}
	switch cmd.Phase {
	case store.SecretStaticRotationRolledBack:
		resp.RolledBack, resp.RollbackAttempted, resp.FailedPhase = true, true, "verify"
	case store.SecretStaticRotationRollbackFailed:
		resp.RollbackAttempted, resp.RollbackFailed, resp.FailedPhase = true, true, "verify"
		resp.RollbackError = store.SecretRotationScheduleRollbackError
	case store.SecretStaticRotationFailed:
		resp.FailedPhase = "stage"
		if cmd.NewRef != "" {
			resp.FailedPhase = "cutover"
		}
	case store.SecretStaticRotationRetirePending:
		resp.FailedPhase = "retire"
	}
	return resp
}

// getStaticSecretRotation serves one command's non-secret state.
func (a *API) getStaticSecretRotation(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	cmd, err := a.store.GetSecretStaticRotationCommand(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrSecretStaticRotationCommandNotFound) {
			a.writeError(w, errStatus(http.StatusNotFound, "resource not found"))
			return
		}
		a.writeError(w, err)
		return
	}
	view, err := a.staticRotationView(r.Context(), cmd)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, view)
}

// listStaticSecretRotations pages commands newest first, optionally for one
// secret (?key=).
func (a *API) listStaticSecretRotations(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if after == store.ZeroUUID {
		after = "" // first page: the keyset starts at the newest command
	}
	rows, err := a.store.ListSecretStaticRotationCommandsPage(r.Context(), tenantID, strings.TrimSpace(r.URL.Query().Get("key")), after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]secretStaticRotationView, 0, len(rows))
	for _, row := range rows {
		view, err := a.staticRotationView(r.Context(), row)
		if err != nil {
			a.writeError(w, err)
			return
		}
		items = append(items, view)
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

// staticRotationLiveRef names the provider credential a terminal command left
// in use: a completed (or retire-pending) command's successor, or the
// predecessor a failed or rolled-back command preserved. Empty when the
// command is not terminal or its outcome does not say.
func staticRotationLiveRef(cmd store.SecretStaticRotationCommand) string {
	switch cmd.Phase {
	case store.SecretStaticRotationCompleted, store.SecretStaticRotationRetirePending:
		return cmd.NewRef
	case store.SecretStaticRotationRolledBack, store.SecretStaticRotationFailed:
		return cmd.OldRef
	}
	return ""
}

// vaultedAccountRotationKey is the static rotation idempotency key of one
// check-out (A261 part 2): its check-in and its deadline queue one command.
func vaultedAccountRotationKey(requestID string) string { return "pam-checkout:" + requestID }

// vaultedAccountPredecessor is the credential a vaulted account's next
// rotation retires: the live one the last command left, else — before any
// rotation — the account its secret signs in as now (a two-account role), or
// nothing to name when issuing the successor itself invalidates the
// predecessor (an in-place, single-phase role). A role whose rotation mints a
// new principal cannot retire a credential it did not mint, so a check-out
// of it waits for its first rotation.
func (a *API) vaultedAccountPredecessor(ctx context.Context, tenantID, providerID, key, currentAccount string) (string, error) {
	provider, _, err := a.staticRotationProvider(tenantID, providerID, key)
	if err != nil {
		return "", err
	}
	latest, found, err := a.store.LatestSecretStaticRotationCommandForKey(ctx, tenantID, key)
	switch {
	case err != nil:
		return "", err
	case found && !latest.Terminal():
		return "", errStatus(http.StatusConflict, staticRotationInFlightDetail)
	case found && latest.Phase == store.SecretStaticRotationRollbackFailed:
		return "", errStatus(http.StatusConflict, staticRotationUnresolvedDetail)
	}
	if live := staticRotationLiveRef(latest); found && live != "" {
		return live, nil
	}
	if pair, ok := staticRotationTwoUserAccounts(provider, key); ok {
		if currentAccount != pair[0] && currentAccount != pair[1] {
			return "", errStatus(http.StatusConflict, fmt.Sprintf(staticRotationTwoUserOldRefDetail, pair[0], pair[1]))
		}
		return currentAccount, nil
	}
	if staticRotationPhase(provider, key) == dynsecret.RotationSinglePhase {
		return staticRotationNoPredecessor, nil
	}
	return "", errStatus(http.StatusConflict, "this vaulted account has not been rotated yet: its first rotation must run before a check-out, so checking in can retire what was revealed")
}

// CheckVaultedAccountRotation says whether a check-out of a vaulted account
// could be retired by a rotation now.
func (a *API) CheckVaultedAccountRotation(ctx context.Context, tenantID, providerID, key, currentAccount string) error {
	if a.secrets == nil {
		return errStatus(http.StatusServiceUnavailable, staticRotationProviderUnavailableDetail)
	}
	_, err := a.vaultedAccountPredecessor(ctx, tenantID, providerID, key, currentAccount)
	return err
}

// QueueVaultedAccountRotation queues the static rotation that retires a
// check-out's revealed credential (A261 part 2), at its check-in or deadline,
// and returns the command's ID. The check-out names the command: a retry, or
// the deadline racing a check-in, finds the one command already queued.
func (a *API) QueueVaultedAccountRotation(ctx context.Context, tenantID, providerID, key, currentAccount, requestID string) (string, error) {
	if a.secrets == nil {
		return "", errStatus(http.StatusServiceUnavailable, staticRotationProviderUnavailableDetail)
	}
	idempotencyKey := vaultedAccountRotationKey(requestID)
	epoch, err := a.applicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return "", err
	}
	id := applicationSecretMutationEventID(tenantID, epoch, key, "static-rotate", crypto.SHA256Hex([]byte(idempotencyKey)))
	if existing, err := a.store.GetSecretStaticRotationCommand(ctx, tenantID, id); err == nil {
		return existing.ID, nil
	} else if !errors.Is(err, store.ErrSecretStaticRotationCommandNotFound) {
		return "", err
	}
	oldRef, err := a.vaultedAccountPredecessor(ctx, tenantID, providerID, key, currentAccount)
	if err != nil {
		return "", err
	}
	req := secretRotationRequest{Provider: providerID, Key: key, OldRef: oldRef, AcknowledgeSinglePhase: true}
	_, binding, err := a.applicationSecretRequestBinding(tenantID, idempotencyKey, "pam-checkout", "WORKER",
		"/api/v1/access/checkouts/"+requestID+"/checkin", "static-rotate", staticRotationSurface, key, req)
	if err != nil {
		return "", err
	}
	cmd, err := a.queueStaticSecretRotation(ctx, tenantID, idempotencyKey, binding, "", req)
	if err != nil {
		return "", err
	}
	a.auditSecret(ctx, "secret.rotation.queued", tenantID, key, 0)
	return cmd.ID, nil
}
