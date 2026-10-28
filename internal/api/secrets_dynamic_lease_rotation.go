// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Dynamic-lease rotation (A201).
//
// A dynamic-lease rotation replaces the lease an application secret publishes
// with a new lease of the requested TTL. It runs as a static-rotation command
// (A14): the request commits the queued event, its projected row and one
// outbox intent, and the secret-integrations outbox drives the phases. Each
// provider effect goes through the durable lease lifecycle instead of a
// long-lived credential: stage issues the new lease with IssueBound (the
// lease's own outbox creates it at the provider), cutover publishes its
// credential as the next secret version, verify proves the credential works,
// and retire revokes the predecessor lease with RevokeBound, completing only
// once the provider confirms the old credential is gone. Every child operation
// has an idempotency key derived from the command, so a crash between phases
// resumes the same lease operations instead of creating new ones.

const (
	dynamicLeaseRotationTypeUnavailableDetail  = "dynamic-lease rotation needs a configured postgresql, mysql or redis dynamic-secret provider whose allowed roles include the secret name"
	dynamicLeaseRotationProviderRequiredDetail = "dynamic-lease rotation names its provider as dynamic-lease:<provider>"
	dynamicLeaseRotationTTLRequiredDetail      = "ttl_seconds is required for dynamic-lease rotation and must be positive"
	dynamicLeaseRotationOldLeaseDetail         = "old_ref must be none or an active lease of this provider for the role the secret names"
	dynamicLeaseRotationRetirePendingDetail    = "predecessor lease revocation is still pending at the provider"
	dynamicLeaseRotationRetireFailedDetail     = "predecessor lease revocation failed at the provider"
	// dynamicLeaseRotationIssueWait bounds how long one worker attempt waits
	// for the lease outbox to issue the new lease; a slower issuance is found
	// again by its idempotency key on the next attempt.
	dynamicLeaseRotationIssueWait = 5 * time.Second
)

// dynamicLeaseRotationProviderTypes are the provider types whose lease
// credential the verify phase can prove.
var dynamicLeaseRotationProviderTypes = []string{"postgresql", "mysql", "redis"}

func isDynamicLeaseRotation(provider string) bool {
	return strings.HasPrefix(strings.TrimSpace(provider), secretDynamicLeaseRotationPrefix)
}

func dynamicLeaseRotationProviderName(provider string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(provider), secretDynamicLeaseRotationPrefix))
}

// dynamicLeaseRotationProvider checks that the named provider can issue a lease
// of ttlSeconds for role and prove its credential. A provider that is missing,
// of another type or not ready is the typed 503 an unavailable mode always was;
// a role or TTL the provider refuses is the lease route's own 422.
func (a *API) dynamicLeaseRotationProvider(tenantID, provider, role string, ttlSeconds int) (dynamicSecretConfiguredProvider, error) {
	name := dynamicLeaseRotationProviderName(provider)
	if a.secrets == nil || name == "" {
		return dynamicSecretConfiguredProvider{}, errStatus(http.StatusServiceUnavailable, dynamicLeaseRotationTypeUnavailableDetail)
	}
	configured, found := a.secrets.configuredDynamicSecretProvider(tenantID, name)
	if !found || !slices.Contains(dynamicLeaseRotationProviderTypes, configured.Type) {
		return dynamicSecretConfiguredProvider{}, errStatus(http.StatusServiceUnavailable, dynamicLeaseRotationTypeUnavailableDetail)
	}
	if err := validateDynamicLeaseProviderRequest(configured, dynamicLeaseIssueRequest{Provider: name, Role: role, TTLSeconds: ttlSeconds}); err != nil {
		return dynamicSecretConfiguredProvider{}, err
	}
	return configured, nil
}

// checkDynamicLeaseRotationPredecessor requires old_ref to be "none" or this
// tenant's active lease of the provider for the role.
func (a *API) checkDynamicLeaseRotationPredecessor(ctx context.Context, tenantID, providerName, role, oldRef string) error {
	if oldRef == staticRotationNoPredecessor {
		return nil
	}
	lease, err := a.store.GetDynamicSecretLease(ctx, tenantID, oldRef)
	if err != nil {
		if store.IsNotFound(err) {
			return errStatus(http.StatusConflict, dynamicLeaseRotationOldLeaseDetail)
		}
		return err
	}
	if lease.Provider != providerName || lease.Role != role || lease.State != store.DynamicSecretLeaseActive {
		return errStatus(http.StatusConflict, dynamicLeaseRotationOldLeaseDetail)
	}
	return nil
}

// rotateDynamicLeaseSecret is the dynamic-lease branch of POST
// /api/v1/secrets/rotations: it commits the durable command and returns queued
// evidence, like a static rotation.
func (a *API) rotateDynamicLeaseSecret(w http.ResponseWriter, r *http.Request, idempotencyKey string, req secretRotationRequest) {
	if dynamicLeaseRotationProviderName(req.Provider) == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, dynamicLeaseRotationProviderRequiredDetail))
		return
	}
	if req.TTLSeconds == nil || *req.TTLSeconds <= 0 {
		a.writeError(w, errStatus(http.StatusBadRequest, dynamicLeaseRotationTTLRequiredDetail))
		return
	}
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	bindingTenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	_, requestBinding, err := a.applicationSecretRequestBinding(
		bindingTenantID, idempotencyKey, principal, r.Method, r.URL.EscapedPath(),
		"dynamic-lease-rotate", staticRotationSurface, req.Key, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateBound(w, r, idempotencyKey, requestBinding, func(ctx context.Context, tenantID string) (int, any, error) {
		if tenantID != bindingTenantID {
			return 0, nil, errors.New("api: dynamic-lease rotation binding tenant changed")
		}
		cmd, err := a.queueDynamicLeaseRotation(ctx, tenantID, idempotencyKey, requestBinding, req)
		if err != nil {
			var public *apiError
			if errors.As(err, &public) && public.status == http.StatusServiceUnavailable {
				// Recorded under the request binding, as a static rotation's typed
				// refusal is: a retry replays it, a changed command is a conflict.
				return http.StatusServiceUnavailable, problem.New(http.StatusServiceUnavailable, public.detail), nil
			}
			return 0, nil, applicationSecretMutationError(err)
		}
		a.auditSecret(ctx, "secret.rotation.queued", tenantID, req.Key, 0)
		return http.StatusOK, toStaticSecretRotationResponse(cmd), nil
	})
}

// queueDynamicLeaseRotation commits the durable command. Its id is
// deterministic from the tenant epoch, secret and Idempotency-Key digest, in a
// domain of its own, so a retried request finds its command and a different
// request under the same key is a conflict.
func (a *API) queueDynamicLeaseRotation(ctx context.Context, tenantID, idempotencyKey, requestBinding string, req secretRotationRequest) (store.SecretStaticRotationCommand, error) {
	if _, err := a.dynamicLeaseRotationProvider(tenantID, req.Provider, req.Key, *req.TTLSeconds); err != nil {
		return store.SecretStaticRotationCommand{}, err
	}
	epoch, err := a.applicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return store.SecretStaticRotationCommand{}, err
	}
	key := []byte(idempotencyKey)
	keyDigest := crypto.SHA256Hex(key)
	secret.Wipe(key)
	id := applicationSecretMutationEventID(tenantID, epoch, req.Key, "dynamic-lease-rotate", keyDigest)
	existing, err := a.store.GetSecretStaticRotationCommand(ctx, tenantID, id)
	switch {
	case err == nil:
		if !crypto.ConstantTimeEqual([]byte(existing.RequestBinding), []byte(requestBinding)) {
			return store.SecretStaticRotationCommand{}, fmt.Errorf("%w: dynamic-lease rotation command binding differs", store.ErrIdempotencyConflict)
		}
		return existing, nil
	case !errors.Is(err, store.ErrSecretStaticRotationCommandNotFound):
		return store.SecretStaticRotationCommand{}, err
	}
	if err := a.checkDynamicLeaseRotationPredecessor(ctx, tenantID, dynamicLeaseRotationProviderName(req.Provider), req.Key, req.OldRef); err != nil {
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
		TTLSeconds: *req.TTLSeconds,
	}
	if err := a.appendAndProjectStaticRotation(ctx, tenantID, id, projections.EventSecretStaticRotationQueued, payload); err != nil {
		return store.SecretStaticRotationCommand{}, err
	}
	return a.store.GetSecretStaticRotationCommand(ctx, tenantID, id)
}

// dynamicLeaseRotationBinding is a child lease operation's request binding,
// derived from the command's so it is the same on every attempt.
func dynamicLeaseRotationBinding(cmd store.SecretStaticRotationCommand, step string) string {
	return crypto.SHA256Hex([]byte(cmd.RequestBinding + "\x00dynamic-lease-rotation-" + step))
}

// dynamicLeaseRotationLifecycle is the tenant's durable lease engine with the
// bound issue and revoke operations the phases use.
func (a *API) dynamicLeaseRotationLifecycle(tenantID string) (boundDynamicLeaseIssuer, boundDynamicLeaseRevoker, error) {
	engine, err := a.secrets.dynamicLeaseEngine(tenantID)
	if err != nil {
		return nil, nil, err
	}
	issuer, issues := engine.(boundDynamicLeaseIssuer)
	revoker, revokes := engine.(boundDynamicLeaseRevoker)
	if !issues || !revokes {
		return nil, nil, errStatus(http.StatusServiceUnavailable, "the durable lease lifecycle is unavailable")
	}
	return issuer, revoker, nil
}

// leaseRotationRevoker lets the shared cutover and rollback steps revoke the
// command's new lease: Revoke goes through the durable lease lifecycle, never
// straight to the provider.
type leaseRotationRevoker struct {
	cmd     store.SecretStaticRotationCommand
	revoker boundDynamicLeaseRevoker
}

func (l leaseRotationRevoker) Name() string { return dynamicLeaseRotationProviderName(l.cmd.Provider) }

func (l leaseRotationRevoker) Generate(context.Context, dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	return dynsecret.Credential{}, errors.New("api: a dynamic-lease rotation issues leases through the lease lifecycle")
}

func (l leaseRotationRevoker) Revoke(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return nil
	}
	_, err := l.revoker.RevokeBound(ctx, leaseID, "dlrot-revoke-new:"+l.cmd.ID, dynamicLeaseRotationBinding(l.cmd, "revoke-new"))
	return err
}

// stepDynamicLeaseRotation runs the command's current phase.
func (a *API) stepDynamicLeaseRotation(ctx context.Context, cmd store.SecretStaticRotationCommand, attempt int) error {
	issuer, revoker, err := a.dynamicLeaseRotationLifecycle(cmd.TenantID)
	if err != nil {
		return err
	}
	switch cmd.Phase {
	case store.SecretStaticRotationQueued:
		return a.stageDynamicLeaseRotation(ctx, cmd, issuer)
	case store.SecretStaticRotationStaged:
		return a.cutoverStaticRotation(ctx, cmd, leaseRotationRevoker{cmd: cmd, revoker: revoker})
	case store.SecretStaticRotationCutover:
		return a.verifyDynamicLeaseRotation(ctx, cmd, leaseRotationRevoker{cmd: cmd, revoker: revoker}, attempt)
	case store.SecretStaticRotationVerified:
		return a.retireDynamicLeaseRotation(ctx, cmd, revoker)
	default:
		return fmt.Errorf("api: dynamic-lease rotation command %s has unknown phase %q", cmd.ID, cmd.Phase)
	}
}

// stageDynamicLeaseRotation issues the new lease with the command's TTL. A
// worker attempt waits briefly; the lease's own outbox keeps issuing, and the
// next attempt finds the same lease by its key.
func (a *API) stageDynamicLeaseRotation(ctx context.Context, cmd store.SecretStaticRotationCommand, issuer boundDynamicLeaseIssuer) error {
	if cmd.TTLSeconds <= 0 {
		return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationFailed, Error: dynamicLeaseRotationTTLRequiredDetail})
	}
	configured, err := a.dynamicLeaseRotationProvider(cmd.TenantID, cmd.Provider, cmd.Key, cmd.TTLSeconds)
	if err != nil {
		return err
	}
	issueCtx, cancel := context.WithTimeout(ctx, dynamicLeaseRotationIssueWait)
	defer cancel()
	lease, credential, err := issuer.IssueBound(issueCtx, configured.ID, cmd.Key, time.Duration(cmd.TTLSeconds)*time.Second,
		"dlrot-issue:"+cmd.ID, dynamicLeaseRotationBinding(cmd, "issue"))
	if err != nil {
		return fmt.Errorf("api: dynamic-lease rotation issue: %w", err)
	}
	defer secret.Wipe(credential)
	if lease.ID == "" || lease.Provider != configured.ID || lease.Role != cmd.Key || len(credential) == 0 {
		return errors.New("api: dynamic-lease rotation issue returned another lease")
	}
	sealed, err := a.secrets.seal(ctx, cmd.TenantID, credential, staticRotationAAD(cmd.TenantID, cmd.ID, "new"))
	if err != nil {
		return err
	}
	expires := lease.ExpiresAt.UTC()
	return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{
		Phase: store.SecretStaticRotationStaged, ProviderType: configured.Type,
		NewRef: lease.ID, SealedNew: sealed, NewExpiresAt: &expires,
	})
}

// verifyDynamicLeaseRotation proves the published lease credential works; a
// proof that still fails on the last attempt rolls the secret back and
// revokes the new lease.
func (a *API) verifyDynamicLeaseRotation(ctx context.Context, cmd store.SecretStaticRotationCommand, revoker leaseRotationRevoker, attempt int) error {
	verifier, err := a.dynamicLeaseRotationVerifier(cmd)
	if err != nil {
		return err
	}
	value, err := a.secrets.open(ctx, cmd.TenantID, cmd.SealedNew, staticRotationAAD(cmd.TenantID, cmd.ID, "new"))
	if err != nil {
		return err
	}
	mode, verifyErr := verifier.VerifyLeaseCredential(ctx, value)
	secret.Wipe(value)
	if verifyErr == nil {
		if mode == "" {
			mode = "not_available"
		}
		return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationVerified, VerifyMode: mode})
	}
	if attempt < staticRotationVerifyAttempts {
		return fmt.Errorf("api: dynamic-lease rotation verify (attempt %d): %w", attempt, verifyErr)
	}
	return a.rollbackStaticRotation(ctx, cmd, revoker)
}

func (a *API) dynamicLeaseRotationVerifier(cmd store.SecretStaticRotationCommand) (dynsecret.LeaseCredentialVerifier, error) {
	name := dynamicLeaseRotationProviderName(cmd.Provider)
	for _, p := range a.secrets.dynamicProviders(cmd.TenantID) {
		if p == nil || p.Name() != name {
			continue
		}
		if verifier, ok := p.(dynsecret.LeaseCredentialVerifier); ok {
			return verifier, nil
		}
	}
	return nil, errStatus(http.StatusServiceUnavailable, dynamicLeaseRotationTypeUnavailableDetail)
}

// retireDynamicLeaseRotation revokes the predecessor lease and completes once
// the provider confirms the credential is gone. A pending provider revocation
// is retried by the outbox; one that never completes ends as retire_pending
// with the new lease live.
func (a *API) retireDynamicLeaseRotation(ctx context.Context, cmd store.SecretStaticRotationCommand, revoker boundDynamicLeaseRevoker) error {
	if cmd.OldRef != staticRotationNoPredecessor {
		if _, err := revoker.RevokeBound(ctx, cmd.OldRef, "dlrot-retire:"+cmd.ID, dynamicLeaseRotationBinding(cmd, "retire")); err != nil {
			return fmt.Errorf("api: dynamic-lease rotation retire: %w", err)
		}
		old, err := a.store.GetDynamicSecretLease(ctx, cmd.TenantID, cmd.OldRef)
		if err != nil {
			return err
		}
		switch old.RevocationStatus {
		case store.DynamicSecretRevocationCompleted:
		case store.DynamicSecretRevocationFailed:
			return errors.New("api: dynamic-lease rotation retire: " + dynamicLeaseRotationRetireFailedDetail)
		default:
			return errors.New("api: dynamic-lease rotation retire: " + dynamicLeaseRotationRetirePendingDetail)
		}
	}
	return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationCompleted})
}

// failDynamicLeaseRotation is the outbox's terminal-failure hook for a
// dynamic-lease command, with the static command's outcomes: nothing published
// fails outright (revoking an issued but unpublished lease), a published but
// unverified lease rolls back, and a verified one stays live with the
// predecessor's retirement pending.
func (a *API) failDynamicLeaseRotation(ctx context.Context, cmd store.SecretStaticRotationCommand) error {
	switch cmd.Phase {
	case store.SecretStaticRotationQueued:
		return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationFailed, Error: staticRotationRetryExhaustedDetail})
	case store.SecretStaticRotationStaged:
		if _, revoker, err := a.dynamicLeaseRotationLifecycle(cmd.TenantID); err == nil {
			_ = leaseRotationRevoker{cmd: cmd, revoker: revoker}.Revoke(ctx, cmd.NewRef) // best effort: never published
		}
		return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationFailed, Error: staticRotationRetryExhaustedDetail})
	case store.SecretStaticRotationCutover:
		_, revoker, err := a.dynamicLeaseRotationLifecycle(cmd.TenantID)
		if err != nil {
			return err
		}
		return a.rollbackStaticRotation(ctx, cmd, leaseRotationRevoker{cmd: cmd, revoker: revoker})
	case store.SecretStaticRotationVerified:
		return a.advanceStaticRotation(ctx, cmd, projections.SecretStaticRotationAdvanced{Phase: store.SecretStaticRotationRetirePending, Error: staticRotationRetireExhaustedDetail})
	}
	return nil
}

// previewDynamicLeaseRotation completes the effect-free rotation plan for a
// dynamic-lease command: the phases the worker will run and every blocker the
// request route would refuse with. It contacts no provider and writes nothing.
func (a *API) previewDynamicLeaseRotation(w http.ResponseWriter, r *http.Request, tenantID string, req secretRotationRequest, plan secretRotationPreviewResponse) {
	name := dynamicLeaseRotationProviderName(req.Provider)
	ttl := 0
	if req.TTLSeconds != nil {
		ttl = *req.TTLSeconds
	}
	plan.ExecuteWrites = []string{
		"append one immutable secret.static_rotation.queued event carrying ttl_seconds, and its single outbox intent",
		"project each worker phase (staged, cutover, verified, completed) as an immutable secret.static_rotation.advanced event with the new lease's credential sealed under the tenant key domain",
		"open the new lease and revoke the predecessor through the durable lease lifecycle (dynamic-secret lease events and their outbox)",
		"append one secret.rotated event for the next secret version at cutover (and one more at rollback)",
	}
	plan.ExecuteExternalEffects = []string{
		fmt.Sprintf("issue a lease for role %s at provider %s that expires %d seconds after issue", req.Key, name, ttl),
		"verify the new lease's credential at provider " + name + " before retiring anything",
		"revoke predecessor lease " + req.OldRef + " at provider " + name + " after verification",
	}
	plan.RecoverySteps = []string{
		"retry the same command with the same Idempotency-Key after a transient failure",
		"follow GET /api/v1/secrets/rotations/{command_id} to the terminal phase",
		"a failed verification restores the predecessor as a new version and revokes the new lease",
	}
	block := func(err error) bool {
		var public *apiError
		if errors.As(err, &public) {
			plan.Blockers = append(plan.Blockers, public.detail)
			return true
		}
		a.writeError(w, err)
		return false
	}
	switch {
	case name == "":
		plan.Blockers = append(plan.Blockers, dynamicLeaseRotationProviderRequiredDetail)
	case ttl <= 0:
		plan.Blockers = append(plan.Blockers, dynamicLeaseRotationTTLRequiredDetail)
	default:
		if _, err := a.dynamicLeaseRotationProvider(tenantID, req.Provider, req.Key, ttl); err != nil && !block(err) {
			return
		}
	}
	if err := a.checkDynamicLeaseRotationPredecessor(r.Context(), tenantID, name, req.Key, req.OldRef); err != nil && !block(err) {
		return
	}
	current, getErr := a.secrets.be.Store.GetSecret(r.Context(), tenantID, req.Key)
	switch {
	case errors.Is(getErr, store.ErrSecretNotFound):
		plan.Blockers = append(plan.Blockers, "application secret was not found")
	case getErr != nil:
		a.writeError(w, getErr)
		return
	default:
		plan.CurrentVersion = current.Version
		plan.NextVersion = current.Version + 1
	}
	if latest, found, err := a.store.LatestSecretStaticRotationCommandForKey(r.Context(), tenantID, req.Key); err != nil {
		a.writeError(w, err)
		return
	} else if found && !latest.Terminal() {
		plan.Blockers = append(plan.Blockers, staticRotationInFlightDetail)
	}
	plan.Ready = len(plan.Blockers) == 0
	a.writeJSON(w, http.StatusOK, plan)
}
