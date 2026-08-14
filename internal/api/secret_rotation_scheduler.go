// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/rotation"
	"trstctl.com/trstctl/internal/rotationcommand"
	"trstctl.com/trstctl/internal/store"
)

// runDueSecretRotationSchedules is the served connector scheduler tick for
// CAP-SECR-06. Each exact due edge first acquires a durable command receiver;
// only then may the event-sourced application-secret/outbox command run.
//
//trstctl:mutation
func (a *API) runDueSecretRotationSchedules(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	escapedPath := ""
	if r.URL != nil {
		escapedPath = r.URL.EscapedPath()
	}
	routeBinding, err := mutationRouteBinding(principal, r.Method, escapedPath)
	if err != nil {
		a.writeError(w, err)
		return
	}
	var registration orchestrator.TenantRegistrationAuthority
	err = a.store.WithPrivacyRecoveryBarrier(
		r.Context(), tenantID, "secret rotation scheduler registration authority",
		func(barrierCtx context.Context) error {
			var resolveErr error
			registration, resolveErr = orchestrator.ResolveLiveTenantRegistrationAuthority(
				barrierCtx, a.secrets.be.EventLog, a.store, tenantID)
			return resolveErr
		})
	if err != nil {
		a.writeError(w, err)
		return
	}
	outerKey, requestBinding, err := secretRotationScheduleTickAuthority(
		tenantID, registration, idempotencyKey, routeBinding)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	const (
		runLimit          = 50
		scanLimit         = 500
		commandGCLimit    = 50
		tickLeaseDuration = 2 * time.Minute
	)
	ownerToken := events.NewID()
	recoveryCommandLeaseToken := events.NewID()
	var (
		tick       store.SecretRotationScheduleTick
		claimState store.SecretRotationScheduleTickClaimState
	)
	a.mutatePreparedDurableBound(
		w, r, outerKey, requestBinding,
		func(ctx context.Context, preparedTenantID string, tx pgx.Tx) (orchestrator.PreparedDurableEffectClaim, error) {
			if preparedTenantID != tenantID {
				return orchestrator.PreparedDurableEffectClaim{}, errors.New("api: scheduler tenant changed after registration resolution")
			}
			prepared, err := a.store.PrepareSecretRotationScheduleTickTx(
				ctx, tx, tenantID, outerKey, requestBinding,
				registration.EventID, registration.EventSequence, ownerToken,
				recoveryCommandLeaseToken, tickLeaseDuration)
			if err != nil {
				return orchestrator.PreparedDurableEffectClaim{}, err
			}
			tick = prepared.Tick
			claimState = prepared.State
			switch claimState {
			case store.SecretRotationScheduleTickSameKeyBusy:
				return orchestrator.PreparedDurableEffectClaim{}, errors.Join(
					errStatus(http.StatusServiceUnavailable, "this scheduler tick is already running; retry the same Idempotency-Key"),
					store.ErrSecretRotationScheduleTickInProgress,
					orchestrator.ErrInProgress,
				)
			case store.SecretRotationScheduleTickDifferentBusy:
				return orchestrator.PreparedDurableEffectClaim{}, errors.Join(
					errStatus(http.StatusServiceUnavailable, "another scheduler tick owns this tenant; retry after its bounded lease"),
					store.ErrSecretRotationScheduleTickInProgress,
				)
			case store.SecretRotationScheduleTickAcquired, store.SecretRotationScheduleTickTerminal:
			default:
				return orchestrator.PreparedDurableEffectClaim{}, fmt.Errorf(
					"%w: unknown scheduler tick claim state %q", store.ErrSecretRotationScheduleTickConflict, claimState)
			}
			return orchestrator.PreparedDurableEffectClaim{
				Completed: prepared.OuterCompleted, ResultCodec: prepared.ResultCodec,
				CompletedResult: prepared.ProtectedResult,
			}, nil
		},
		func(ctx context.Context, verifiedTenantID string, tx pgx.Tx, plaintext []byte) error {
			if verifiedTenantID != tenantID {
				return errors.New("api: scheduler tenant changed before terminal verification")
			}
			var cached cachedResponse
			if len(plaintext) == 0 || json.Unmarshal(plaintext, &cached) != nil ||
				!crypto.ConstantTimeEqual([]byte(cached.Binding), []byte(requestBinding)) {
				return fmt.Errorf("%w: outer scheduler result is not the exact bound response", store.ErrSecretRotationScheduleTickConflict)
			}
			return a.store.VerifySecretRotationScheduleTickTerminalTx(
				ctx, tx, tenantID, outerKey, requestBinding,
				registration.EventID, registration.EventSequence, cached.Status, cached.Body)
		},
		func(ctx context.Context, tenantID string) (int, any, error) {
			switch claimState {
			case store.SecretRotationScheduleTickTerminal:
				if tick.TerminalHTTPStatus == nil || len(tick.TerminalBody) == 0 || !json.Valid(tick.TerminalBody) {
					return 0, nil, fmt.Errorf("%w: terminal scheduler tick lacks canonical HTTP bytes", store.ErrSecretRotationScheduleTickConflict)
				}
				return *tick.TerminalHTTPStatus, json.RawMessage(append([]byte(nil), tick.TerminalBody...)), nil
			case store.SecretRotationScheduleTickAcquired:
			default:
				return 0, nil, fmt.Errorf("%w: unknown scheduler tick claim state %q", store.ErrSecretRotationScheduleTickConflict, claimState)
			}

			var resp secretRotationDueRunResponse
			if len(tick.Receipt) == 0 || json.Unmarshal(tick.Receipt, &resp) != nil ||
				resp.Runs == nil || resp.Deferred == nil || resp.Ran != tick.Ran || resp.Scanned != tick.Scanned {
				return 0, nil, fmt.Errorf("%w: retained scheduler progress is not a complete receipt", store.ErrSecretRotationScheduleTickConflict)
			}
			finalize := func(status int, commandRelease *store.SecretRotationScheduleCommandLeaseRelease) (int, any, error) {
				body, err := json.Marshal(resp)
				if err != nil {
					return 0, nil, err
				}
				terminal, err := a.store.FinalizeSecretRotationScheduleTick(
					ctx, tick, ownerToken, tick.OwnerGeneration, status, body, commandRelease)
				if err != nil {
					return 0, nil, err
				}
				if terminal.TerminalHTTPStatus == nil || *terminal.TerminalHTTPStatus != status ||
					len(terminal.TerminalBody) == 0 || !json.Valid(terminal.TerminalBody) {
					return 0, nil, fmt.Errorf("%w: finalized scheduler tick lacks exact terminal bytes", store.ErrSecretRotationScheduleTickConflict)
				}
				return status, json.RawMessage(append([]byte(nil), terminal.TerminalBody...)), nil
			}
			fail := func(scheduleID string, cause error, commandRelease *store.SecretRotationScheduleCommandLeaseRelease) (int, any, error) {
				markSecretRotationScheduleDueRunFailed(
					&resp, scheduleID, secretRotationScheduleSystemErrorDetail(cause))
				status, body, err := finalize(http.StatusServiceUnavailable, commandRelease)
				if err != nil {
					return 0, nil, errors.Join(cause, err)
				}
				return status, body, nil
			}

			for tick.Ran < runLimit && tick.Scanned < tick.SnapshotCount && tick.Scanned < scanLimit {
				var sched store.SecretRotationSchedule
				commandLeaseToken := ""
				if tick.CurrentSchedule != nil {
					sched = *tick.CurrentSchedule
					if tick.CurrentCommandLeaseToken == "" {
						return 0, nil, fmt.Errorf("%w: retained row snapshot is incomplete", store.ErrSecretRotationScheduleTickConflict)
					}
					commandLeaseToken = tick.CurrentCommandLeaseToken
				} else {
					var err error
					sched, err = a.store.GetSecretRotationScheduleTickRow(
						ctx, tenantID, tick.IdempotencyKey, tick.Scanned+1)
					if err != nil {
						return fail("", err, nil)
					}
					commandLeaseToken = events.NewID()
					tick, err = a.store.StartSecretRotationScheduleTickRow(
						ctx, tick, ownerToken, tick.OwnerGeneration, sched,
						commandLeaseToken, tickLeaseDuration)
					if err != nil {
						return 0, nil, err
					}
				}

				var (
					run            secretRotationScheduleRunResponse
					commandRelease *store.SecretRotationScheduleCommandLeaseRelease
					outcome        store.SecretRotationScheduleTickRowOutcome
					runErr         error
				)
				if sched.ConfigEventSequence == 0 {
					// Migration 0155 cannot invent the event sequence that created an
					// already-projected schedule. Consume and diagnose that immutable
					// snapshot row, but never claim a child command or call a provider.
					runErr = secretRotationScheduleDeferredError{
						reason: "config_revision_unanchored",
						cause:  errors.New("schedule configuration has no event revision; re-save the schedule before it can run"),
					}
				} else {
					run, commandRelease, runErr = a.runSecretRotationSchedule(
						ctx, tenantID, tick.IdempotencyKey, tick.Scanned+1, sched, commandLeaseToken)
				}
				if errors.Is(runErr, store.ErrSecretRotationScheduleDueEdgeStale) {
					// A retained terminal event already owns this exact frozen due edge.
				} else if reason, detail, deferred := secretRotationScheduleDeferredReason(runErr); deferred {
					deferredReceipt := secretRotationScheduleDeferredResponse{
						ScheduleID: sched.ID, Reason: reason, DueAt: sched.NextRunAt, Error: detail,
					}
					resp.Deferred = append(resp.Deferred, deferredReceipt)
					outcome.Deferred, err = json.Marshal(deferredReceipt)
					if err != nil {
						return 0, nil, err
					}
				} else if runErr != nil {
					// The typed 503 is terminal for this outer key, not for the
					// row_started child. Cursor position and logical budgets stay put;
					// a new-key tick carries and reconciles this deterministic child.
					return fail(sched.ID, runErr, commandRelease)
				} else {
					resp.Runs = append(resp.Runs, run)
					resp.Ran++
					outcome.Run, err = json.Marshal(run)
					if err != nil {
						return 0, nil, err
					}
				}
				resp.Scanned++
				tick, err = a.store.CompleteSecretRotationScheduleTickRowOutcome(
					ctx, tick, ownerToken, tick.OwnerGeneration, outcome,
					commandRelease, tickLeaseDuration)
				if err != nil {
					return 0, nil, err
				}
				if tick.Ran != resp.Ran || tick.Scanned != resp.Scanned {
					return 0, nil, fmt.Errorf("%w: incremental scheduler budgets diverged",
						store.ErrSecretRotationScheduleTickConflict)
				}
			}
			exhausted := tick.Scanned == tick.SnapshotCount
			// Exact-bound completion stays conservative: consuming all 50 runs or
			// 500 scans says another tick may be needed even if the last page was
			// short. Only an under-budget empty/short ring proves completion.
			resp.RunLimitReached = tick.Ran == runLimit
			resp.ScanLimitReached = tick.Scanned == scanLimit
			resp.Complete = exhausted && !resp.RunLimitReached && !resp.ScanLimitReached
			resp.Partial = false
			resp.FailedScheduleID = ""
			resp.SystemError = ""
			if _, err := a.orch.PurgeSecretRotationScheduleCommands(ctx, tenantID, commandGCLimit); err != nil {
				return fail("", err, nil)
			}
			return finalize(http.StatusOK, nil)
		})
}

func markSecretRotationScheduleDueRunFailed(
	resp *secretRotationDueRunResponse,
	scheduleID, systemError string,
) {
	resp.Complete = false
	resp.Partial = len(resp.Runs) > 0 || len(resp.Deferred) > 0
	resp.RunLimitReached = false
	resp.ScanLimitReached = false
	resp.FailedScheduleID = scheduleID
	resp.SystemError = systemError
}

type secretRotationScheduleDeferredError struct {
	reason string
	cause  error
}

func secretRotationScheduleTickAuthority(
	tenantID string,
	registration orchestrator.TenantRegistrationAuthority,
	rawIdempotencyKey, routeBinding string,
) (string, string, error) {
	if tenantID == "" || registration.EventID == "" || registration.EventSequence == 0 ||
		rawIdempotencyKey == "" || routeBinding == "" {
		return "", "", errors.New("scheduler tick requires a live registration, Idempotency-Key, and route binding")
	}
	rawKey := []byte(rawIdempotencyKey)
	rawKeyDigest := crypto.SHA256Hex(rawKey)
	secret.Wipe(rawKey)
	keyMaterial, err := json.Marshal(struct {
		Domain             string `json:"domain"`
		TenantID           string `json:"tenant_id"`
		RegistrationSeq    uint64 `json:"tenant_registration_event_sequence"`
		IdempotencyKeyHash string `json:"idempotency_key_sha256"`
	}{
		Domain: "trstctl.secret-rotation-schedule.tick-key.v3", TenantID: tenantID,
		RegistrationSeq:    registration.EventSequence,
		IdempotencyKeyHash: rawKeyDigest,
	})
	if err != nil {
		return "", "", err
	}
	defer secret.Wipe(keyMaterial)
	outerKey := rotationcommand.OuterKeyV3Prefix + crypto.SHA256Hex(keyMaterial)
	bindingMaterial, err := json.Marshal(struct {
		Domain          string `json:"domain"`
		TenantID        string `json:"tenant_id"`
		RegistrationSeq uint64 `json:"tenant_registration_event_sequence"`
		OuterKey        string `json:"outer_key"`
		RouteBinding    string `json:"route_binding"`
	}{
		Domain: "trstctl.secret-rotation-schedule.tick-binding.v3", TenantID: tenantID,
		RegistrationSeq: registration.EventSequence,
		OuterKey:        outerKey, RouteBinding: routeBinding,
	})
	if err != nil {
		return "", "", err
	}
	defer secret.Wipe(bindingMaterial)
	return outerKey, crypto.SHA256Hex(bindingMaterial), nil
}

func (e secretRotationScheduleDeferredError) Error() string {
	return secretRotationScheduleDeferredDetail(e.reason)
}
func (e secretRotationScheduleDeferredError) Unwrap() error { return e.cause }

func secretRotationScheduleDeferredReason(err error) (string, string, bool) {
	var deferred secretRotationScheduleDeferredError
	if !errors.As(err, &deferred) {
		return "", "", false
	}
	return deferred.reason, deferred.Error(), true
}

// secretRotationScheduleDeferredDetail returns only closed, bounded product
// language. The wrapped cause is kept for control flow and server logging, but
// provider/store text must never become a durable scheduler receipt.
func secretRotationScheduleDeferredDetail(reason string) string {
	return store.SecretRotationScheduleDeferredError(reason)
}

// secretRotationScheduleSystemErrorDetail deliberately does not render err.
// SQL constraint errors, custody backends, and wrapped connector failures can
// contain human-entered references or provider-controlled text. The receipt has
// stable schedule/run IDs for correlation; detailed causes stay in server logs.
func secretRotationScheduleSystemErrorDetail(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return store.SecretRotationScheduleTickInterruptedError
	}
	return store.SecretRotationScheduleTickProcessingError
}

// secretRotationScheduleTerminalErrorDetail admits only exact API details whose
// spelling is defined in this package. In particular, the connector worker's
// LastError is provider-controlled and is collapsed to a fixed delivery class.
func secretRotationScheduleTerminalErrorDetail(err error) string {
	if errors.Is(err, errTerminalConnectorRotationDelivery) {
		return connectorRotationDeliveryFailedDetail
	}
	if errors.Is(err, errTerminalApplicationSecretApproval) {
		return "application-secret approval is no longer usable"
	}
	var public *apiError
	if errors.As(err, &public) {
		switch public.detail {
		case "no such secret",
			"resource not found",
			"approval requester cannot approve their own request",
			"approval request expired",
			"approval request superseded",
			"approval authority already consumed",
			"approval target version or state drifted",
			"approval request has not reached quorum",
			connectorRotationDeliveryFailedDetail,
			connectorRotationTargetRequiredDetail,
			connectorRotationTargetUnavailableDetail,
			connectorRotationOldRefInvalidDetail,
			connectorRotationOldRefStaleDetail:
			return public.detail
		}
	}
	return "scheduled rotation failed"
}

// secretRotationScheduleContext replaces only the inner command identity. The
// HTTP middleware has already authenticated and authorized the run-due caller;
// the persisted enabled schedule is the non-human authority that must stay stable
// when another authorized runner takes over or the process restarts.
func secretRotationScheduleContext(ctx context.Context, tenantID string, sched store.SecretRotationSchedule) context.Context {
	authority := "secret-rotation-schedule:" + sched.ID
	ctx = context.WithValue(ctx, principalCtxKey, authz.Principal{TenantID: tenantID, Subject: authority})
	return events.ContextWithActor(ctx, events.Actor{Subject: authority})
}

func (a *API) runSecretRotationSchedule(
	ctx context.Context,
	tenantID string,
	tickIdempotencyKey string,
	tickOrdinal int,
	sched store.SecretRotationSchedule,
	leaseToken string,
) (secretRotationScheduleRunResponse, *store.SecretRotationScheduleCommandLeaseRelease, error) {
	if tickIdempotencyKey == "" || tickOrdinal <= 0 || leaseToken == "" {
		return secretRotationScheduleRunResponse{}, nil, fmt.Errorf("%w: scheduler child lease token is required", store.ErrSecretRotationScheduleCommandConflict)
	}
	ctx = secretRotationScheduleContext(ctx, tenantID, sched)
	runID := orchestrator.SecretRotationScheduleRunID(
		tenantID, sched.TenantRegistrationEventSequence, sched.ID, sched.NextRunAt)
	commandKey := orchestrator.SecretRotationScheduleCommandKey(runID)
	terminalEventID := orchestrator.SecretRotationScheduleRunEventID(runID)
	principal := "secret-rotation-schedule:" + sched.ID
	request := secretRotationRequest{Provider: sched.Provider, Key: sched.Key, OldRef: sched.OldRef}
	requestBinding, err := a.secretRotationScheduleRequestBinding(
		tenantID, principal, sched, commandKey, request)
	if err != nil {
		return secretRotationScheduleRunResponse{}, nil, err
	}
	command := store.SecretRotationScheduleCommand{
		TenantID: tenantID, IdentityVersion: sched.IdentityVersion,
		TenantRegistrationEventID:       sched.TenantRegistrationEventID,
		TenantRegistrationEventSequence: sched.TenantRegistrationEventSequence,
		ScheduleID:                      sched.ID, RunID: runID, DueAt: sched.NextRunAt,
		Provider: sched.Provider, Key: sched.Key, OldRef: sched.OldRef,
		IntervalSeconds: sched.IntervalSeconds, ConfigEventSequence: sched.ConfigEventSequence,
		TickIdempotencyKey: tickIdempotencyKey, TickOrdinal: tickOrdinal,
		CommandKey: commandKey, RequestBinding: requestBinding, TerminalEventID: terminalEventID,
	}
	claimed, acquired, err := a.store.ClaimSecretRotationScheduleCommand(
		ctx, command, leaseToken, time.Minute)
	if err != nil {
		return secretRotationScheduleRunResponse{}, nil, err
	}
	if !acquired {
		if claimed.ClaimState == store.SecretRotationScheduleCommandBusy && claimed.Status == "claimed" {
			return secretRotationScheduleRunResponse{}, nil, secretRotationScheduleDeferredError{
				reason: "command_claimed", cause: errors.New("another scheduler owns the durable due-edge command lease"),
			}
		}
		retained, found, reconcileErr := a.orch.ReconcileSecretRotationScheduleRun(
			ctx, tenantID, sched.ID, runID, sched.NextRunAt)
		if reconcileErr != nil {
			return secretRotationScheduleRunResponse{}, nil, reconcileErr
		}
		if !found {
			return secretRotationScheduleRunResponse{}, nil, fmt.Errorf(
				"%w: terminal command has no retained terminal event",
				store.ErrSecretRotationScheduleCommandConflict)
		}
		return secretRotationScheduleRunResponseFromReceipt(sched, retained, true), nil, nil
	}
	commandRelease := &store.SecretRotationScheduleCommandLeaseRelease{
		ScheduleID: sched.ID,
		RunID:      runID,
		LeaseToken: leaseToken,
	}
	if claimed.ClaimState == store.SecretRotationScheduleCommandRecovered {
		retained, found, reconcileErr := a.orch.ReconcileSecretRotationScheduleRun(
			ctx, tenantID, sched.ID, runID, sched.NextRunAt)
		if reconcileErr != nil {
			return secretRotationScheduleRunResponse{}, commandRelease, reconcileErr
		}
		if found {
			return secretRotationScheduleRunResponseFromReceipt(sched, retained, true), nil, nil
		}
		if claimed.PreparedAt != nil {
			retained, recordErr := a.orch.RecordSecretRotationScheduleRun(ctx, tenantID, store.SecretRotationScheduleRun{
				ScheduleID: sched.ID, RunID: runID,
				Status: claimed.PreparedStatus, NewRef: claimed.PreparedNewRef, Error: claimed.PreparedError,
				RanAt: *claimed.PreparedAt, TickIdempotencyKey: tickIdempotencyKey,
				TickOrdinal: tickOrdinal, LeaseToken: leaseToken,
			})
			if recordErr != nil {
				return secretRotationScheduleRunResponse{}, commandRelease, recordErr
			}
			return secretRotationScheduleRunResponseFromReceipt(sched, retained, true), nil, nil
		}
	} else if claimed.ClaimState != store.SecretRotationScheduleCommandCreated {
		return secretRotationScheduleRunResponse{}, commandRelease, fmt.Errorf(
			"%w: acquired command has unknown claim state %q",
			store.ErrSecretRotationScheduleCommandConflict, claimed.ClaimState)
	}

	status := "failed"
	errText := ""
	rep := rotation.Report{Key: sched.Key, OldRef: sched.OldRef}
	if isConnectorSecretRotation(sched.Provider) {
		rep, err = a.executeConnectorApplicationSecretRotation(ctx, tenantID, commandKey, requestBinding, request)
		if err != nil {
			if errors.Is(err, errPendingApplicationSecretApproval) {
				return secretRotationScheduleRunResponse{}, commandRelease, secretRotationScheduleDeferredError{
					reason: "approval_pending", cause: applicationSecretMutationError(err),
				}
			}
			if errors.Is(err, store.ErrApplicationSecretMutationInFlight) {
				return secretRotationScheduleRunResponse{}, commandRelease, secretRotationScheduleDeferredError{
					reason: "command_in_flight", cause: applicationSecretMutationError(err),
				}
			}
			if !isTerminalConnectorRotationScheduleError(err) {
				// Shared store/event/custody and integrity failures fail-stop the tick.
				return secretRotationScheduleRunResponse{}, commandRelease, applicationSecretMutationError(err)
			}
			// A stale source or connector configuration is terminal for this due edge,
			// not for the whole tenant batch. Persist the failure below and retry only
			// at the bounded next cadence so one broken schedule cannot starve newer work.
			err = applicationSecretMutationError(err)
		}
	} else {
		// Rows created before the connector-only contract may still name an
		// in-process static or dynamic provider. They execute no provider phase:
		// a terminal unsupported event advances and disables the schedule.
		status = "unsupported"
		if strings.HasPrefix(sched.Provider, secretDynamicLeaseRotationPrefix) {
			errText = dynamicLeaseRotationUnavailableDetail
		} else {
			errText = scheduledStaticRotationUnavailableDetail
		}
	}
	if err != nil {
		errText = secretRotationScheduleTerminalErrorDetail(err)
		if rep.RollbackFailed {
			status = "rollback_failed"
		} else if rep.RollbackAttempted && rep.RolledBack {
			status = "rolled_back"
		} else if rep.FailedPhase == "retire" && rep.NewRef != "" {
			// Cutover and verification committed the live successor. The next
			// cadence must start from it even though predecessor cleanup is pending.
			status = "retire_pending"
		} else if rep.FailedPhase == "delivery" && rep.NewRef != "" {
			// The canonical application-secret version committed before the worker
			// exhausted delivery. Preserve that explicit phase as advancement proof.
			status = "delivery_failed"
		}
	} else if status == "unsupported" {
		// The explicit terminal classification above is already authoritative.
	} else if rep.Completed {
		status = "completed"
	} else if rep.Queued {
		status = "queued"
	}
	rotationResp := toSecretRotationResponse(rep)
	if rotationResp.RollbackError != "" {
		rotationResp.RollbackError = store.SecretRotationScheduleRollbackError
	}
	rotationResp.Error = errText
	run, err := a.orch.RecordSecretRotationScheduleRun(ctx, tenantID, store.SecretRotationScheduleRun{
		ScheduleID: sched.ID, RunID: runID, Status: status, NewRef: rep.NewRef, Error: errText,
		TickIdempotencyKey: tickIdempotencyKey, TickOrdinal: tickOrdinal, LeaseToken: leaseToken,
	})
	if err != nil {
		return secretRotationScheduleRunResponse{}, commandRelease, err
	}
	switch status {
	case "completed":
		a.auditSecret(ctx, "secret.rotation_schedule.completed", tenantID, sched.Key, 0)
	case "queued":
		a.auditSecret(ctx, "secret.rotation_schedule.queued", tenantID, sched.Key, 0)
	}
	result := secretRotationScheduleRunResponseFromReceipt(sched, run, false)
	if run.Status != "unsupported" {
		result.Rotation = rotationResp
		result.Rotation.NewRef = run.NewRef
		result.Rotation.Error = run.Error
	}
	result.Status = run.Status
	result.Error = run.Error
	return result, nil, nil
}

func (a *API) secretRotationScheduleRequestBinding(
	tenantID, principal string,
	sched store.SecretRotationSchedule,
	commandKey string,
	request secretRotationRequest,
) (string, error) {
	if isConnectorSecretRotation(sched.Provider) {
		_, baseBinding, err := a.applicationSecretRequestBinding(
			tenantID, commandKey, principal, "SCHEDULE",
			"/api/v1/secrets/rotation-schedules/"+sched.ID,
			"rotate", "rotation", sched.Key, request)
		if err != nil {
			return "", err
		}
		canonical, err := json.Marshal(struct {
			Domain          string `json:"domain"`
			RegistrationSeq uint64 `json:"tenant_registration_event_sequence"`
			BaseBinding     string `json:"base_binding"`
		}{
			Domain:          "trstctl.secret-rotation-schedule.child-binding.v3",
			RegistrationSeq: sched.TenantRegistrationEventSequence,
			BaseBinding:     baseBinding,
		})
		if err != nil {
			return "", err
		}
		defer secret.Wipe(canonical)
		return crypto.SHA256Hex(canonical), nil
	}
	canonical, err := json.Marshal(struct {
		Domain          string    `json:"domain"`
		TenantID        string    `json:"tenant_id"`
		RegistrationSeq uint64    `json:"tenant_registration_event_sequence"`
		ScheduleID      string    `json:"schedule_id"`
		DueAt           time.Time `json:"due_at"`
		Provider        string    `json:"provider"`
		Key             string    `json:"key"`
		OldRef          string    `json:"old_ref"`
		CommandKey      string    `json:"command_key"`
	}{
		"trstctl.secret-rotation-schedule.child-binding.v3", tenantID,
		sched.TenantRegistrationEventSequence, sched.ID, sched.NextRunAt.UTC(),
		sched.Provider, sched.Key, sched.OldRef, commandKey,
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(canonical)
	return crypto.SHA256Hex(canonical), nil
}

func secretRotationScheduleRunResponseFromReceipt(
	sched store.SecretRotationSchedule,
	run store.SecretRotationScheduleRun,
	reconciled bool,
) secretRotationScheduleRunResponse {
	closedError := store.CanonicalSecretRotationScheduleError(run.Status, run.Error)
	rep := rotation.Report{Key: sched.Key, OldRef: sched.OldRef, NewRef: run.NewRef}
	switch run.Status {
	case "completed":
		rep.Completed = true
	case "queued":
		rep.Queued = true
	case "rolled_back":
		rep.RollbackAttempted = true
		rep.RolledBack = true
	case "rollback_failed":
		rep.RollbackAttempted = true
		rep.RollbackFailed = true
	case "retire_pending":
		rep.FailedPhase = "retire"
	case "delivery_failed":
		rep.FailedPhase = "delivery"
	case "unsupported":
		rep.FailedPhase = "provider"
	}
	rotationResp := toSecretRotationResponse(rep)
	rotationResp.Error = closedError
	return secretRotationScheduleRunResponse{
		ScheduleID: sched.ID, RunID: run.RunID, DueAt: run.DueAt, Status: run.Status,
		Rotation: rotationResp, Error: closedError, RanAt: run.RanAt, Reconciled: reconciled,
	}
}
