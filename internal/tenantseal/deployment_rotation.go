// SPDX-License-Identifier: BUSL-1.1

package tenantseal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var (
	// ErrDeploymentRotationConflict means a rotation to another wrapper is
	// recorded and not complete; it must finish (or be resumed) first, because
	// data written since it started is already under its next generation.
	ErrDeploymentRotationConflict = errors.New("tenantseal: a deployment KEK rotation to another wrapper is not complete")
	// ErrDeploymentRotationNotConfigured means the deployment KEK is not
	// rotatable here: no database, event log, or wrapper registry.
	ErrDeploymentRotationNotConfigured = errors.New("tenantseal: deployment KEK rotation is not configured")
)

const (
	// defaultDeploymentSettle is how long a rotation waits after recording its
	// next generation before it re-wraps anything: every request or delivery
	// that sealed under the previous generation before the record has finished
	// by then, and every direct use of the keyring has re-read the state.
	defaultDeploymentSettle = 2 * time.Minute
	// deploymentTenantBatch bounds one step of a hot-state pass.
	deploymentTenantBatch = 25
	// deploymentMaxVerifyPasses bounds how often a verify pass may still find
	// a data key under a previous generation before the rotation fails.
	deploymentMaxVerifyPasses = 3
)

// DeploymentRotation is the served lifecycle of the deployment KEK (A198). A
// rotation records the next generation (created under the operator's wrapper),
// from which moment every new data key is wrapped under it, then re-wraps
// every stored data key in bounded steps a leader worker drives: each tenant's
// hot state under that tenant's exclusive fence, the event history of every
// tenant whose history still holds deployment-KEK containers, and the
// deployment-scoped sealed files; a verify pass reads everything back and
// must find nothing under a previous generation before the next generation is
// promoted and the previous one retired. Payloads are never opened. Requests
// keep being served throughout, and a restarted or new leader resumes from
// the recorded step.
type DeploymentRotation struct {
	store          *store.Store
	log            *events.Log
	projector      *projections.Projector
	keyring        *DeploymentKeyring
	registry       DomainKEKManager
	settle         time.Duration
	files          []string
	rewriteOptions []events.TenantDataRewriteOption
	now            func() time.Time
}

// DeploymentRotationOption configures a DeploymentRotation.
type DeploymentRotationOption func(*DeploymentRotation)

// WithDeploymentSettle replaces the wait between recording the next
// generation and the first re-wrap.
func WithDeploymentSettle(d time.Duration) DeploymentRotationOption {
	return func(r *DeploymentRotation) { r.settle = d }
}

// WithDeploymentSealedFiles names the deployment-scoped files sealed under the
// deployment KEK (the SAML encryption identity, protocol RA identities, the
// reachability verdict key, a transit keyring checkpoint). A rotation
// re-wraps each one that exists.
func WithDeploymentSealedFiles(paths ...string) DeploymentRotationOption {
	return func(r *DeploymentRotation) {
		for _, path := range paths {
			if strings.TrimSpace(path) != "" {
				r.files = append(r.files, filepath.Clean(path))
			}
		}
	}
}

// WithDeploymentHistoryRewriteOptions passes the history-rewrite proof walls
// (continuity receipts, audit checkpoints) every history pass uses.
func WithDeploymentHistoryRewriteOptions(options ...events.TenantDataRewriteOption) DeploymentRotationOption {
	return func(r *DeploymentRotation) { r.rewriteOptions = append(r.rewriteOptions, options...) }
}

// NewDeploymentRotation builds the lifecycle. It opens no wrapper.
func NewDeploymentRotation(
	st *store.Store,
	log *events.Log,
	keyring *DeploymentKeyring,
	registry DomainKEKManager,
	options ...DeploymentRotationOption,
) (*DeploymentRotation, error) {
	if st == nil || log == nil || keyring == nil || registry == nil {
		return nil, ErrDeploymentRotationNotConfigured
	}
	r := &DeploymentRotation{
		store: st, log: log, projector: projections.New(st),
		keyring: keyring, registry: registry,
		settle: defaultDeploymentSettle, now: time.Now,
	}
	for _, option := range options {
		option(r)
	}
	sort.Strings(r.files)
	return r, nil
}

// Status returns the recorded deployment KEK state; found is false while the
// deployment KEK has never rotated.
func (r *DeploymentRotation) Status(ctx context.Context) (store.DeploymentKEKDomain, bool, error) {
	if r == nil {
		return store.DeploymentKEKDomain{}, false, ErrDeploymentRotationNotConfigured
	}
	return r.store.DeploymentKEKDomain(ctx)
}

// Begin records a rotation to the next generation under ref, or resumes the
// recorded one to the same wrapper. operatorTenantID is the tenant whose
// history records the rotation.
func (r *DeploymentRotation) Begin(ctx context.Context, operatorTenantID string, ref WrapperRef) (store.DeploymentKEKDomain, error) {
	if r == nil {
		return store.DeploymentKEKDomain{}, ErrDeploymentRotationNotConfigured
	}
	if operatorTenantID == "" {
		return store.DeploymentKEKDomain{}, errors.New("tenantseal: the operator tenant is required (AN-1)")
	}
	if !validWrapperRef(ref) {
		return store.DeploymentKEKDomain{}, fmt.Errorf("%w: wrapper kind and id are required", ErrInvalidWrapperConfig)
	}
	var out store.DeploymentKEKDomain
	err := r.store.WithTenant(ctx, operatorTenantID, func(tx pgx.Tx) error {
		if err := r.store.LockDeploymentKEKTx(ctx, tx); err != nil {
			return err
		}
		current, found, err := r.store.DeploymentKEKDomainTx(ctx, tx)
		if err != nil {
			return err
		}
		if found && current.Rotating() {
			if current.NextWrapperKind != ref.Kind || current.NextWrapperID != ref.ID {
				return ErrDeploymentRotationConflict
			}
			if current.OperationStatus == store.DeploymentKEKOperationRunning {
				out = current
				return nil
			}
			resumed := current
			resumed.OperationStatus = store.DeploymentKEKOperationRunning
			resumed.LastErrorCode, resumed.LastError = "", ""
			return r.appendTx(ctx, tx, operatorTenantID, projections.EventDeploymentKEKRotationProgressed, resumed, &out)
		}
		next := current
		if !found {
			next = store.DeploymentKEKDomain{DomainID: uuid.NewString(), CreatedAt: r.now().UTC()}
		}
		next.NextGeneration = next.Generation + 1
		binding, err := DeploymentBinding(next.DomainID, next.NextGeneration)
		if err != nil {
			return err
		}
		key, wrapped, err := r.registry.CreateDomainKEK(ctx, ref, binding)
		if err != nil {
			return err
		}
		if key != nil {
			key.Destroy()
		}
		started := r.now().UTC()
		next.NextWrapperKind, next.NextWrapperID, next.NextWrappedKEK = ref.Kind, ref.ID, wrapped
		next.OperationID = uuid.NewString()
		next.OperationStatus = store.DeploymentKEKOperationRunning
		next.Stage, next.ProgressCursor = store.DeploymentKEKStageSettling, ""
		next.TenantsTotal, next.TenantsDone = 0, 0
		next.ContainersRewrapped, next.HistoryEventsRewrapped, next.FilesRewrapped = 0, 0, 0
		next.ContainersVerified, next.VerifyPasses, next.VerifyStragglers = 0, 0, 0
		next.StartedAt, next.VerifiedAt = &started, nil
		next.LastErrorCode, next.LastError = "", ""
		return r.appendTx(ctx, tx, operatorTenantID, projections.EventDeploymentKEKRotationStarted, next, &out)
	})
	if err != nil {
		return store.DeploymentKEKDomain{}, err
	}
	r.keyring.Observe(out)
	return out, nil
}

func validWrapperRef(ref WrapperRef) bool {
	return (ref.Kind == WrapperKindLocalFile || ref.Kind == WrapperKindPKCS11) &&
		ref.ID != "" && strings.TrimSpace(ref.ID) == ref.ID
}

// Step advances a running rotation by one bounded unit of work. done reports
// that no rotation needs more work now (none runs, it failed, or it is
// waiting out its settle time); the caller steps again on its next tick.
func (r *DeploymentRotation) Step(ctx context.Context) (done bool, err error) {
	if r == nil {
		return true, nil
	}
	current, found, err := r.store.DeploymentKEKDomain(ctx)
	if err != nil {
		return true, err
	}
	if !found || !current.Rotating() || current.OperationStatus != store.DeploymentKEKOperationRunning {
		return true, nil
	}
	r.keyring.Observe(current)
	switch current.Stage {
	case store.DeploymentKEKStageSettling:
		if current.StartedAt != nil && r.now().Sub(*current.StartedAt) < r.settle {
			return true, nil
		}
		tenants, err := r.tenantIDs(ctx)
		if err != nil {
			return true, err
		}
		next := current
		next.Stage, next.ProgressCursor = store.DeploymentKEKStageHotState, ""
		next.TenantsTotal, next.TenantsDone = int64(len(tenants)), 0
		return false, r.progress(ctx, current, next, projections.EventDeploymentKEKRotationProgressed)
	case store.DeploymentKEKStageHotState, store.DeploymentKEKStageVerify:
		return false, r.stepHotState(ctx, current)
	case store.DeploymentKEKStageHistory:
		return false, r.stepHistory(ctx, current)
	case store.DeploymentKEKStageFiles:
		return false, r.stepFiles(ctx, current)
	default:
		return true, r.fail(ctx, current, "unknown_stage", "the rotation names a stage this release does not run")
	}
}

// stepHotState re-wraps (or, in the verify pass, reads back and re-wraps any
// straggler in) every ciphertext column of the next batch of tenants.
func (r *DeploymentRotation) stepHotState(ctx context.Context, current store.DeploymentKEKDomain) error {
	tenants, err := r.tenantIDs(ctx)
	if err != nil {
		return err
	}
	batch := tenantsAfter(tenants, current.ProgressCursor, deploymentTenantBatch)
	view := r.keyring.View(&current)
	defer view.Destroy()
	rewriter, err := NewDeploymentRewrapper(view)
	if err != nil {
		return err
	}
	var changed int64
	for _, tenantID := range batch {
		for _, stage := range store.TenantKeyDomainCiphertextMigrationStages() {
			n, err := r.store.RewriteTenantKeyDomainCiphertextStage(ctx, tenantID, stage,
				func(before []byte) ([]byte, bool, error) {
					return rewriter.Transform("postgres."+stage, 1, before)
				})
			if err != nil {
				return r.stepFailure(ctx, current, "hot_state_rewrap_failed", "a tenant's stored data keys could not be re-wrapped", err)
			}
			changed += n
		}
	}
	containers, _ := rewriter.DeploymentCounts()
	next := current
	next.TenantsDone += int64(len(batch))
	if len(batch) > 0 {
		next.ProgressCursor = batch[len(batch)-1]
	}
	next.LastErrorCode, next.LastError = "", ""
	next.ContainersRewrapped += changed
	verifying := current.Stage == store.DeploymentKEKStageVerify
	if verifying {
		// A straggler re-wrapped now is counted, and the pass repeats: only a
		// pass that changes nothing proves the previous generation is unused.
		next.ContainersVerified += containers
		next.VerifyStragglers += changed
	}
	if len(tenantsAfter(tenants, next.ProgressCursor, 1)) > 0 {
		return r.progress(ctx, current, next, projections.EventDeploymentKEKRotationProgressed)
	}
	if !verifying {
		history, err := r.historyTenantIDs(ctx, tenants)
		if err != nil {
			return err
		}
		next.Stage, next.ProgressCursor = store.DeploymentKEKStageHistory, ""
		next.TenantsTotal, next.TenantsDone = int64(len(history)), 0
		return r.progress(ctx, current, next, projections.EventDeploymentKEKRotationProgressed)
	}
	// The verify pass's last batch: read back the files as well.
	filesChanged, err := r.rewrapFiles(view)
	if err != nil {
		return r.stepFailure(ctx, current, "files_rewrap_failed", "a deployment sealed file could not be re-wrapped", err)
	}
	next.FilesRewrapped += filesChanged
	next.VerifyStragglers += filesChanged
	if next.VerifyStragglers > 0 {
		next.VerifyPasses++
		if next.VerifyPasses >= deploymentMaxVerifyPasses {
			return r.fail(ctx, next, "stragglers_after_verify",
				"data keys under the previous generation kept appearing after the re-wrap; the previous generation stays current")
		}
		next.ProgressCursor, next.TenantsDone, next.VerifyStragglers = "", 0, 0
		return r.progress(ctx, current, next, projections.EventDeploymentKEKRotationProgressed)
	}
	return r.complete(ctx, current, next)
}

// stepHistory re-wraps one tenant's event history: tenants whose key-domain
// migration completed hold no deployment-KEK container there any more.
func (r *DeploymentRotation) stepHistory(ctx context.Context, current store.DeploymentKEKDomain) error {
	tenants, err := r.tenantIDs(ctx)
	if err != nil {
		return err
	}
	history, err := r.historyTenantIDs(ctx, tenants)
	if err != nil {
		return err
	}
	next := current
	next.LastErrorCode, next.LastError = "", ""
	batch := tenantsAfter(history, current.ProgressCursor, 1)
	if len(batch) == 0 {
		next.Stage, next.ProgressCursor = store.DeploymentKEKStageFiles, ""
		return r.progress(ctx, current, next, projections.EventDeploymentKEKRotationProgressed)
	}
	tenantID := batch[0]
	view := r.keyring.View(&current)
	defer view.Destroy()
	rewriter, err := NewDeploymentRewrapper(view)
	if err != nil {
		return err
	}
	var changed int
	err = r.log.WithHistoryOperation(ctx, func(operationCtx context.Context) error {
		options := append([]events.TenantDataRewriteOption{
			events.WithTenantDataPairValidator(rewriter.ValidatePair),
		}, r.rewriteOptions...)
		var err error
		changed, err = r.log.RewriteTenantData(operationCtx, tenantID, rewriter.Transform, options...)
		return err
	})
	if err != nil {
		return r.stepFailure(ctx, current, "history_rewrap_failed", "a tenant's event history could not be re-wrapped", err)
	}
	next.HistoryEventsRewrapped += int64(changed)
	next.TenantsDone++
	next.ProgressCursor = tenantID
	return r.progress(ctx, current, next, projections.EventDeploymentKEKRotationProgressed)
}

// stepFiles re-wraps the deployment-scoped sealed files, then starts the
// verify pass.
func (r *DeploymentRotation) stepFiles(ctx context.Context, current store.DeploymentKEKDomain) error {
	view := r.keyring.View(&current)
	defer view.Destroy()
	changed, err := r.rewrapFiles(view)
	if err != nil {
		return r.stepFailure(ctx, current, "files_rewrap_failed", "a deployment sealed file could not be re-wrapped", err)
	}
	tenants, err := r.tenantIDs(ctx)
	if err != nil {
		return err
	}
	next := current
	next.FilesRewrapped += changed
	next.Stage, next.ProgressCursor = store.DeploymentKEKStageVerify, ""
	next.TenantsTotal, next.TenantsDone = int64(len(tenants)), 0
	next.LastErrorCode, next.LastError = "", ""
	return r.progress(ctx, current, next, projections.EventDeploymentKEKRotationProgressed)
}

// rewrapFiles moves each existing deployment sealed file's data key to the
// writing generation, replacing the file atomically.
func (r *DeploymentRotation) rewrapFiles(view *DeploymentView) (int64, error) {
	var changed int64
	for _, path := range r.files {
		content, err := os.ReadFile(path) // #nosec G304 -- operator-configured deployment file paths (CWE-22)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return changed, err
		}
		if !bytes.HasPrefix(content, []byte("CSL1")) {
			return changed, fmt.Errorf("tenantseal: %s is not a sealed container", path)
		}
		next, moved, err := seal.RewrapContainerDEK(content, view.Rewrap)
		if err != nil {
			return changed, fmt.Errorf("tenantseal: re-wrap %s: %w", path, err)
		}
		if !moved {
			continue
		}
		if err := replaceFileAtomically(path, next); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

func replaceFileAtomically(path string, content []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".deployment-kek-rewrap-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// complete promotes the verified next generation and retires the previous one.
func (r *DeploymentRotation) complete(ctx context.Context, current, next store.DeploymentKEKDomain) error {
	now := r.now().UTC()
	next.PreviousGeneration = current.Generation
	next.Generation = current.NextGeneration
	next.WrapperKind, next.WrapperID, next.WrappedKEK = current.NextWrapperKind, current.NextWrapperID, current.NextWrappedKEK
	next.NextGeneration, next.NextWrapperKind, next.NextWrapperID, next.NextWrappedKEK = 0, "", "", nil
	next.OperationStatus = store.DeploymentKEKOperationCompleted
	next.Stage, next.ProgressCursor = store.DeploymentKEKStageCompleted, ""
	next.VerifiedAt, next.RotatedAt = &now, &now
	next.LastErrorCode, next.LastError = "", ""
	return r.progress(ctx, current, next, projections.EventDeploymentKEKRotationCompleted)
}

// stepFailure records why a step did not finish. A failure that a retry cannot
// fix (a container that needs an explicit migration, a corrupt container, a
// data key under a generation nobody holds) fails the rotation; any other
// keeps it running so the next step retries.
func (r *DeploymentRotation) stepFailure(ctx context.Context, current store.DeploymentKEKDomain, code, message string, cause error) error {
	if errors.Is(cause, ErrLegacyEnvelope) || errors.Is(cause, ErrCertificateMetadataReceiptBridge) ||
		errors.Is(cause, ErrCorruptContainer) || errors.Is(cause, ErrDeploymentGenerationNotLive) ||
		errors.Is(cause, ErrUnexpectedDomain) {
		if err := r.fail(ctx, current, code, message); err != nil {
			return err
		}
		return cause
	}
	if current.LastErrorCode != code {
		next := current
		next.LastErrorCode, next.LastError = code, message
		if err := r.progress(ctx, current, next, projections.EventDeploymentKEKRotationProgressed); err != nil {
			return errors.Join(cause, err)
		}
	}
	return cause
}

// fail stops the rotation. The next generation stays recorded and keeps
// receiving new data, so the rotation can only be resumed to the same
// wrapper.
func (r *DeploymentRotation) fail(ctx context.Context, current store.DeploymentKEKDomain, code, message string) error {
	next := current
	next.OperationStatus = store.DeploymentKEKOperationFailed
	next.LastErrorCode, next.LastError = code, message
	return r.progress(ctx, current, next, projections.EventDeploymentKEKRotationFailed)
}

// progress records the next state if the recorded one is still current, so
// two workers never both advance one step.
func (r *DeploymentRotation) progress(ctx context.Context, current, next store.DeploymentKEKDomain, eventType string) error {
	tenantID := current.OperatorTenantID
	var out store.DeploymentKEKDomain
	err := r.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := r.store.LockDeploymentKEKTx(ctx, tx); err != nil {
			return err
		}
		recorded, found, err := r.store.DeploymentKEKDomainTx(ctx, tx)
		if err != nil {
			return err
		}
		if !found || recorded.LastTransitionSequence != current.LastTransitionSequence {
			out = recorded
			return nil
		}
		return r.appendTx(ctx, tx, tenantID, eventType, next, &out)
	})
	if err != nil {
		return err
	}
	r.keyring.Observe(out)
	return nil
}

func (r *DeploymentRotation) appendTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, eventType string,
	next store.DeploymentKEKDomain,
	out *store.DeploymentKEKDomain,
) error {
	next.UpdatedAt = r.now().UTC()
	payload, err := json.Marshal(projections.DeploymentKEKSnapshotFrom(next))
	if err != nil {
		return err
	}
	event, err := r.log.Append(ctx, events.Event{
		Type: eventType, TenantID: tenantID, SchemaVersion: 1, Data: payload,
	})
	if err != nil {
		return err
	}
	if err := r.projector.ApplyTx(ctx, tx, event); err != nil {
		return err
	}
	recorded, found, err := r.store.DeploymentKEKDomainTx(ctx, tx)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("tenantseal: the deployment KEK record did not project")
	}
	*out = recorded
	return nil
}

func (r *DeploymentRotation) tenantIDs(ctx context.Context) ([]string, error) {
	tenants, err := r.store.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(tenants))
	for _, tenant := range tenants {
		out = append(out, tenant.TenantID)
	}
	sort.Strings(out)
	return out, nil
}

func (r *DeploymentRotation) historyTenantIDs(ctx context.Context, tenants []string) ([]string, error) {
	migrated, err := r.store.TenantsWithMigratedKeyDomainHistory(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(tenants))
	for _, tenantID := range tenants {
		if !migrated[tenantID] {
			out = append(out, tenantID)
		}
	}
	return out, nil
}

// tenantsAfter returns up to limit sorted tenant IDs after cursor.
func tenantsAfter(sorted []string, cursor string, limit int) []string {
	start := sort.SearchStrings(sorted, cursor)
	if start < len(sorted) && sorted[start] == cursor {
		start++
	}
	if cursor == "" {
		start = 0
	}
	end := start + limit
	if end > len(sorted) {
		end = len(sorted)
	}
	return sorted[start:end]
}
