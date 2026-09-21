// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nuid"

	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/tenancy"
)

const (
	activeStreamProbeSubject = "events.__trstctl_route_probe"
	rewriteStreamPrefix      = "TRSTCTL_EVENTS_G_"

	rewriteMetadataOperation           = "trstctl.rewrite.operation"
	rewriteMetadataRole                = "trstctl.rewrite.role"
	rewriteMetadataPhase               = "trstctl.rewrite.phase"
	rewriteMetadataSource              = "trstctl.rewrite.source"
	rewriteMetadataTarget              = "trstctl.rewrite.target"
	rewriteMetadataTenant              = "trstctl.rewrite.tenant"
	rewriteMetadataGeneration          = "trstctl.generation"
	rewriteMetadataConfigHash          = "trstctl.rewrite.config_sha256"
	rewriteMetadataReceiptSeq          = "trstctl.rewrite.receipt_sequence"
	rewriteMetadataReceiptID           = "trstctl.rewrite.receipt_id"
	rewriteMetadataReceiptSum          = "trstctl.rewrite.receipt_sha256"
	rewriteMetadataReport              = "trstctl.rewrite.report_base64"
	rewriteMetadataReportSum           = "trstctl.rewrite.report_sha256"
	rewriteMetadataRestore             = "trstctl.rewrite.source_restore_base64"
	rewriteMetadataRestoreSum          = "trstctl.rewrite.source_restore_sha256"
	rewriteMetadataExternalPreparation = "trstctl.rewrite.external_preparation"

	rewriteRoleSource = "source"
	rewriteRoleTarget = "target"
	rewriteRoleActive = "active"

	rewriteExternalPreparationPrivacySubjectErasure = "privacy_subject_erasure"
)

// ErrGenerationChanged reports that a read view crossed a generation cutover.
// Callers whose callback has side effects may retry from their durable sequence
// watermark; the rewrite preserves every historical stream sequence.
var ErrGenerationChanged = errors.New("events: active stream generation changed")

// HistoryRewriteCoordinator is the cross-replica safety wall around a generation
// rewrite. WithRewriteOperation elects one rewriter. WithCutover excludes all
// WithRead views during freeze/activation. External NATS mode refuses a rewrite
// unless the server wires a deployment-wide implementation.
type HistoryRewriteCoordinator interface {
	WithRewriteOperation(context.Context, func(context.Context) error) error
	WithCutover(context.Context, func(context.Context) error) error
	WithRead(context.Context, func(context.Context) error) error
}

// HistoryRewritePreparationResolver is the optional cross-store recovery seam
// for a target that was fully staged and signed before an external PostgreSQL
// preparation committed. A coordinator backed by that same PostgreSQL deployment
// can prove the non-PII operation/target marker after a process crash; the events
// layer then activates without needing the erased plaintext again.
type HistoryRewritePreparationResolver interface {
	HistoryRewritePreparationActive(
		ctx context.Context,
		tenantID, targetGeneration string,
	) (bool, error)
}

type localHistoryRewriteCoordinator struct {
	operation sync.Mutex
	barrier   sync.RWMutex
}

type localHistoryReadToken struct {
	coordinator *localHistoryRewriteCoordinator
	active      *atomic.Bool
}

type localHistoryReadContextKey struct{}

type localHistoryExclusiveGrant struct {
	coordinator *localHistoryRewriteCoordinator
	active      *atomic.Bool
}

type localHistoryExclusiveGrantContextKey struct{}

// historyGenerationReadView is a private route valid only while one cutover owns
// the exclusive history barrier. External privacy preparation needs to inspect
// the pre-rewrite facts after the source route is frozen, but that authority must
// not escape into a later generation. Every read receives a revocable lease; the
// cutover stops admitting new leases and waits for all admitted reads before it
// activates the target or deletes the source.
type historyGenerationReadView struct {
	log       *Log
	name      string
	stream    jetstream.Stream
	mu        sync.Mutex
	drained   *sync.Cond
	accepting bool
	readers   int
}

type historyGenerationReadGrant struct {
	view *historyGenerationReadView
}

type historyGenerationReadGrantContextKey struct{}

type historyGenerationReadLease struct {
	view   *historyGenerationReadView
	active bool
}

type historyGenerationReadLeaseContextKey struct{}

// detachedHistoryGenerationContext preserves only cancellation and deadline
// behavior after a private generation view expires. In particular it drops a
// coordinator's package-private cutover grant: otherwise an escaped preparation
// context could make WithRead believe it still owned the outer exclusive lock
// during the short interval before that callback returns. The stale caller then
// reacquires the ordinary barrier and resolves whichever generation is actually
// authoritative after the cutover.
type detachedHistoryGenerationContext struct {
	context.Context
}

func (detachedHistoryGenerationContext) Value(any) any { return nil }

type historyOperationToken struct {
	log    *Log
	active *atomic.Bool
}

type historyOperationContextKey struct{}

func newLocalHistoryRewriteCoordinator() *localHistoryRewriteCoordinator {
	return &localHistoryRewriteCoordinator{}
}

func newHistoryGenerationReadView(
	log *Log,
	name string,
	stream jetstream.Stream,
) *historyGenerationReadView {
	view := &historyGenerationReadView{
		log: log, name: name, stream: stream, accepting: true,
	}
	view.drained = sync.NewCond(&view.mu)
	return view
}

func (v *historyGenerationReadView) acquire(
	log *Log,
	parent *historyGenerationReadLease,
) *historyGenerationReadLease {
	if v == nil {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.log != log {
		return nil
	}
	if parent == nil {
		if !v.accepting {
			return nil
		}
	} else if parent.view != v || !parent.active {
		return nil
	}
	v.readers++
	return &historyGenerationReadLease{view: v, active: true}
}

func (v *historyGenerationReadView) release(lease *historyGenerationReadLease) {
	if v == nil || lease == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if lease.view != v || !lease.active {
		return
	}
	lease.active = false
	v.readers--
	if v.readers == 0 {
		v.drained.Broadcast()
	}
}

func (v *historyGenerationReadView) revokeAndWait() {
	if v == nil {
		return
	}
	v.mu.Lock()
	v.accepting = false
	for v.readers > 0 {
		v.drained.Wait()
	}
	v.mu.Unlock()
}

func (v *historyGenerationReadView) route(
	log *Log,
	lease *historyGenerationReadLease,
) (string, jetstream.Stream, bool) {
	if v == nil || lease == nil {
		return "", nil, false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.log != log || lease.view != v || !lease.active {
		return "", nil, false
	}
	return v.name, v.stream, true
}

func (c *localHistoryRewriteCoordinator) WithRewriteOperation(ctx context.Context, fn func(context.Context) error) error {
	c.operation.Lock()
	defer c.operation.Unlock()
	return fn(ctx)
}

func (c *localHistoryRewriteCoordinator) WithCutover(ctx context.Context, fn func(context.Context) error) error {
	c.barrier.Lock()
	defer c.barrier.Unlock()
	active := &atomic.Bool{}
	active.Store(true)
	defer active.Store(false)
	cutoverCtx := context.WithValue(ctx, localHistoryExclusiveGrantContextKey{}, localHistoryExclusiveGrant{
		coordinator: c,
		active:      active,
	})
	return fn(cutoverCtx)
}

func (c *localHistoryRewriteCoordinator) WithRead(ctx context.Context, fn func(context.Context) error) error {
	if grant, ok := ctx.Value(localHistoryExclusiveGrantContextKey{}).(localHistoryExclusiveGrant); ok &&
		grant.coordinator == c && grant.active != nil && grant.active.Load() {
		return fn(ctx)
	}
	if token, ok := ctx.Value(localHistoryReadContextKey{}).(localHistoryReadToken); ok &&
		token.coordinator == c && token.active != nil && token.active.Load() {
		return fn(ctx)
	}
	c.barrier.RLock()
	defer c.barrier.RUnlock()
	active := &atomic.Bool{}
	active.Store(true)
	defer active.Store(false)
	readCtx := context.WithValue(ctx, localHistoryReadContextKey{}, localHistoryReadToken{
		coordinator: c,
		active:      active,
	})
	return fn(readCtx)
}

// TenantDataTransform receives one immutable event payload for a single tenant.
// Returning changed=false preserves the exact stored bytes. A changed payload must
// remain valid for that event type/schema so deterministic replay rebuilds the
// same logical state.
type TenantDataTransform func(eventType string, schemaVersion int, data []byte) (next []byte, changed bool, err error)

// TenantDataPairValidator verifies one actual old/new pair without recreating the
// new bytes. Cryptographic rewraps are randomized, so final reconciliation must
// validate the staged result rather than invoke transform a second time.
type TenantDataPairValidator func(eventType string, schemaVersion int, before, after []byte) error

type storedEventTransform func(storedEvent) (storedEvent, bool, error)
type storedEventPairValidator func(before, after storedEvent) error

// TenantDataContinuity creates the signed, tenant-scoped event that authorizes
// activation and binds the old/new mapping report. The event is persisted in the
// target generation before that generation can become authoritative.
type TenantDataContinuity func(context.Context, TenantDataRewriteReport) (Event, error)

// TenantDataCutoverPreparation must acquire the backup write fence and invalidate
// recoverable read-model snapshots before activation. Generic rewrites delete the
// full snapshot cache before invoking proceed. The privacy external preparation
// instead deletes its target tenant's snapshot inside the same SQL transaction as
// its durable marker; TenantDataCutoverDefersSnapshotInvalidation is the private
// context proof for that one exception. RewriteTenantData calls this callback while
// its exclusive history cutover barrier is held, and refuses activation unless
// proceed is invoked.
type TenantDataCutoverPreparation func(
	context.Context,
	TenantDataRewriteReport,
	func(context.Context) error,
) error

// TenantDataAuditCheckpoint identifies the exact retention seed used to derive
// both audit heads. IdentityDigest must also distinguish the genesis/no-checkpoint
// case (for example SHA-256 of a canonical "genesis" record).
type TenantDataAuditCheckpoint struct {
	BoundarySequence uint64 `json:"boundary_sequence"`
	BoundaryHash     string `json:"boundary_hash,omitempty"`
	RecordCount      uint64 `json:"record_count"`
	IdentityDigest   string `json:"identity_digest"`
}

// TenantDataAuditContinuity is supplied by the audit layer while source and
// target are both frozen. Event.Data is audit-hash-covered, so these heads are
// required evidence of the intentional chain divergence.
type TenantDataAuditContinuity struct {
	Checkpoint            TenantDataAuditCheckpoint `json:"checkpoint"`
	SourcePreCutChainHead string                    `json:"source_pre_cut_chain_head"`
	TargetPreReceiptHead  string                    `json:"target_pre_receipt_chain_head"`
}

// TenantDataAuditView provides generation-pinned replay to the audit callback.
// Its methods do not re-resolve the active stream while the cutover is frozen.
type TenantDataAuditView struct {
	Report TenantDataRewriteReport
	source jetstream.Stream
	target jetstream.Stream
}

func (v TenantDataAuditView) ReplaySource(ctx context.Context, fn func(Event) error) error {
	return replayStreamThrough(ctx, v.source, v.Report.SourceCutSequence, fn)
}

func (v TenantDataAuditView) ReplayTarget(ctx context.Context, fn func(Event) error) error {
	return replayStreamThrough(ctx, v.target, v.Report.SourceCutSequence, fn)
}

// TenantDataAuditContinuityProvider supplies the current retention seed while the
// history barrier and caller-supplied backup fence are both held. The events
// package derives both heads itself over generation-pinned bytes.
type TenantDataAuditContinuityProvider func(
	context.Context,
	TenantDataAuditView,
) (TenantDataAuditCheckpoint, error)

// TenantDataContinuityEvidence is the verifier input. Recovery reconstructs it
// from durable target metadata plus the exact receipt event.
type TenantDataContinuityEvidence struct {
	OperationID     string                  `json:"operation_id"`
	TenantID        string                  `json:"tenant_id"`
	SourceStream    string                  `json:"source_stream"`
	TargetStream    string                  `json:"target_stream"`
	ReceiptSequence uint64                  `json:"receipt_sequence"`
	Receipt         Event                   `json:"receipt"`
	Report          TenantDataRewriteReport `json:"report"`
}

// TenantDataContinuityVerifier verifies the caller's signed receipt. It must
// perform cryptographic verification, not merely parse the event.
type TenantDataContinuityVerifier func(context.Context, TenantDataContinuityEvidence) error

type tenantDataRewriteOptions struct {
	validate            TenantDataPairValidator
	continuity          TenantDataContinuity
	prepare             TenantDataCutoverPreparation
	audit               TenantDataAuditContinuityProvider
	profile             string
	externalPreparation func(context.Context, TenantDataRewriteReport) error
	externalKind        string
}

type tenantDataSnapshotInvalidationContextKey struct{}

// TenantDataCutoverDefersSnapshotInvalidation reports whether the cutover's
// independently durable SQL preparation owns target-snapshot deletion. It is a
// narrow store-facing signal, not caller-supplied policy: only the privacy
// rewrite path can install it, and only while its exact external preparation is
// about to run before activation. Generic rewrites continue to invalidate their
// snapshots in the cutover wrapper before proceeding.
func TenantDataCutoverDefersSnapshotInvalidation(ctx context.Context) bool {
	kind, _ := ctx.Value(tenantDataSnapshotInvalidationContextKey{}).(string)
	return kind == rewriteExternalPreparationPrivacySubjectErasure
}

func tenantDataCutoverPreparationContext(
	ctx context.Context,
	opts tenantDataRewriteOptions,
) context.Context {
	if opts.externalPreparation == nil ||
		opts.externalKind != rewriteExternalPreparationPrivacySubjectErasure {
		return ctx
	}
	return context.WithValue(
		ctx,
		tenantDataSnapshotInvalidationContextKey{},
		opts.externalKind,
	)
}

// TenantDataRewriteOption configures the mandatory proof walls for a rewrite.
type TenantDataRewriteOption func(*tenantDataRewriteOptions)

// WithTenantDataPairValidator requires a transform-specific old/new validation.
func WithTenantDataPairValidator(validate TenantDataPairValidator) TenantDataRewriteOption {
	return func(options *tenantDataRewriteOptions) { options.validate = validate }
}

// WithTenantDataContinuity requires durable signed continuity before activation.
func WithTenantDataContinuity(continuity TenantDataContinuity) TenantDataRewriteOption {
	return func(options *tenantDataRewriteOptions) { options.continuity = continuity }
}

// WithTenantDataCutoverPreparation wires snapshot invalidation under the backup
// write fence. The callback must invoke proceed exactly once.
func WithTenantDataCutoverPreparation(prepare TenantDataCutoverPreparation) TenantDataRewriteOption {
	return func(options *tenantDataRewriteOptions) { options.prepare = prepare }
}

// WithTenantDataAuditContinuity wires audit-chain divergence evidence.
func WithTenantDataAuditContinuity(audit TenantDataAuditContinuityProvider) TenantDataRewriteOption {
	return func(options *tenantDataRewriteOptions) { options.audit = audit }
}

// WithTenantDataRewriteProfile binds a closed transform identity into the
// signed continuity report. Generic historical rewrites may leave it empty;
// recovery and artifact-resume paths that authorize one exact deterministic
// rewrite require their profile explicitly.
func WithTenantDataRewriteProfile(profile string) TenantDataRewriteOption {
	return func(options *tenantDataRewriteOptions) { options.profile = strings.TrimSpace(profile) }
}

// ValidateTenantDataRewriteOptions checks the externally supplied proof walls
// without touching JetStream. Served mutations use this before emitting their
// command event so missing backup/audit/signing wiring fails before any state
// change. Transform-specific pair validation is intentionally checked by
// RewriteTenantData; privacy erasure supplies its stricter validator internally.
func ValidateTenantDataRewriteOptions(options ...TenantDataRewriteOption) error {
	opts := parseTenantDataRewriteOptions(options)
	switch {
	case opts.continuity == nil:
		return errors.New("events: tenant data rewrite requires a signed continuity callback")
	case opts.prepare == nil:
		return errors.New("events: tenant data rewrite requires cutover preparation under the backup fence")
	case opts.audit == nil:
		return errors.New("events: tenant data rewrite requires frozen source/target audit continuity")
	default:
		return nil
	}
}

func parseTenantDataRewriteOptions(options []TenantDataRewriteOption) tenantDataRewriteOptions {
	var opts tenantDataRewriteOptions
	for _, option := range options {
		if option != nil {
			option(&opts)
		}
	}
	return opts
}

// HistoryRewriteReady is a side-effect-free served-path preflight. A generation
// rewrite cannot safely start unless both the cross-store history wall and the
// recovery-time signature verifier were installed when the Log was opened.
func (l *Log) HistoryRewriteReady() error {
	switch {
	case l == nil:
		return errors.New("events: history rewrite log is nil")
	case l.history == nil:
		return errors.New("events: history rewrite requires a deployment-wide coordinator")
	case l.continuityVerifier == nil:
		return errors.New("events: history rewrite requires a continuity signature verifier")
	default:
		return nil
	}
}

// TenantDataRewriteReport is the canonical input to the caller's signed receipt.
// Digests are domain-separated SHA-256 chains over sequence-ordered records. No
// plaintext or key material is included.
type TenantDataRewriteReport struct {
	OperationID         string                    `json:"operation_id"`
	Profile             string                    `json:"profile,omitempty"`
	TenantID            string                    `json:"tenant_id"`
	SourceStream        string                    `json:"source_stream"`
	SourceGeneration    string                    `json:"source_generation"`
	TargetStream        string                    `json:"target_stream"`
	TargetGeneration    string                    `json:"target_generation"`
	FirstSequence       uint64                    `json:"first_sequence"`
	SourceCutSequence   uint64                    `json:"source_cut_sequence"`
	ReceiptSequence     uint64                    `json:"receipt_sequence"`
	ChangedEvents       int                       `json:"changed_events"`
	EnvelopeDigest      string                    `json:"envelope_digest"`
	MappingDigest       string                    `json:"mapping_digest"`
	TargetContentDigest string                    `json:"target_content_digest"`
	SourceConfigDigest  string                    `json:"source_config_digest"`
	TargetConfigDigest  string                    `json:"target_config_digest"`
	ArchiveExposure     TenantDataArchiveExposure `json:"archive_exposure"`
	AuditCheckpoint     TenantDataAuditCheckpoint `json:"audit_checkpoint"`
	SourceAuditHead     string                    `json:"source_audit_chain_head"`
	TargetAuditHead     string                    `json:"target_pre_receipt_audit_chain_head"`
	StartedAt           time.Time                 `json:"started_at"`
	CompletedAt         time.Time                 `json:"completed_at"`
}

// TenantDataArchiveExposure records what the generation switch cannot erase.
// Rewriting the live JetStream log never rewrites exports, cold archives, or
// backups that were copied before the cutover.
type TenantDataArchiveExposure string

const (
	TenantDataArchiveExposureExternalCopiesMayRetainSourceBytes TenantDataArchiveExposure = "external_archives_exports_and_backups_may_retain_source_bytes"
)

type rewritePhase string

const (
	rewritePhaseStaging   rewritePhase = "staging"
	rewritePhaseFrozen    rewritePhase = "frozen"
	rewritePhaseReady     rewritePhase = "ready_for_external_preparation"
	rewritePhasePrepared  rewritePhase = "prepared"
	rewritePhaseActivated rewritePhase = "active_pending_scrub"
	rewritePhaseScrubbing rewritePhase = "scrubbing"
	rewritePhaseComplete  rewritePhase = "active"
)

// errRewriteTestCrash is package-private so production callers cannot request a
// deliberately unfinished cutover.
var errRewriteTestCrash = errors.New("events: simulated rewrite crash")

type rewriteStreams struct {
	operation string
	source    *jetstream.StreamInfo
	target    *jetstream.StreamInfo
}

// RewriteTenantData creates a complete replacement generation, freezes the source
// only for its final append delta, activates the verified target, then securely
// removes changed bytes from the frozen source. It never purges or repopulates the
// authoritative stream in place.
func (l *Log) RewriteTenantData(
	ctx context.Context,
	tenantID string,
	transform TenantDataTransform,
	options ...TenantDataRewriteOption,
) (int, error) {
	if tenantID == "" {
		return 0, errors.New("events: tenant data rewrite requires tenant_id (AN-1)")
	}
	if transform == nil {
		return 0, errors.New("events: tenant data rewrite requires transform")
	}
	opts := parseTenantDataRewriteOptions(options)
	if opts.validate == nil {
		return 0, errors.New("events: tenant data rewrite requires an old/new pair validator")
	}
	if err := ValidateTenantDataRewriteOptions(options...); err != nil {
		return 0, err
	}
	if err := l.HistoryRewriteReady(); err != nil {
		return 0, err
	}

	var changed int
	err := l.withRewriteOperation(ctx, func(ctx context.Context) error {
		var err error
		storedTransform := func(before storedEvent) (storedEvent, bool, error) {
			if before.TenantID != tenantID {
				return before, false, nil
			}
			next, changed, err := transform(
				before.Type, normalizedSchemaVersion(before.SchemaVersion),
				append([]byte(nil), before.Data...),
			)
			if err != nil {
				return storedEvent{}, false, err
			}
			if !changed {
				return before, false, nil
			}
			after := before
			after.Data = append([]byte(nil), next...)
			return after, true, nil
		}
		storedValidate := func(before, after storedEvent) error {
			if before.TenantID != tenantID {
				return errors.New("tenant data rewrite changed a non-target tenant")
			}
			if !actorsEqual(before.Actor, after.Actor) {
				return errors.New("tenant data rewrite changed the event actor")
			}
			return opts.validate(
				before.Type, normalizedSchemaVersion(before.SchemaVersion),
				before.Data, after.Data,
			)
		}
		changed, err = l.rewriteStoredGeneration(
			ctx, tenantID, storedTransform, storedValidate, opts,
		)
		return err
	})
	return changed, err
}

// withRewriteOperation is the only entry point for starting a new generation
// rewrite in a live process. A previous attempt may have activated a target and
// then returned an error while scrubbing its source. Recovery therefore happens
// after acquiring the deployment-wide operation lock and under a short exclusive
// cutover before the caller is allowed to create another generation.
func (l *Log) withRewriteOperation(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	return l.withRewriteOperationPolicy(ctx, false, fn)
}

// withBackupRestoreOperation is the single exception to the ordinary rewrite
// floor. It serializes with every generation rewrite but lets the exact artifact
// whose durable binding is already present resume and clear that binding.
func (l *Log) withBackupRestoreOperation(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	return l.withRewriteOperationPolicy(ctx, true, fn)
}

func (l *Log) withRewriteOperationPolicy(
	ctx context.Context,
	allowPendingBackupRestore bool,
	fn func(context.Context) error,
) error {
	return l.withHistoryOperationLock(ctx, func(ctx context.Context) error {
		if !allowPendingBackupRestore {
			if err := l.requireNoPendingBackupRestoreBeforeRecovery(ctx); err != nil {
				return err
			}
		}
		if err := l.recoverUnfinishedRewriteWithCutover(ctx); err != nil {
			return fmt.Errorf("events: recover unfinished rewrite before new operation: %w", err)
		}
		if !allowPendingBackupRestore {
			if err := l.requireNoPendingBackupRestoreForOperation(ctx); err != nil {
				return err
			}
		}
		return fn(ctx)
	})
}

// WithHistoryOperation serializes a multi-step history mutation across replicas.
// The callback may take and release shared history views; nested low-level
// history operations reuse this operation lock instead of deadlocking on the
// deployment-wide coordinator.
func (l *Log) WithHistoryOperation(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	if fn == nil {
		return errors.New("events: history operation callback is required")
	}
	if l.history == nil {
		return errors.New("events: history operation requires a history coordinator")
	}
	return l.withHistoryOperationLock(ctx, func(ctx context.Context) error {
		if err := l.requireNoPendingBackupRestoreBeforeRecovery(ctx); err != nil {
			return err
		}
		if err := l.recoverUnfinishedRewriteWithCutover(ctx); err != nil {
			return fmt.Errorf("events: recover unfinished rewrite before history operation: %w", err)
		}
		if err := l.requireNoPendingBackupRestoreForOperation(ctx); err != nil {
			return err
		}
		return fn(ctx)
	})
}

func (l *Log) requireNoPendingBackupRestoreBeforeRecovery(ctx context.Context) error {
	_, _, found, err := l.pendingBackupRestoreStream(ctx)
	if err != nil {
		return err
	}
	if found {
		return ErrBackupRestoreIncomplete
	}
	return nil
}

// requireNoPendingBackupRestoreForOperation runs while the caller owns the
// deployment-wide history-operation lease. Exact restore owns that same lease,
// so the binding cannot appear between this metadata read and the callback; no
// shared history grant (and no backup-fence lock-order edge) is needed.
func (l *Log) requireNoPendingBackupRestoreForOperation(ctx context.Context) error {
	_, stream, err := l.resolveActiveStream(ctx)
	if err != nil {
		return fmt.Errorf("events: resolve history operation restore state: %w", err)
	}
	return l.requireNoPendingBackupRestoreStream(ctx, stream)
}

func (l *Log) withHistoryOperationLock(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	if token, ok := ctx.Value(historyOperationContextKey{}).(historyOperationToken); ok &&
		token.log == l && token.active != nil && token.active.Load() {
		return fn(ctx)
	}
	return l.history.WithRewriteOperation(ctx, func(ctx context.Context) error {
		active := &atomic.Bool{}
		active.Store(true)
		defer active.Store(false)
		operationCtx := context.WithValue(
			ctx, historyOperationContextKey{}, historyOperationToken{log: l, active: active},
		)
		return fn(operationCtx)
	})
}

// recoverUnfinishedRewriteWithCutover assumes the caller already owns the
// deployment-wide rewrite-operation lock. It takes the exclusive history barrier
// only for the authority decision and any required recovery.
func (l *Log) recoverUnfinishedRewriteWithCutover(ctx context.Context) error {
	return l.history.WithCutover(ctx, func(ctx context.Context) error {
		state, err := l.findRewriteStreams(ctx)
		if err != nil {
			return err
		}
		if state == nil {
			return nil
		}
		return l.recoverRewriteStreams(ctx, *state)
	})
}

func (l *Log) rewriteStoredGeneration(
	ctx context.Context,
	tenantID string,
	transform storedEventTransform,
	validate storedEventPairValidator,
	opts tenantDataRewriteOptions,
) (changed int, retErr error) {
	sourceName, source, err := l.resolveActiveStream(ctx)
	if err != nil {
		return 0, fmt.Errorf("events: resolve rewrite source: %w", err)
	}
	sourceInfo, err := l.infoForStream(ctx, source)
	if err != nil {
		return 0, fmt.Errorf("events: tenant data rewrite source info: %w", err)
	}
	// A durable external preparation is still required when the stream is empty.
	// The caller may need to erase SQL read-model rows, invalidate snapshots, and
	// bind its completion event to the active generation even though no retained
	// history record contains the subject. Let that case take the ordinary no-op
	// path below, which restores the source and prepares against its generation.
	if sourceInfo.State.Msgs == 0 && opts.externalPreparation == nil {
		return 0, nil
	}
	if err := validateRewriteSourceConfig(sourceInfo.Config); err != nil {
		return 0, err
	}

	operationID := nuid.Next()
	targetName := rewriteStreamPrefix + operationID
	sourceGeneration := streamGeneration(sourceInfo)
	sourceRestore, err := encodeRewriteSourceRestore(sourceInfo.Config)
	if err != nil {
		return 0, fmt.Errorf("events: encode rewrite source restore point: %w", err)
	}
	configHash, err := rewriteBaseConfigDigest(sourceInfo.Config)
	if err != nil {
		return 0, fmt.Errorf("events: digest rewrite source config: %w", err)
	}
	startedAt := time.Now().UTC()

	sourceCfg := cloneStreamConfig(sourceInfo.Config)
	sourceCfg.Metadata = rewriteMetadata(
		sourceCfg.Metadata, operationID, rewriteRoleSource, rewritePhaseStaging,
		sourceName, targetName, tenantID, sourceGeneration,
	)
	sourceCfg.Metadata[rewriteMetadataConfigHash] = configHash
	sourceCfg.Metadata[rewriteMetadataRestore] = sourceRestore
	sourceCfg.Metadata[rewriteMetadataRestoreSum] = crypto.SHA256Hex([]byte(sourceRestore))
	source, err = l.js.UpdateStream(ctx, sourceCfg)
	if err != nil {
		return 0, fmt.Errorf("events: mark rewrite source: %w", err)
	}

	targetCfg := cloneStreamConfig(sourceInfo.Config)
	targetCfg.Name = targetName
	targetCfg.Description = "trstctl event-log rewrite generation " + operationID
	targetCfg.Subjects = []string{rewriteStagingFilter(operationID)}
	targetCfg.SubjectTransform = &jetstream.SubjectTransformConfig{
		Source: rewriteStagingFilter(operationID), Destination: subjectFilter,
	}
	targetCfg.FirstSeq = sourceInfo.State.FirstSeq
	targetCfg.Metadata = rewriteMetadata(
		rewriteTargetMetadata(sourceInfo.Config.Metadata),
		operationID, rewriteRoleTarget, rewritePhaseStaging,
		sourceName, targetName, tenantID, operationID,
	)
	targetCfg.Metadata[rewriteMetadataConfigHash] = configHash
	targetCfg.Metadata[rewriteMetadataRestore] = sourceRestore
	targetCfg.Metadata[rewriteMetadataRestoreSum] = crypto.SHA256Hex([]byte(sourceRestore))
	var target jetstream.Stream
	if l.createRewriteTargetTestHook != nil {
		err = l.createRewriteTargetTestHook()
	} else {
		target, err = l.js.CreateStream(ctx, targetCfg)
	}
	if err != nil {
		createErr := fmt.Errorf("events: create rewrite target: %w", err)
		if restoreErr := l.restoreSourceAndDiscardTarget(
			context.Background(), sourceName, targetName,
		); restoreErr != nil {
			return 0, errors.Join(
				createErr,
				fmt.Errorf("events: restore source after target-create failure: %w", restoreErr),
			)
		}
		return 0, createErr
	}

	activated := false
	externallyPrepared := false
	sourceRestored := false
	cleanupBeforeActivation := func(cause error) error {
		if errors.Is(cause, errRewriteTestCrash) {
			return cause
		}
		if activated || externallyPrepared || sourceRestored {
			return cause
		}
		restoreErr := l.restoreSourceAndDiscardTarget(context.Background(), sourceName, targetName)
		if restoreErr != nil {
			return errors.Join(cause, fmt.Errorf("events: rollback rewrite source: %w", restoreErr))
		}
		return cause
	}

	first := sourceInfo.State.FirstSeq
	if first == 0 {
		first = 1
	}
	if _, err := l.copyRewriteRange(ctx, source, target, operationID, first, sourceInfo.State.LastSeq, transform, validate); err != nil {
		return 0, cleanupBeforeActivation(err)
	}
	if err := l.callRewriteTestHook(rewritePhaseStaging); err != nil {
		return 0, cleanupBeforeActivation(err)
	}

	err = l.history.WithCutover(ctx, func(ctx context.Context) error {
		frozenCfg := cloneStreamConfig(sourceCfg)
		frozenCfg.Subjects = []string{rewriteFrozenFilter(operationID)}
		frozenCfg.SubjectTransform = nil
		frozenCfg.Metadata = rewriteMetadata(
			frozenCfg.Metadata, operationID, rewriteRoleSource, rewritePhaseFrozen,
			sourceName, targetName, tenantID, sourceGeneration,
		)
		source, err = l.js.UpdateStream(ctx, frozenCfg)
		if err != nil {
			return fmt.Errorf("events: freeze rewrite source: %w", err)
		}
		if err := l.callRewriteTestHook(rewritePhaseFrozen); err != nil {
			return err
		}

		finalInfo, err := l.infoForStream(ctx, source)
		if err != nil {
			return fmt.Errorf("events: frozen source info: %w", err)
		}
		if finalInfo.State.LastSeq > sourceInfo.State.LastSeq {
			if _, err := l.copyRewriteRange(
				ctx, source, target, operationID,
				sourceInfo.State.LastSeq+1, finalInfo.State.LastSeq,
				transform, validate,
			); err != nil {
				return err
			}
		}

		report, err := l.reconcileAndReport(
			ctx, source, target, operationID, tenantID, sourceGeneration,
			first, finalInfo.State.LastSeq, startedAt, validate, transform,
		)
		if err != nil {
			return err
		}
		report.Profile = opts.profile
		changed = report.ChangedEvents
		if report.ChangedEvents == 0 {
			proceeded := false
			err = opts.prepare(
				tenantDataCutoverPreparationContext(ctx, opts),
				report,
				func(ctx context.Context) error {
					if proceeded {
						return errors.New("events: no-op cutover preparation invoked completion more than once")
					}
					proceeded = true
					if err := l.restoreSourceAndDiscardTarget(ctx, sourceName, targetName); err != nil {
						return fmt.Errorf("events: restore no-op rewrite source: %w", err)
					}
					sourceRestored = true
					if opts.externalPreparation == nil {
						return nil
					}
					// The staged target is intentionally discarded because no retained
					// source record contained the subject. Bind the SQL marker to the
					// still-authoritative source generation so startup can prove that
					// history did not move before publishing deterministic completion.
					report.TargetStream = sourceName
					report.TargetGeneration = sourceGeneration
					if err := opts.externalPreparation(ctx, report); err != nil {
						return fmt.Errorf("events: external no-op rewrite preparation: %w", err)
					}
					externallyPrepared = true
					return nil
				},
			)
			if err != nil {
				return fmt.Errorf("events: prepare no-op rewrite completion: %w", err)
			}
			if !proceeded {
				return errors.New("events: no-op cutover preparation returned without invalidating snapshots and invoking completion")
			}
			return nil
		}
		proceeded := false
		err = opts.prepare(
			tenantDataCutoverPreparationContext(ctx, opts),
			report,
			func(ctx context.Context) error {
				if proceeded {
					return errors.New("events: cutover preparation invoked activation more than once")
				}
				proceeded = true
				auditView := TenantDataAuditView{
					Report: report, source: source, target: target,
				}
				checkpoint, err := opts.audit(ctx, auditView)
				if err != nil {
					return fmt.Errorf("events: read frozen audit checkpoint seed: %w", err)
				}
				auditEvidence, err := deriveAuditContinuity(ctx, auditView, checkpoint)
				if err != nil {
					return fmt.Errorf("events: compute frozen audit continuity: %w", err)
				}
				if err := validateAuditContinuity(report, auditEvidence); err != nil {
					return err
				}
				report.AuditCheckpoint = auditEvidence.Checkpoint
				report.SourceAuditHead = auditEvidence.SourcePreCutChainHead
				report.TargetAuditHead = auditEvidence.TargetPreReceiptHead

				receipt, err := opts.continuity(ctx, report)
				if err != nil {
					return fmt.Errorf("events: create signed rewrite continuity: %w", err)
				}
				receiptSum, err := l.appendRewriteReceipt(ctx, target, operationID, report, receipt)
				if err != nil {
					return err
				}
				evidence := TenantDataContinuityEvidence{
					OperationID: operationID, TenantID: tenantID,
					SourceStream: sourceName, TargetStream: targetName,
					ReceiptSequence: report.ReceiptSequence, Receipt: receipt, Report: report,
				}
				if err := l.continuityVerifier(ctx, evidence); err != nil {
					return fmt.Errorf("events: verify signed rewrite continuity: %w", err)
				}

				targetInfo, err := l.infoForStream(ctx, target)
				if err != nil {
					return fmt.Errorf("events: rewrite target info before activation: %w", err)
				}
				proofCfg := cloneStreamConfig(targetInfo.Config)
				proofCfg.Metadata = rewriteMetadata(
					proofCfg.Metadata, operationID, rewriteRoleTarget, rewritePhaseStaging,
					sourceName, targetName, tenantID, operationID,
				)
				proofCfg.Metadata[rewriteMetadataReceiptSeq] = strconv.FormatUint(report.ReceiptSequence, 10)
				proofCfg.Metadata[rewriteMetadataReceiptID] = receipt.ID
				proofCfg.Metadata[rewriteMetadataReceiptSum] = receiptSum
				reportPayload, err := json.Marshal(report)
				if err != nil {
					return fmt.Errorf("events: encode rewrite report metadata: %w", err)
				}
				proofCfg.Metadata[rewriteMetadataReport] = base64.RawStdEncoding.EncodeToString(reportPayload)
				proofCfg.Metadata[rewriteMetadataReportSum] = crypto.SHA256Hex(reportPayload)

				if opts.externalPreparation != nil {
					proofCfg.Metadata[rewriteMetadataPhase] = string(rewritePhaseReady)
					proofCfg.Metadata[rewriteMetadataExternalPreparation] = opts.externalKind
					target, err = l.js.UpdateStream(ctx, proofCfg)
					if err != nil {
						return fmt.Errorf("events: persist externally preparable rewrite target: %w", err)
					}
					preparationErr := l.withFrozenGenerationReadView(
						ctx, sourceName, source,
						func(preparationCtx context.Context) error {
							return opts.externalPreparation(preparationCtx, report)
						},
					)
					if preparationErr != nil {
						resolver, ok := l.history.(HistoryRewritePreparationResolver)
						if !ok {
							// Without the independent authority store we cannot distinguish
							// a validation failure from a committed transaction whose ACK was
							// lost. Preserve the target; only an authoritative false below is
							// permission to roll it back.
							externallyPrepared = true
							return fmt.Errorf("events: external rewrite preparation: %w", preparationErr)
						}
						active, resolveErr := resolver.HistoryRewritePreparationActive(
							ctx, tenantID, report.TargetGeneration,
						)
						if resolveErr != nil {
							// A commit acknowledgment can be lost. If PostgreSQL cannot
							// prove the transaction absent, preserve the signed target;
							// deleting it could strand an already-committed marker.
							externallyPrepared = true
							return errors.Join(
								fmt.Errorf("events: external rewrite preparation: %w", preparationErr),
								fmt.Errorf("events: resolve ambiguous external preparation: %w", resolveErr),
							)
						}
						if active {
							externallyPrepared = true
						}
						return fmt.Errorf("events: external rewrite preparation: %w", preparationErr)
					}
					externallyPrepared = true
					// This hook is deliberately after the independent SQL commit and
					// before the target advertises "prepared". Both an ordinary error
					// and a simulated process crash must leave the ready target intact.
					if err := l.callRewriteTestHook(rewritePhasePrepared); err != nil {
						return err
					}
					proofCfg.Metadata[rewriteMetadataPhase] = string(rewritePhasePrepared)
					target, err = l.js.UpdateStream(ctx, proofCfg)
					if err != nil {
						return fmt.Errorf("events: mark externally prepared rewrite target: %w", err)
					}
				}

				activeCfg := cloneStreamConfig(proofCfg)
				activeCfg.Subjects = []string{subjectFilter}
				activeCfg.SubjectTransform = nil
				activeCfg.Metadata = rewriteMetadata(
					activeCfg.Metadata, operationID, rewriteRoleTarget, rewritePhaseActivated,
					sourceName, targetName, tenantID, operationID,
				)
				target, err = l.js.UpdateStream(ctx, activeCfg)
				if err != nil {
					return fmt.Errorf("events: activate rewrite target: %w", err)
				}
				activated = true
				l.setActiveStreamNamed(targetName, target)
				if err := l.callRewriteTestHook(rewritePhaseActivated); err != nil {
					return err
				}
				if err := l.scrubAndDeleteSource(ctx, source, target); err != nil {
					return fmt.Errorf("events: scrub frozen rewrite source: %w", err)
				}
				if err := l.clearRewriteMetadata(ctx, target); err != nil {
					return fmt.Errorf("events: clear activated rewrite metadata: %w", err)
				}
				return l.callRewriteTestHook(rewritePhaseComplete)
			},
		)
		if err != nil {
			return fmt.Errorf("events: prepare rewrite cutover: %w", err)
		}
		if !proceeded {
			return errors.New("events: cutover preparation returned without invalidating snapshots and invoking activation")
		}
		return nil
	})
	if err != nil {
		return changed, cleanupBeforeActivation(err)
	}
	return changed, nil
}

func validateRewriteSourceConfig(cfg jetstream.StreamConfig) error {
	switch {
	case cfg.Sealed:
		return errors.New("events: cannot rewrite a sealed source stream")
	case cfg.DenyDelete:
		return errors.New("events: cannot securely scrub a source stream with deny-delete enabled")
	case cfg.DenyPurge:
		return errors.New("events: cannot remove a rewritten source stream with deny-purge enabled")
	case cfg.Mirror != nil || len(cfg.Sources) != 0:
		return errors.New("events: source/mirror event streams are unsupported for an in-place authority switch")
	case cfg.RePublish != nil:
		return errors.New("events: republishing event streams are unsupported for a generation rewrite")
	default:
		return nil
	}
}

func (l *Log) copyRewriteRange(
	ctx context.Context,
	source, target jetstream.Stream,
	operationID string,
	first, last uint64,
	transform storedEventTransform,
	validate storedEventPairValidator,
) (int, error) {
	if last < first {
		return 0, nil
	}
	changed := 0
	for seq := first; seq <= last; seq++ {
		sourceRaw, err := source.GetMsg(ctx, seq)
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			if err := l.ensureRewriteGap(ctx, target, operationID, seq); err != nil {
				return 0, err
			}
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("events: read rewrite source seq %d: %w", seq, err)
		}
		wasChanged, err := l.copyRewriteMessage(
			ctx, target, operationID, sourceRaw, transform, validate,
		)
		if err != nil {
			return 0, err
		}
		if wasChanged {
			changed++
		}
	}
	return changed, nil
}

func (l *Log) copyRewriteMessage(
	ctx context.Context,
	target jetstream.Stream,
	operationID string,
	sourceRaw *jetstream.RawStreamMsg,
	transform storedEventTransform,
	validate storedEventPairValidator,
) (bool, error) {
	if existing, err := target.GetMsg(ctx, sourceRaw.Sequence); err == nil {
		return validateRewritePair(sourceRaw, existing, validate)
	} else if !errors.Is(err, jetstream.ErrMsgNotFound) {
		return false, fmt.Errorf("events: read staged seq %d: %w", sourceRaw.Sequence, err)
	}

	var sourceEvent storedEvent
	if err := json.Unmarshal(sourceRaw.Data, &sourceEvent); err != nil {
		return false, fmt.Errorf("events: decode rewrite source seq %d: %w", sourceRaw.Sequence, err)
	}
	targetEvent, changed, err := transform(sourceEvent)
	if err != nil {
		return false, fmt.Errorf("events: transform event %q: %w", sourceEvent.ID, err)
	}
	targetData := sourceRaw.Data
	if changed {
		if err := validate(sourceEvent, targetEvent); err != nil {
			return false, fmt.Errorf("events: validate transformed event %q: %w", sourceEvent.ID, err)
		}
		if actorsEqual(sourceEvent.Actor, targetEvent.Actor) {
			targetData, err = RewriteStoredEnvelopeDataExact(
				sourceRaw.Data, sourceEvent.Data, targetEvent.Data,
			)
		} else {
			// Subject erasure may intentionally change both actor and data. AUD-116's
			// scheduler profile never changes actor, so it always takes the exact
			// one-token branch above.
			targetData, err = json.Marshal(targetEvent)
		}
		if err != nil {
			return false, fmt.Errorf("events: rewrite transformed event %q envelope: %w", sourceEvent.ID, err)
		}
	}

	publishOpts := []jetstream.PublishOpt{
		jetstream.WithExpectStream(target.CachedInfo().Config.Name),
		jetstream.WithExpectLastSequence(sourceRaw.Sequence - 1),
		jetstream.WithMsgID(sourceEvent.ID),
	}
	ack, err := l.js.Publish(
		ctx, rewriteStagingSubject(operationID, sourceRaw.Subject), targetData, publishOpts...,
	)
	if err != nil {
		if existing, getErr := target.GetMsg(ctx, sourceRaw.Sequence); getErr == nil {
			return validateRewritePair(sourceRaw, existing, validate)
		}
		return false, fmt.Errorf("events: stage rewrite seq %d: %w", sourceRaw.Sequence, err)
	}
	if ack.Sequence != sourceRaw.Sequence {
		return false, fmt.Errorf("events: staged source seq %d at target seq %d", sourceRaw.Sequence, ack.Sequence)
	}
	return changed, nil
}

func (l *Log) ensureRewriteGap(ctx context.Context, target jetstream.Stream, operationID string, seq uint64) error {
	if _, err := target.GetMsg(ctx, seq); err == nil {
		if err := target.SecureDeleteMsg(ctx, seq); err != nil {
			return fmt.Errorf("events: reconcile target gap %d: %w", seq, err)
		}
		return nil
	} else if !errors.Is(err, jetstream.ErrMsgNotFound) {
		return fmt.Errorf("events: inspect target gap %d: %w", seq, err)
	}
	info, err := l.infoForStream(ctx, target)
	if err != nil {
		return fmt.Errorf("events: target info for gap %d: %w", seq, err)
	}
	if info.State.LastSeq >= seq {
		return nil
	}
	if info.State.LastSeq+1 != seq {
		return fmt.Errorf("events: target head %d cannot create source gap %d", info.State.LastSeq, seq)
	}
	ack, err := l.js.Publish(
		ctx,
		rewriteStagingSubject(operationID, "events.__rewrite_gap"),
		[]byte(`{"trstctl_rewrite_gap":true}`),
		jetstream.WithExpectStream(info.Config.Name),
		jetstream.WithExpectLastSequence(seq-1),
	)
	if err != nil {
		return fmt.Errorf("events: stage gap %d: %w", seq, err)
	}
	if ack.Sequence != seq {
		return fmt.Errorf("events: staged gap %d at target seq %d", seq, ack.Sequence)
	}
	if err := target.SecureDeleteMsg(ctx, seq); err != nil {
		return fmt.Errorf("events: secure-delete staged gap %d: %w", seq, err)
	}
	return nil
}

func (l *Log) reconcileAndReport(
	ctx context.Context,
	source, target jetstream.Stream,
	operationID, tenantID, sourceGeneration string,
	first, last uint64,
	startedAt time.Time,
	validate storedEventPairValidator,
	transform storedEventTransform,
) (TenantDataRewriteReport, error) {
	envelopeDigest := crypto.SHA256Hex([]byte("trstctl.event-rewrite.envelopes.v1"))
	mappingDigest := crypto.SHA256Hex([]byte("trstctl.event-rewrite.mapping.v1"))
	targetContentDigest := crypto.SHA256Hex([]byte("trstctl.event-rewrite.target-content.v1"))
	changed := 0
	for seq := first; seq <= last; seq++ {
		sourceRaw, sourceErr := source.GetMsg(ctx, seq)
		targetRaw, targetErr := target.GetMsg(ctx, seq)
		if errors.Is(sourceErr, jetstream.ErrMsgNotFound) {
			if err := l.ensureRewriteGap(ctx, target, operationID, seq); err != nil {
				return TenantDataRewriteReport{}, err
			}
			envelopeDigest = digestChain(envelopeDigest, struct {
				Sequence uint64 `json:"sequence"`
				Gap      bool   `json:"gap"`
			}{Sequence: seq, Gap: true})
			targetContentDigest = digestChain(targetContentDigest, struct {
				Sequence uint64 `json:"sequence"`
				Gap      bool   `json:"gap"`
			}{Sequence: seq, Gap: true})
			continue
		}
		if sourceErr != nil {
			return TenantDataRewriteReport{}, fmt.Errorf("events: reconcile source seq %d: %w", seq, sourceErr)
		}
		if errors.Is(targetErr, jetstream.ErrMsgNotFound) {
			if _, err := l.copyRewriteMessage(ctx, target, operationID, sourceRaw, transform, validate); err != nil {
				return TenantDataRewriteReport{}, err
			}
			targetRaw, targetErr = target.GetMsg(ctx, seq)
		}
		if targetErr != nil {
			return TenantDataRewriteReport{}, fmt.Errorf("events: reconcile target seq %d: %w", seq, targetErr)
		}
		wasChanged, err := validateRewritePair(sourceRaw, targetRaw, validate)
		if err != nil {
			return TenantDataRewriteReport{}, err
		}
		invariant, err := rewriteInvariantFor(sourceRaw)
		if err != nil {
			return TenantDataRewriteReport{}, err
		}
		envelopeDigest = digestChain(envelopeDigest, invariant)
		targetContentDigest = digestTargetContent(targetContentDigest, targetRaw)
		if wasChanged {
			var before, after storedEvent
			if err := json.Unmarshal(sourceRaw.Data, &before); err != nil {
				return TenantDataRewriteReport{}, err
			}
			if err := json.Unmarshal(targetRaw.Data, &after); err != nil {
				return TenantDataRewriteReport{}, err
			}
			mappingDigest = digestChain(mappingDigest, struct {
				Sequence uint64 `json:"sequence"`
				EventID  string `json:"event_id"`
				Before   string `json:"before_sha256"`
				After    string `json:"after_sha256"`
			}{
				Sequence: seq, EventID: before.ID,
				Before: crypto.SHA256Hex(sourceRaw.Data), After: crypto.SHA256Hex(targetRaw.Data),
			},
			)
			changed++
		}
	}
	sourceInfo, err := l.infoForStream(ctx, source)
	if err != nil {
		return TenantDataRewriteReport{}, fmt.Errorf("events: read frozen source config: %w", err)
	}
	targetInfo, err := l.infoForStream(ctx, target)
	if err != nil {
		return TenantDataRewriteReport{}, fmt.Errorf("events: read staged target config: %w", err)
	}
	sourceConfigDigest, err := rewriteAuthorizedConfigDigest(sourceInfo.Config)
	if err != nil {
		return TenantDataRewriteReport{}, fmt.Errorf("events: digest frozen source config: %w", err)
	}
	targetConfigDigest, err := rewriteAuthorizedConfigDigest(targetInfo.Config)
	if err != nil {
		return TenantDataRewriteReport{}, fmt.Errorf("events: digest staged target config: %w", err)
	}
	targetName := targetInfo.Config.Name
	return TenantDataRewriteReport{
		OperationID: operationID, TenantID: tenantID,
		SourceStream: sourceInfo.Config.Name, SourceGeneration: sourceGeneration,
		TargetStream: targetName, TargetGeneration: operationID,
		FirstSequence: first, SourceCutSequence: last, ReceiptSequence: last + 1,
		ChangedEvents: changed, EnvelopeDigest: envelopeDigest, MappingDigest: mappingDigest,
		TargetContentDigest: targetContentDigest,
		SourceConfigDigest:  sourceConfigDigest, TargetConfigDigest: targetConfigDigest,
		ArchiveExposure: TenantDataArchiveExposureExternalCopiesMayRetainSourceBytes,
		StartedAt:       startedAt, CompletedAt: time.Now().UTC(),
	}, nil
}

type rewriteInvariant struct {
	Sequence      uint64 `json:"sequence"`
	Subject       string `json:"subject"`
	MessageID     string `json:"message_id"`
	ID            string `json:"id"`
	Type          string `json:"type"`
	TenantID      string `json:"tenant_id"`
	Time          string `json:"time"`
	SchemaVersion int    `json:"schema_version"`
}

func rewriteInvariantFor(raw *jetstream.RawStreamMsg) (rewriteInvariant, error) {
	var event storedEvent
	if err := json.Unmarshal(raw.Data, &event); err != nil {
		return rewriteInvariant{}, fmt.Errorf("events: decode rewrite invariant seq %d: %w", raw.Sequence, err)
	}
	messageIDs := raw.Header.Values(jetstream.MsgIDHeader)
	if len(messageIDs) != 1 || strings.TrimSpace(messageIDs[0]) == "" {
		return rewriteInvariant{}, fmt.Errorf(
			"events: rewrite source seq %d lacks one canonical %s header",
			raw.Sequence, jetstream.MsgIDHeader,
		)
	}
	if messageIDs[0] != event.ID {
		return rewriteInvariant{}, fmt.Errorf(
			"events: rewrite source seq %d %s %q does not match event id %q",
			raw.Sequence, jetstream.MsgIDHeader, messageIDs[0], event.ID,
		)
	}
	return rewriteInvariant{
		Sequence: raw.Sequence, Subject: raw.Subject, MessageID: messageIDs[0],
		ID: event.ID, Type: event.Type,
		TenantID: event.TenantID, Time: event.Time.UTC().Format(time.RFC3339Nano),
		SchemaVersion: normalizedSchemaVersion(event.SchemaVersion),
	}, nil
}

func validateRewritePair(
	sourceRaw, targetRaw *jetstream.RawStreamMsg,
	validate storedEventPairValidator,
) (bool, error) {
	beforeInvariant, err := rewriteInvariantFor(sourceRaw)
	if err != nil {
		return false, err
	}
	afterInvariant, err := rewriteInvariantFor(targetRaw)
	if err != nil {
		return false, err
	}
	beforeCanonical, beforeErr := json.Marshal(beforeInvariant)
	afterCanonical, afterErr := json.Marshal(afterInvariant)
	if beforeErr != nil || afterErr != nil {
		return false, errors.Join(beforeErr, afterErr)
	}
	if !bytes.Equal(beforeCanonical, afterCanonical) {
		return false, fmt.Errorf(
			"events: rewrite changed immutable envelope at seq %d: before=%+v after=%+v",
			sourceRaw.Sequence, beforeInvariant, afterInvariant,
		)
	}
	if bytes.Equal(sourceRaw.Data, targetRaw.Data) {
		return false, nil
	}
	var before, after storedEvent
	if err := json.Unmarshal(sourceRaw.Data, &before); err != nil {
		return false, err
	}
	if err := json.Unmarshal(targetRaw.Data, &after); err != nil {
		return false, err
	}
	if err := validate(before, after); err != nil {
		return false, fmt.Errorf("events: validate staged pair event %q: %w", before.ID, err)
	}
	if actorsEqual(before.Actor, after.Actor) {
		exact, err := RewriteStoredEnvelopeDataExact(sourceRaw.Data, before.Data, after.Data)
		if err != nil {
			return false, fmt.Errorf("events: reconstruct exact staged pair event %q: %w", before.ID, err)
		}
		if !bytes.Equal(exact, targetRaw.Data) {
			return false, fmt.Errorf(
				"events: rewrite changed bytes outside data token at seq %d",
				sourceRaw.Sequence,
			)
		}
	}
	return true, nil
}

func actorsEqual(before, after *Actor) bool {
	beforeCanonical, beforeErr := json.Marshal(before)
	afterCanonical, afterErr := json.Marshal(after)
	return beforeErr == nil && afterErr == nil && bytes.Equal(beforeCanonical, afterCanonical)
}

func digestChain(previous string, value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	framed := previous + "\x00" + strconv.Itoa(len(payload)) + "\x00" + string(payload)
	return crypto.SHA256Hex([]byte(framed))
}

func digestTargetContent(previous string, raw *jetstream.RawStreamMsg) string {
	return digestChain(previous, struct {
		Sequence uint64 `json:"sequence"`
		Subject  string `json:"subject"`
		Data     []byte `json:"data"`
	}{
		Sequence: raw.Sequence,
		Subject:  raw.Subject,
		Data:     raw.Data,
	})
}

func validateAuditContinuity(report TenantDataRewriteReport, evidence TenantDataAuditContinuity) error {
	if strings.TrimSpace(evidence.Checkpoint.IdentityDigest) == "" {
		return errors.New("events: audit continuity requires a retention checkpoint/genesis identity digest")
	}
	if report.ChangedEvents > 0 &&
		(strings.TrimSpace(evidence.SourcePreCutChainHead) == "" ||
			strings.TrimSpace(evidence.TargetPreReceiptHead) == "") {
		return errors.New("events: audit continuity requires old and new pre-receipt chain heads")
	}
	return nil
}

func deriveAuditContinuity(
	ctx context.Context,
	view TenantDataAuditView,
	checkpoint TenantDataAuditCheckpoint,
) (TenantDataAuditContinuity, error) {
	sourceRecords, err := auditRecordsForGeneration(
		ctx, view.source, view.Report.TenantID, view.Report.SourceCutSequence, checkpoint,
	)
	if err != nil {
		return TenantDataAuditContinuity{}, err
	}
	targetRecords, err := auditRecordsForGeneration(
		ctx, view.target, view.Report.TenantID, view.Report.SourceCutSequence, checkpoint,
	)
	if err != nil {
		return TenantDataAuditContinuity{}, err
	}
	if len(sourceRecords) != len(targetRecords) {
		return TenantDataAuditContinuity{}, fmt.Errorf(
			"events: audit record count differs across rewrite: source=%d target=%d",
			len(sourceRecords), len(targetRecords),
		)
	}
	return TenantDataAuditContinuity{
		Checkpoint:            checkpoint,
		SourcePreCutChainHead: auditchain.SealFrom(checkpoint.BoundaryHash, sourceRecords),
		TargetPreReceiptHead:  auditchain.SealFrom(checkpoint.BoundaryHash, targetRecords),
	}, nil
}

func auditRecordsForGeneration(
	ctx context.Context,
	stream jetstream.Stream,
	tenantID string,
	last uint64,
	checkpoint TenantDataAuditCheckpoint,
) ([]auditchain.Record, error) {
	first := checkpoint.BoundarySequence + 1
	if first == 0 {
		first = 1
	}
	records := make([]auditchain.Record, 0)
	ordinal := checkpoint.RecordCount
	for seq := first; seq <= last; seq++ {
		raw, err := stream.GetMsg(ctx, seq)
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("events: read audit generation seq %d: %w", seq, err)
		}
		event, err := decodeStored(raw.Data, raw.Sequence)
		if err != nil {
			return nil, err
		}
		if event.TenantID != tenantID {
			continue
		}
		ordinal++
		records = append(records, auditchain.Record{
			Sequence: ordinal, StreamSequence: event.Sequence,
			ID: event.ID, Type: event.Type, TenantID: event.TenantID,
			Time: event.Time, Actor: event.Actor, Data: json.RawMessage(event.Data),
		})
	}
	return records, nil
}

func replayStreamThrough(
	ctx context.Context,
	stream jetstream.Stream,
	last uint64,
	fn func(Event) error,
) error {
	info := stream.CachedInfo()
	first := uint64(1)
	if info != nil && info.State.FirstSeq != 0 {
		first = info.State.FirstSeq
	}
	for seq := first; seq <= last; seq++ {
		raw, err := stream.GetMsg(ctx, seq)
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("events: replay pinned generation seq %d: %w", seq, err)
		}
		event, err := decodeStored(raw.Data, raw.Sequence)
		if err != nil {
			return err
		}
		if err := fn(event); err != nil {
			return err
		}
	}
	return nil
}

func (l *Log) appendRewriteReceipt(
	ctx context.Context,
	target jetstream.Stream,
	operationID string,
	report TenantDataRewriteReport,
	receipt Event,
) (string, error) {
	if receipt.ID == "" || receipt.Type == "" || receipt.TenantID != report.TenantID || receipt.Time.IsZero() {
		return "", errors.New("events: signed rewrite continuity must return an id, type, matching tenant, and time")
	}
	if receipt.SchemaVersion == 0 {
		receipt.SchemaVersion = DefaultSchemaVersion
	}
	payload, err := json.Marshal(storedEvent{
		ID: receipt.ID, Type: receipt.Type, TenantID: receipt.TenantID, Time: receipt.Time,
		SchemaVersion: receipt.SchemaVersion, Data: receipt.Data, Actor: receipt.Actor,
	})
	if err != nil {
		return "", fmt.Errorf("events: marshal rewrite continuity: %w", err)
	}
	subject, err := tenancy.EventSubject(ctx, receipt.TenantID, subjectPrefix, receipt.Type)
	if err != nil {
		return "", err
	}
	ack, err := l.js.Publish(
		ctx, rewriteStagingSubject(operationID, subject), payload,
		jetstream.WithExpectStream(report.TargetStream),
		jetstream.WithExpectLastSequence(report.ReceiptSequence-1),
		jetstream.WithMsgID(receipt.ID),
	)
	if err != nil {
		return "", fmt.Errorf("events: persist signed rewrite continuity: %w", err)
	}
	if ack.Sequence != report.ReceiptSequence {
		return "", fmt.Errorf(
			"events: rewrite continuity sequence = %d, want %d",
			ack.Sequence, report.ReceiptSequence,
		)
	}
	return crypto.SHA256Hex(payload), nil
}

func rewriteStagingFilter(operationID string) string {
	return "__trstctl_rewrite." + operationID + ".events.>"
}

func rewriteStagingSubject(operationID, original string) string {
	return "__trstctl_rewrite." + operationID + "." + original
}

func rewriteFrozenFilter(operationID string) string {
	return "__trstctl_frozen." + operationID + ".>"
}

func rewriteMetadata(
	current map[string]string,
	operationID, role string,
	phase rewritePhase,
	source, target, tenantID, generation string,
) map[string]string {
	metadata := make(map[string]string, len(current)+7)
	for key, value := range current {
		metadata[key] = value
	}
	metadata[rewriteMetadataOperation] = operationID
	metadata[rewriteMetadataRole] = role
	metadata[rewriteMetadataPhase] = string(phase)
	metadata[rewriteMetadataSource] = source
	metadata[rewriteMetadataTarget] = target
	metadata[rewriteMetadataTenant] = tenantID
	metadata[rewriteMetadataGeneration] = generation
	return metadata
}

func cloneStreamConfig(cfg jetstream.StreamConfig) jetstream.StreamConfig {
	clone := cfg
	clone.Subjects = append([]string(nil), cfg.Subjects...)
	clone.Metadata = make(map[string]string, len(cfg.Metadata))
	for key, value := range cfg.Metadata {
		clone.Metadata[key] = value
	}
	return clone
}

type rewriteSourceRestore struct {
	Subjects         []string                          `json:"subjects"`
	SubjectTransform *jetstream.SubjectTransformConfig `json:"subject_transform,omitempty"`
	Metadata         map[string]string                 `json:"metadata,omitempty"`
	MetadataWasNil   bool                              `json:"metadata_was_nil,omitempty"`
}

func encodeRewriteSourceRestore(cfg jetstream.StreamConfig) (string, error) {
	restore := rewriteSourceRestore{
		Subjects:       append([]string(nil), cfg.Subjects...),
		MetadataWasNil: cfg.Metadata == nil,
	}
	if cfg.Metadata != nil {
		restore.Metadata = make(map[string]string, len(cfg.Metadata))
	}
	if cfg.SubjectTransform != nil {
		transform := *cfg.SubjectTransform
		restore.SubjectTransform = &transform
	}
	for key, value := range cfg.Metadata {
		restore.Metadata[key] = value
	}
	payload, err := json.Marshal(restore)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(payload), nil
}

func decodeRewriteSourceRestore(encoded string) (rewriteSourceRestore, error) {
	if encoded == "" {
		return rewriteSourceRestore{}, errors.New("events: rewrite source lacks its exact restore point")
	}
	payload, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return rewriteSourceRestore{}, errors.New("events: rewrite source restore point is not valid base64")
	}
	var restore rewriteSourceRestore
	if err := json.Unmarshal(payload, &restore); err != nil {
		return rewriteSourceRestore{}, fmt.Errorf("events: decode rewrite source restore point: %w", err)
	}
	if len(restore.Subjects) == 0 {
		return rewriteSourceRestore{}, errors.New("events: rewrite source restore point has no subjects")
	}
	return restore, nil
}

func rewriteTargetMetadata(current map[string]string) map[string]string {
	metadata := make(map[string]string, len(current))
	for key, value := range current {
		if strings.HasPrefix(key, "trstctl.rewrite.") ||
			key == rewriteMetadataGeneration ||
			strings.HasPrefix(key, "_nats.") {
			continue
		}
		metadata[key] = value
	}
	return metadata
}

func rewriteBaseConfigDigest(cfg jetstream.StreamConfig) (string, error) {
	base := cloneStreamConfig(cfg)
	deleteServerManagedMetadata(base.Metadata)
	base.Name = ""
	base.Description = ""
	base.Subjects = nil
	base.SubjectTransform = nil
	base.FirstSeq = 0
	for key := range base.Metadata {
		if strings.HasPrefix(key, "trstctl.rewrite.") || key == rewriteMetadataGeneration {
			delete(base.Metadata, key)
		}
	}
	if len(base.Metadata) == 0 {
		base.Metadata = nil
	}
	payload, err := json.Marshal(base)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(payload), nil
}

func rewriteAuthorizedConfigDigest(cfg jetstream.StreamConfig) (string, error) {
	canonical := cloneStreamConfig(cfg)
	deleteServerManagedMetadata(canonical.Metadata)
	payload, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(payload), nil
}

func deleteServerManagedMetadata(metadata map[string]string) {
	for key := range metadata {
		if strings.HasPrefix(key, "_nats.") {
			delete(metadata, key)
		}
	}
}

func streamGeneration(info *jetstream.StreamInfo) string {
	if info != nil && info.Config.Metadata != nil {
		if generation := info.Config.Metadata[rewriteMetadataGeneration]; generation != "" {
			return generation
		}
	}
	if info != nil {
		return info.Config.Name
	}
	return ""
}

func (l *Log) callRewriteTestHook(phase rewritePhase) error {
	if l.rewriteTestHook == nil {
		return nil
	}
	return l.rewriteTestHook(phase)
}

func (l *Log) restoreSourceAndDiscardTarget(ctx context.Context, sourceName, targetName string) error {
	source, err := l.js.Stream(ctx, sourceName)
	if err != nil {
		return err
	}
	info, err := l.infoForStream(ctx, source)
	if err != nil {
		return err
	}
	cfg := cloneStreamConfig(info.Config)
	restore, err := decodeRewriteSourceRestore(cfg.Metadata[rewriteMetadataRestore])
	if err != nil {
		return err
	}
	cfg.Subjects = append([]string(nil), restore.Subjects...)
	if restore.SubjectTransform == nil {
		cfg.SubjectTransform = nil
	} else {
		transform := *restore.SubjectTransform
		cfg.SubjectTransform = &transform
	}
	if restore.MetadataWasNil {
		cfg.Metadata = nil
	} else {
		cfg.Metadata = make(map[string]string, len(restore.Metadata))
		for key, value := range restore.Metadata {
			cfg.Metadata[key] = value
		}
	}
	source, err = l.js.UpdateStream(ctx, cfg)
	if err != nil {
		return err
	}
	l.setActiveStreamNamed(sourceName, source)
	if targetName != "" {
		if err := l.js.DeleteStream(ctx, targetName); err != nil && !errors.Is(err, jetstream.ErrStreamNotFound) {
			return err
		}
	}
	return nil
}

func deleteRewriteMetadata(metadata map[string]string) {
	for key := range metadata {
		if strings.HasPrefix(key, "trstctl.rewrite.") {
			delete(metadata, key)
		}
	}
}

func (l *Log) clearRewriteMetadata(ctx context.Context, stream jetstream.Stream) error {
	info, err := l.infoForStream(ctx, stream)
	if err != nil {
		return err
	}
	cfg := cloneStreamConfig(info.Config)
	deleteRewriteMetadata(cfg.Metadata)
	_, err = l.js.UpdateStream(ctx, cfg)
	return err
}

func (l *Log) scrubAndDeleteSource(ctx context.Context, source, target jetstream.Stream) error {
	sourceInfo, err := l.infoForStream(ctx, source)
	if err != nil {
		return err
	}
	targetInfo, err := l.infoForStream(ctx, target)
	if err != nil {
		return err
	}
	if targetInfo.State.LastSeq < sourceInfo.State.LastSeq {
		return fmt.Errorf(
			"target head %d is behind frozen source head %d",
			targetInfo.State.LastSeq, sourceInfo.State.LastSeq,
		)
	}
	first := sourceInfo.State.FirstSeq
	if first == 0 {
		first = 1
	}
	for seq := first; seq <= sourceInfo.State.LastSeq; seq++ {
		sourceRaw, err := source.GetMsg(ctx, seq)
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read frozen source seq %d: %w", seq, err)
		}
		targetRaw, err := target.GetMsg(ctx, seq)
		if err != nil {
			return fmt.Errorf("read active target seq %d while scrubbing: %w", seq, err)
		}
		if bytes.Equal(sourceRaw.Data, targetRaw.Data) {
			continue
		}
		if err := source.SecureDeleteMsg(ctx, seq); err != nil && !errors.Is(err, jetstream.ErrMsgNotFound) {
			return fmt.Errorf("secure-delete frozen source seq %d: %w", seq, err)
		}
		if err := l.callRewriteTestHook(rewritePhaseScrubbing); err != nil {
			return err
		}
	}
	sourceName := sourceInfo.Config.Name
	if err := l.js.DeleteStream(ctx, sourceName); err != nil && !errors.Is(err, jetstream.ErrStreamNotFound) {
		return fmt.Errorf("delete frozen source %s: %w", sourceName, err)
	}
	return nil
}

func (l *Log) recoverOrCreateActiveStream(ctx context.Context, desired jetstream.StreamConfig) (jetstream.Stream, error) {
	resolveOrCreate := func(ctx context.Context, mayUpgradeLegacyRestore bool) (jetstream.Stream, error) {
		pendingName, pending, found, err := l.pendingBackupRestoreStream(ctx)
		if err != nil {
			return nil, err
		}
		if found {
			activeName, activeErr := l.activeStreamName(ctx)
			switch {
			case activeErr == nil && activeName != pendingName:
				return nil, fmt.Errorf(
					"events: pending backup restore generation %q conflicts with active generation %q",
					pendingName, activeName,
				)
			case activeErr != nil && !errors.Is(activeErr, jetstream.ErrStreamNotFound):
				return nil, activeErr
			}
			info, err := l.infoForStream(ctx, pending)
			if err != nil {
				return nil, fmt.Errorf("events: inspect pending backup restore recovery: %w", err)
			}
			if backupRestoreRouteNeedsUpgrade(info.Config) {
				if !mayUpgradeLegacyRestore {
					return nil, errors.New(
						"events: legacy pending backup restore requires a history coordinator",
					)
				}
				pending, err = l.freezeLegacyBackupRestoreRoute(ctx, pendingName, pending, info)
				if err != nil {
					return nil, err
				}
			}
			return pending, nil
		}
		state, err := l.findRewriteStreams(ctx)
		if err != nil {
			return nil, err
		}
		if state != nil {
			if err := l.recoverRewriteStreams(ctx, *state); err != nil {
				return nil, err
			}
		}
		if name, err := l.activeStreamName(ctx); err == nil {
			stream, err := l.js.Stream(ctx, name)
			if err != nil {
				return nil, err
			}
			info, err := l.infoForStream(ctx, stream)
			if err != nil {
				return nil, err
			}
			if completedRewriteGeneration(info.Config) {
				if err := l.verifyCompletedTargetContinuity(ctx, stream); err != nil {
					return nil, err
				}
				if err := l.clearRewriteMetadata(ctx, stream); err != nil {
					return nil, fmt.Errorf(
						"events: retire verified completed rewrite recovery metadata: %w",
						err,
					)
				}
			}
			return stream, nil
		} else if !errors.Is(err, jetstream.ErrStreamNotFound) {
			return nil, err
		}
		return l.js.CreateOrUpdateStream(ctx, desired)
	}
	if l.history == nil {
		state, err := l.findRewriteStreams(ctx)
		if err != nil {
			return nil, err
		}
		if state != nil {
			return nil, errors.New("unfinished event rewrite requires a history coordinator for recovery")
		}
		return resolveOrCreate(ctx, false)
	}
	var stream jetstream.Stream
	err := l.history.WithRewriteOperation(ctx, func(ctx context.Context) error {
		return l.history.WithCutover(ctx, func(ctx context.Context) error {
			var err error
			// Re-scan only after both locks are held. Another replica may have
			// completed recovery while this opener waited for the operation wall.
			stream, err = resolveOrCreate(ctx, true)
			return err
		})
	})
	return stream, err
}

func (l *Log) findRewriteStreams(ctx context.Context) (*rewriteStreams, error) {
	var state rewriteStreams
	lister := l.js.ListStreams(ctx)
	for info := range lister.Info() {
		metadata := info.Config.Metadata
		if completedRewriteGeneration(info.Config) {
			continue
		}
		operation := metadata[rewriteMetadataOperation]
		if operation == "" {
			if unfinishedRewriteMarkers(info.Config) {
				return nil, fmt.Errorf(
					"events: stream %q has unfinished rewrite markers but no operation id",
					info.Config.Name,
				)
			}
			continue
		}
		if state.operation != "" && state.operation != operation {
			return nil, fmt.Errorf(
				"events: conflicting unfinished rewrite operations %q and %q",
				state.operation, operation,
			)
		}
		state.operation = operation
		switch info.Config.Metadata[rewriteMetadataRole] {
		case rewriteRoleSource:
			if state.source != nil {
				return nil, errors.New("events: unfinished rewrite has multiple source streams")
			}
			state.source = info
		case rewriteRoleTarget:
			if state.target != nil {
				return nil, errors.New("events: unfinished rewrite has multiple target streams")
			}
			state.target = info
		default:
			return nil, fmt.Errorf(
				"events: unfinished rewrite stream %q has invalid role %q",
				info.Config.Name, info.Config.Metadata[rewriteMetadataRole],
			)
		}
	}
	if err := lister.Err(); err != nil {
		return nil, fmt.Errorf("events: list rewrite streams: %w", err)
	}
	if state.operation == "" {
		return nil, nil
	}
	if err := validateRewriteStateMetadata(state); err != nil {
		return nil, err
	}
	return &state, nil
}

func completedRewriteGeneration(cfg jetstream.StreamConfig) bool {
	metadata := cfg.Metadata
	return strings.HasPrefix(cfg.Name, rewriteStreamPrefix) &&
		len(cfg.Subjects) == 1 && cfg.Subjects[0] == subjectFilter &&
		metadata[rewriteMetadataRole] == rewriteRoleActive &&
		metadata[rewriteMetadataPhase] == string(rewritePhaseComplete) &&
		metadata[rewriteMetadataReceiptSeq] != "" &&
		metadata[rewriteMetadataReceiptID] != "" &&
		metadata[rewriteMetadataReceiptSum] != "" &&
		metadata[rewriteMetadataReport] != "" &&
		metadata[rewriteMetadataReportSum] != ""
}

func unfinishedRewriteMarkers(cfg jetstream.StreamConfig) bool {
	for _, subject := range cfg.Subjects {
		if strings.HasPrefix(subject, "__trstctl_rewrite.") ||
			strings.HasPrefix(subject, "__trstctl_frozen.") {
			return true
		}
	}
	for key := range cfg.Metadata {
		if !strings.HasPrefix(key, "trstctl.rewrite.") {
			continue
		}
		return true
	}
	return false
}

func validateRewriteStateMetadata(state rewriteStreams) error {
	var reference map[string]string
	for _, info := range []*jetstream.StreamInfo{state.source, state.target} {
		if info == nil {
			continue
		}
		metadata := info.Config.Metadata
		if metadata[rewriteMetadataOperation] != state.operation ||
			metadata[rewriteMetadataSource] == "" ||
			metadata[rewriteMetadataTarget] == "" ||
			metadata[rewriteMetadataTenant] == "" ||
			metadata[rewriteMetadataConfigHash] == "" ||
			metadata[rewriteMetadataRestore] == "" ||
			metadata[rewriteMetadataRestoreSum] == "" {
			return fmt.Errorf("events: rewrite stream %q has incomplete recovery metadata", info.Config.Name)
		}
		if crypto.SHA256Hex([]byte(metadata[rewriteMetadataRestore])) !=
			metadata[rewriteMetadataRestoreSum] {
			return fmt.Errorf(
				"events: rewrite stream %q source restore digest mismatch",
				info.Config.Name,
			)
		}
		if _, err := decodeRewriteSourceRestore(metadata[rewriteMetadataRestore]); err != nil {
			return fmt.Errorf("events: rewrite stream %q restore point: %w", info.Config.Name, err)
		}
		if !validRewriteStreamName(metadata[rewriteMetadataTarget]) {
			return fmt.Errorf("events: rewrite target name %q is invalid", metadata[rewriteMetadataTarget])
		}
		actualHash, err := rewriteBaseConfigDigest(info.Config)
		if err != nil {
			return err
		}
		if actualHash != metadata[rewriteMetadataConfigHash] {
			return fmt.Errorf(
				"events: rewrite stream %q config digest mismatch: metadata=%s actual=%s",
				info.Config.Name, metadata[rewriteMetadataConfigHash], actualHash,
			)
		}
		if reference == nil {
			reference = metadata
			continue
		}
		for _, key := range []string{
			rewriteMetadataOperation, rewriteMetadataSource, rewriteMetadataTarget,
			rewriteMetadataTenant, rewriteMetadataConfigHash, rewriteMetadataRestore,
			rewriteMetadataRestoreSum,
		} {
			if reference[key] != metadata[key] {
				return fmt.Errorf(
					"events: rewrite metadata disagreement for %s: %q != %q",
					key, reference[key], metadata[key],
				)
			}
		}
	}
	if reference == nil {
		return errors.New("events: empty unfinished rewrite state")
	}
	if state.source != nil && state.source.Config.Name != reference[rewriteMetadataSource] {
		return errors.New("events: rewrite source name does not match durable metadata")
	}
	if state.target != nil && state.target.Config.Name != reference[rewriteMetadataTarget] {
		return errors.New("events: rewrite target name does not match durable metadata")
	}
	return nil
}

func (l *Log) recoverRewriteStreams(ctx context.Context, state rewriteStreams) error {
	activeName, activeErr := l.activeStreamName(ctx)
	if activeErr != nil && !errors.Is(activeErr, jetstream.ErrStreamNotFound) {
		return activeErr
	}
	sourceName, targetName := "", ""
	if state.source != nil {
		sourceName = state.source.Config.Name
	}
	if state.target != nil {
		targetName = state.target.Config.Name
	}
	switch {
	case activeErr == nil && activeName == sourceName:
		return l.restoreSourceAndDiscardTarget(ctx, sourceName, targetName)
	case activeErr == nil && activeName == targetName:
		target, err := l.js.Stream(ctx, targetName)
		if err != nil {
			return err
		}
		if err := l.verifyActivatedTargetContinuity(ctx, target); err != nil {
			return err
		}
		if state.source != nil {
			source, err := l.js.Stream(ctx, sourceName)
			if err != nil {
				return err
			}
			if err := l.scrubAndDeleteSource(ctx, source, target); err != nil {
				return err
			}
		}
		if err := l.clearRewriteMetadata(ctx, target); err != nil {
			return err
		}
		l.setActiveStreamNamed(targetName, target)
		return nil
	case errors.Is(activeErr, jetstream.ErrStreamNotFound) && state.source != nil:
		if state.target != nil {
			phase := rewritePhase(state.target.Config.Metadata[rewriteMetadataPhase])
			if phase == rewritePhaseReady || phase == rewritePhasePrepared {
				return l.recoverExternallyPreparedRewrite(ctx, state, phase)
			}
		}
		// Freeze completed but target activation did not. Source has never been
		// scrubbed before activation, so restoring its subject is a lossless rollback.
		return l.restoreSourceAndDiscardTarget(ctx, sourceName, targetName)
	default:
		return fmt.Errorf(
			"events: cannot recover rewrite %q: active=%q source=%q target=%q",
			state.operation, activeName, sourceName, targetName,
		)
	}
}

func (l *Log) recoverExternallyPreparedRewrite(
	ctx context.Context,
	state rewriteStreams,
	phase rewritePhase,
) error {
	if state.source == nil || state.target == nil {
		return errors.New("events: externally prepared rewrite lacks source or target")
	}
	metadata := state.target.Config.Metadata
	if metadata[rewriteMetadataExternalPreparation] != rewriteExternalPreparationPrivacySubjectErasure {
		return fmt.Errorf(
			"events: prepared rewrite has unsupported external preparation kind %q",
			metadata[rewriteMetadataExternalPreparation],
		)
	}
	resolver, ok := l.history.(HistoryRewritePreparationResolver)
	if !ok {
		return errors.New("events: prepared rewrite recovery requires an external preparation resolver")
	}
	active, err := resolver.HistoryRewritePreparationActive(
		ctx,
		metadata[rewriteMetadataTenant],
		metadata[rewriteMetadataGeneration],
	)
	if err != nil {
		return fmt.Errorf("events: resolve prepared rewrite marker: %w", err)
	}
	if !active {
		// The external transaction is authoritatively absent. The source was not
		// scrubbed before activation, so rolling back is complete and lossless.
		return l.restoreSourceAndDiscardTarget(
			ctx, state.source.Config.Name, state.target.Config.Name,
		)
	}
	target, err := l.js.Stream(ctx, state.target.Config.Name)
	if err != nil {
		return err
	}
	if err := l.verifyTargetContinuity(ctx, target, phase); err != nil {
		return err
	}

	info, err := l.infoForStream(ctx, target)
	if err != nil {
		return err
	}
	activeCfg := cloneStreamConfig(info.Config)
	activeCfg.Subjects = []string{subjectFilter}
	activeCfg.SubjectTransform = nil
	activeCfg.Metadata = rewriteMetadata(
		activeCfg.Metadata,
		metadata[rewriteMetadataOperation],
		rewriteRoleTarget,
		rewritePhaseActivated,
		state.source.Config.Name,
		state.target.Config.Name,
		metadata[rewriteMetadataTenant],
		metadata[rewriteMetadataGeneration],
	)
	target, err = l.js.UpdateStream(ctx, activeCfg)
	if err != nil {
		return fmt.Errorf("events: activate recovered externally prepared target: %w", err)
	}
	l.setActiveStreamNamed(state.target.Config.Name, target)
	source, err := l.js.Stream(ctx, state.source.Config.Name)
	if err != nil {
		return err
	}
	if err := l.scrubAndDeleteSource(ctx, source, target); err != nil {
		return fmt.Errorf("events: scrub recovered externally prepared source: %w", err)
	}
	if err := l.clearRewriteMetadata(ctx, target); err != nil {
		return fmt.Errorf("events: clear recovered externally prepared metadata: %w", err)
	}
	return nil
}

func (l *Log) verifyActivatedTargetContinuity(ctx context.Context, target jetstream.Stream) error {
	return l.verifyTargetContinuity(ctx, target, rewritePhaseActivated)
}

func (l *Log) verifyCompletedTargetContinuity(ctx context.Context, target jetstream.Stream) error {
	return l.verifyTargetContinuity(ctx, target, rewritePhaseComplete)
}

func (l *Log) verifyTargetContinuity(
	ctx context.Context,
	target jetstream.Stream,
	expectedPhase rewritePhase,
) error {
	if l.continuityVerifier == nil {
		return errors.New("events: rewrite recovery requires a continuity signature verifier")
	}
	info, err := l.infoForStream(ctx, target)
	if err != nil {
		return err
	}
	metadata := info.Config.Metadata
	if metadata[rewriteMetadataPhase] != string(expectedPhase) {
		return fmt.Errorf(
			"events: active rewrite target %q has phase %q, want %q",
			info.Config.Name, metadata[rewriteMetadataPhase], expectedPhase,
		)
	}
	sequence, err := strconv.ParseUint(metadata[rewriteMetadataReceiptSeq], 10, 64)
	if err != nil || sequence == 0 {
		return errors.New("events: active rewrite target lacks a valid receipt sequence")
	}
	raw, err := target.GetMsg(ctx, sequence)
	if err != nil {
		return fmt.Errorf("events: read active rewrite receipt seq %d: %w", sequence, err)
	}
	if crypto.SHA256Hex(raw.Data) != metadata[rewriteMetadataReceiptSum] {
		return errors.New("events: active rewrite receipt digest does not match durable metadata")
	}
	receipt, err := decodeStored(raw.Data, raw.Sequence)
	if err != nil {
		return err
	}
	receiptMessageIDs := raw.Header.Values(jetstream.MsgIDHeader)
	if len(receiptMessageIDs) != 1 || receiptMessageIDs[0] != receipt.ID {
		return errors.New("events: active rewrite receipt message id does not match its signed envelope")
	}
	report, err := rewriteReportFromMetadata(metadata)
	if err != nil {
		return err
	}
	if err := validateRecoveredRewriteReport(info.Config, metadata, sequence, report); err != nil {
		return err
	}
	if receipt.ID != metadata[rewriteMetadataReceiptID] ||
		receipt.TenantID != report.TenantID {
		return errors.New("events: active rewrite receipt identity does not match durable metadata/report")
	}
	evidence := TenantDataContinuityEvidence{
		OperationID:     report.OperationID,
		TenantID:        report.TenantID,
		SourceStream:    report.SourceStream,
		TargetStream:    report.TargetStream,
		ReceiptSequence: sequence,
		Receipt:         receipt,
		Report:          report,
	}
	// Authenticate the signed report before trusting its sequence bounds for any
	// source/target walk. Otherwise a metadata-only SourceCutSequence tamper can
	// force startup to traverse an attacker-chosen range before the JWS failure is
	// discovered.
	if err := l.continuityVerifier(ctx, evidence); err != nil {
		return fmt.Errorf("events: verify signed rewrite continuity: %w", err)
	}
	var source jetstream.Stream
	if sourceName := report.SourceStream; sourceName != "" {
		source, sourceErr := l.js.Stream(ctx, sourceName)
		if sourceErr == nil {
			sourceInfo, infoErr := l.infoForStream(ctx, source)
			if infoErr != nil {
				return infoErr
			}
			sourceDigest, digestErr := rewriteAuthorizedConfigDigest(sourceInfo.Config)
			if digestErr != nil {
				return digestErr
			}
			if sourceDigest != report.SourceConfigDigest {
				return errors.New("events: frozen source config no longer matches the signed rewrite report")
			}
		} else if !errors.Is(sourceErr, jetstream.ErrStreamNotFound) {
			return sourceErr
		}
	}
	if err := validateRecoveredRewriteHistory(ctx, source, target, report); err != nil {
		return err
	}
	return nil
}

func rewriteReportFromMetadata(metadata map[string]string) (TenantDataRewriteReport, error) {
	encoded := metadata[rewriteMetadataReport]
	if encoded == "" {
		return TenantDataRewriteReport{}, errors.New("events: active rewrite target lacks its signed report")
	}
	payload, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return TenantDataRewriteReport{}, errors.New("events: active rewrite report metadata is not valid base64")
	}
	if crypto.SHA256Hex(payload) != metadata[rewriteMetadataReportSum] {
		return TenantDataRewriteReport{}, errors.New("events: active rewrite report digest does not match durable metadata")
	}
	var report TenantDataRewriteReport
	if err := json.Unmarshal(payload, &report); err != nil {
		return TenantDataRewriteReport{}, fmt.Errorf("events: decode active rewrite report: %w", err)
	}
	return report, nil
}

func validateRecoveredRewriteReport(
	activeConfig jetstream.StreamConfig,
	metadata map[string]string,
	receiptSequence uint64,
	report TenantDataRewriteReport,
) error {
	operationID := report.OperationID
	if operationID == "" ||
		report.TenantID == "" ||
		report.SourceStream == "" ||
		report.TargetStream != activeConfig.Name ||
		report.TargetGeneration != operationID ||
		report.ReceiptSequence != receiptSequence {
		return errors.New("events: active rewrite report identity is incomplete or inconsistent")
	}
	for key, want := range map[string]string{
		rewriteMetadataOperation: operationID,
		rewriteMetadataTenant:    report.TenantID,
		rewriteMetadataSource:    report.SourceStream,
		rewriteMetadataTarget:    report.TargetStream,
	} {
		if got := metadata[key]; got != "" && got != want {
			return fmt.Errorf("events: active rewrite metadata %s does not match signed report", key)
		}
	}
	if report.SourceConfigDigest == "" || report.TargetConfigDigest == "" {
		return errors.New("events: active rewrite report lacks source/target config digests")
	}
	if report.TargetContentDigest == "" {
		return errors.New("events: active rewrite report lacks target content digest")
	}
	if report.ArchiveExposure != TenantDataArchiveExposureExternalCopiesMayRetainSourceBytes {
		return errors.New("events: active rewrite report lacks the required external-archive exposure disclosure")
	}
	baseDigest, err := rewriteBaseConfigDigest(activeConfig)
	if err != nil {
		return fmt.Errorf("events: digest active target base config: %w", err)
	}
	if metadata[rewriteMetadataConfigHash] == "" ||
		baseDigest != metadata[rewriteMetadataConfigHash] {
		return errors.New("events: active target base config no longer matches durable rewrite metadata")
	}
	stagedConfig := cloneStreamConfig(activeConfig)
	stagedConfig.Subjects = []string{rewriteStagingFilter(operationID)}
	stagedConfig.SubjectTransform = &jetstream.SubjectTransformConfig{
		Source: rewriteStagingFilter(operationID), Destination: subjectFilter,
	}
	stagedConfig.Metadata[rewriteMetadataOperation] = operationID
	stagedConfig.Metadata[rewriteMetadataRole] = rewriteRoleTarget
	stagedConfig.Metadata[rewriteMetadataPhase] = string(rewritePhaseStaging)
	stagedConfig.Metadata[rewriteMetadataSource] = report.SourceStream
	stagedConfig.Metadata[rewriteMetadataTarget] = report.TargetStream
	stagedConfig.Metadata[rewriteMetadataTenant] = report.TenantID
	stagedConfig.Metadata[rewriteMetadataGeneration] = report.TargetGeneration
	delete(stagedConfig.Metadata, rewriteMetadataReceiptSeq)
	delete(stagedConfig.Metadata, rewriteMetadataReceiptID)
	delete(stagedConfig.Metadata, rewriteMetadataReceiptSum)
	delete(stagedConfig.Metadata, rewriteMetadataReport)
	delete(stagedConfig.Metadata, rewriteMetadataReportSum)
	delete(stagedConfig.Metadata, rewriteMetadataExternalPreparation)
	digest, err := rewriteAuthorizedConfigDigest(stagedConfig)
	if err != nil {
		return fmt.Errorf("events: digest recovered target config: %w", err)
	}
	if digest != report.TargetConfigDigest {
		return errors.New("events: active target config no longer matches the signed rewrite report")
	}
	return nil
}

func validateRecoveredRewriteHistory(
	ctx context.Context,
	source, target jetstream.Stream,
	report TenantDataRewriteReport,
) error {
	envelopeDigest := crypto.SHA256Hex([]byte("trstctl.event-rewrite.envelopes.v1"))
	mappingDigest := crypto.SHA256Hex([]byte("trstctl.event-rewrite.mapping.v1"))
	targetContentDigest := crypto.SHA256Hex([]byte("trstctl.event-rewrite.target-content.v1"))
	changed := 0
	sourceComplete := source != nil
	for seq := report.FirstSequence; seq <= report.SourceCutSequence; seq++ {
		targetRaw, targetErr := target.GetMsg(ctx, seq)
		if errors.Is(targetErr, jetstream.ErrMsgNotFound) {
			targetContentDigest = digestChain(targetContentDigest, struct {
				Sequence uint64 `json:"sequence"`
				Gap      bool   `json:"gap"`
			}{Sequence: seq, Gap: true})
		} else if targetErr != nil {
			return fmt.Errorf("events: verify target content seq %d: %w", seq, targetErr)
		} else {
			targetContentDigest = digestTargetContent(targetContentDigest, targetRaw)
		}
		if source == nil {
			if errors.Is(targetErr, jetstream.ErrMsgNotFound) {
				envelopeDigest = digestChain(envelopeDigest, struct {
					Sequence uint64 `json:"sequence"`
					Gap      bool   `json:"gap"`
				}{Sequence: seq, Gap: true})
				continue
			}
			if targetErr != nil {
				return fmt.Errorf("events: verify completed target seq %d: %w", seq, targetErr)
			}
			invariant, err := rewriteInvariantFor(targetRaw)
			if err != nil {
				return err
			}
			envelopeDigest = digestChain(envelopeDigest, invariant)
			continue
		}

		sourceRaw, sourceErr := source.GetMsg(ctx, seq)
		if errors.Is(sourceErr, jetstream.ErrMsgNotFound) {
			if errors.Is(targetErr, jetstream.ErrMsgNotFound) {
				envelopeDigest = digestChain(envelopeDigest, struct {
					Sequence uint64 `json:"sequence"`
					Gap      bool   `json:"gap"`
				}{Sequence: seq, Gap: true})
				continue
			}
			// SecureDeleteMsg can already have removed one or more changed
			// source records before a crash. The signed target-content root
			// authenticates those target bytes; surviving pairs below still
			// prove every source record that remains.
			sourceComplete = false
			invariant, err := rewriteInvariantFor(targetRaw)
			if err != nil {
				return err
			}
			envelopeDigest = digestChain(envelopeDigest, invariant)
			continue
		}
		if sourceErr != nil {
			return fmt.Errorf("events: verify frozen source seq %d: %w", seq, sourceErr)
		}
		if targetErr != nil {
			return fmt.Errorf("events: verify active target seq %d: %w", seq, targetErr)
		}
		beforeInvariant, err := rewriteInvariantFor(sourceRaw)
		if err != nil {
			return err
		}
		afterInvariant, err := rewriteInvariantFor(targetRaw)
		if err != nil {
			return err
		}
		beforeCanonical, beforeErr := json.Marshal(beforeInvariant)
		afterCanonical, afterErr := json.Marshal(afterInvariant)
		if beforeErr != nil || afterErr != nil {
			return errors.Join(beforeErr, afterErr)
		}
		if !bytes.Equal(beforeCanonical, afterCanonical) {
			return fmt.Errorf("events: recovered target changed immutable envelope at seq %d", seq)
		}
		envelopeDigest = digestChain(envelopeDigest, beforeInvariant)
		if !bytes.Equal(sourceRaw.Data, targetRaw.Data) {
			var before storedEvent
			if err := json.Unmarshal(sourceRaw.Data, &before); err != nil {
				return err
			}
			mappingDigest = digestChain(mappingDigest, struct {
				Sequence uint64 `json:"sequence"`
				EventID  string `json:"event_id"`
				Before   string `json:"before_sha256"`
				After    string `json:"after_sha256"`
			}{
				Sequence: seq, EventID: before.ID,
				Before: crypto.SHA256Hex(sourceRaw.Data), After: crypto.SHA256Hex(targetRaw.Data),
			})
			changed++
		}
	}
	if envelopeDigest != report.EnvelopeDigest {
		return errors.New("events: recovered generation envelope digest does not match signed report")
	}
	if targetContentDigest != report.TargetContentDigest {
		return errors.New("events: recovered target content does not match signed report")
	}
	if sourceComplete &&
		(mappingDigest != report.MappingDigest || changed != report.ChangedEvents) {
		return errors.New("events: recovered generation mapping/count does not match signed report")
	}
	targetRecords, err := auditRecordsForGeneration(
		ctx, target, report.TenantID, report.SourceCutSequence, report.AuditCheckpoint,
	)
	if err != nil {
		return err
	}
	targetHead := auditchain.SealFrom(report.AuditCheckpoint.BoundaryHash, targetRecords)
	if targetHead != report.TargetAuditHead {
		return errors.New("events: recovered target audit head does not match signed report")
	}
	if sourceComplete {
		sourceRecords, err := auditRecordsForGeneration(
			ctx, source, report.TenantID, report.SourceCutSequence, report.AuditCheckpoint,
		)
		if err != nil {
			return err
		}
		sourceHead := auditchain.SealFrom(report.AuditCheckpoint.BoundaryHash, sourceRecords)
		if sourceHead != report.SourceAuditHead {
			return errors.New("events: recovered source audit head does not match signed report")
		}
	}
	return nil
}

// WithHistoryRead pins a complete cross-store read view against a rewrite
// cutover. Backups hold this wall across the event cut, PostgreSQL snapshot, and
// event export. Replay may be called inside fn; coordinators must treat the
// context they return as a re-entrant shared-read token.
func (l *Log) WithHistoryRead(ctx context.Context, fn func(context.Context) error) error {
	if fn == nil {
		return errors.New("events: history read callback is required")
	}
	return l.withHistoryRead(ctx, func(readCtx context.Context) error {
		_, stream, err := l.resolveActiveStream(readCtx)
		if err != nil {
			return fmt.Errorf("events: resolve history read restore state: %w", err)
		}
		if err := l.requireNoPendingBackupRestoreStream(readCtx, stream); err != nil {
			return err
		}
		return fn(readCtx)
	})
}

func (l *Log) withFrozenGenerationReadView(
	ctx context.Context,
	name string,
	stream jetstream.Stream,
	fn func(context.Context) error,
) error {
	view := newHistoryGenerationReadView(l, name, stream)
	// The caller already owns the exclusive barrier. Hide its coordinator grant
	// from escaped preparation contexts: only a live generation lease may bypass
	// the barrier, and an expired context must reacquire the ordinary read wall.
	viewCtx := context.WithValue(
		ctx,
		localHistoryExclusiveGrantContextKey{},
		localHistoryExclusiveGrant{},
	)
	viewCtx = context.WithValue(
		viewCtx,
		historyGenerationReadGrantContextKey{},
		historyGenerationReadGrant{view: view},
	)
	defer view.revokeAndWait()
	return fn(viewCtx)
}

func (l *Log) withHistoryRead(ctx context.Context, fn func(context.Context) error) error {
	if lease, ok := ctx.Value(historyGenerationReadLeaseContextKey{}).(*historyGenerationReadLease); ok &&
		lease != nil && lease.view != nil {
		if nested := lease.view.acquire(l, lease); nested != nil {
			return l.withHistoryGenerationReadLease(ctx, nested, fn)
		}
		ctx = detachedHistoryGenerationContext{Context: ctx}
	}
	if grant, ok := ctx.Value(historyGenerationReadGrantContextKey{}).(historyGenerationReadGrant); ok &&
		grant.view != nil {
		if lease := grant.view.acquire(l, nil); lease != nil {
			return l.withHistoryGenerationReadLease(ctx, lease, fn)
		}
		ctx = detachedHistoryGenerationContext{Context: ctx}
	}
	if l.history == nil {
		return fn(ctx)
	}
	return l.history.WithRead(ctx, fn)
}

func (l *Log) withHistoryGenerationReadLease(
	ctx context.Context,
	lease *historyGenerationReadLease,
	fn func(context.Context) error,
) error {
	leaseCtx := context.WithValue(
		ctx,
		historyGenerationReadGrantContextKey{},
		historyGenerationReadGrant{},
	)
	leaseCtx = context.WithValue(
		leaseCtx,
		historyGenerationReadLeaseContextKey{},
		lease,
	)
	defer lease.view.release(lease)
	return fn(leaseCtx)
}

func (l *Log) historyGenerationReadRoute(
	ctx context.Context,
) (string, jetstream.Stream, bool) {
	lease, _ := ctx.Value(historyGenerationReadLeaseContextKey{}).(*historyGenerationReadLease)
	if lease == nil || lease.view == nil {
		return "", nil, false
	}
	return lease.view.route(l, lease)
}

func (l *Log) infoForStream(ctx context.Context, stream jetstream.Stream) (*jetstream.StreamInfo, error) {
	if stream == nil {
		return nil, errors.New("events: stream handle is nil")
	}
	cached := stream.CachedInfo()
	if cached == nil || strings.TrimSpace(cached.Config.Name) == "" {
		return nil, errors.New("events: stream handle has no cached name")
	}
	// AUD-127: jetstream.Stream.Info mutates the handle's cached StreamInfo while
	// GetMsg reads that cache to choose its direct-read path. Resolve the durable
	// name into a private handle instead of refreshing a handle another replay may
	// be reading. Different callers therefore remain parallel without a global
	// event-log lock, and the returned StreamInfo is already fresh from the server.
	fresh, err := l.js.Stream(ctx, cached.Config.Name)
	if err != nil {
		return nil, err
	}
	info := fresh.CachedInfo()
	if info == nil {
		return nil, errors.New("events: refreshed stream handle has no metadata")
	}
	return info, nil
}

func cachedInfoForResolvedStream(stream jetstream.Stream) (*jetstream.StreamInfo, error) {
	if stream == nil {
		return nil, errors.New("events: resolved stream handle is nil")
	}
	info := stream.CachedInfo()
	if info == nil {
		return nil, errors.New("events: resolved stream handle has no metadata")
	}
	return info, nil
}

func (l *Log) activeStreamName(ctx context.Context) (string, error) {
	if name, _, ok := l.historyGenerationReadRoute(ctx); ok {
		return name, nil
	}
	return l.js.StreamNameBySubject(ctx, activeStreamProbeSubject)
}

// ActiveGeneration returns the durable identity of the generation that owns
// events.>. Startup privacy recovery uses it to prove that PostgreSQL's prepared
// completion marker names the history generation recovered during Log.Open.
func (l *Log) ActiveGeneration(ctx context.Context) (string, error) {
	var generation string
	err := l.withHistoryRead(ctx, func(ctx context.Context) error {
		_, stream, err := l.resolveActiveStream(ctx)
		if err != nil {
			return err
		}
		info, err := cachedInfoForResolvedStream(stream)
		if err != nil {
			return err
		}
		generation = streamGeneration(info)
		if generation == "" {
			return errors.New("events: active stream has no generation identity")
		}
		return nil
	})
	return generation, err
}

func (l *Log) resolveActiveStream(ctx context.Context) (string, jetstream.Stream, error) {
	if name, _, ok := l.historyGenerationReadRoute(ctx); ok {
		// A frozen-generation lease pins the durable name, not a mutable NATS
		// client object. The history wall prevents deletion while each nested read
		// resolves its own concurrency-safe handle for that exact generation.
		stream, err := l.js.Stream(ctx, name)
		if err != nil {
			return "", nil, err
		}
		return name, stream, nil
	}
	name, err := l.activeStreamName(ctx)
	if err != nil {
		if !errors.Is(err, jetstream.ErrStreamNotFound) {
			return "", nil, err
		}
		pendingName, pending, found, pendingErr := l.pendingBackupRestoreStream(ctx)
		if pendingErr != nil {
			return "", nil, pendingErr
		}
		if !found {
			return "", nil, err
		}
		l.setActiveStreamNamed(pendingName, pending)
		return pendingName, pending, nil
	}
	// StreamNameBySubject establishes which durable generation owns events.>.
	// Always resolve that name into a new client handle: Stream.Info mutates a
	// handle-local cache that GetMsg reads without synchronization.
	stream, err := l.js.Stream(ctx, name)
	if err != nil {
		return "", nil, err
	}
	l.setActiveStreamNamed(name, stream)
	return name, stream, nil
}

func (l *Log) setActiveStream(stream jetstream.Stream) {
	name := ""
	if stream != nil && stream.CachedInfo() != nil {
		name = stream.CachedInfo().Config.Name
	}
	l.setActiveStreamNamed(name, stream)
}

func (l *Log) setActiveStreamNamed(name string, stream jetstream.Stream) {
	l.activeMu.Lock()
	l.activeName = name
	l.stream = stream
	l.activeMu.Unlock()
}

func (l *Log) publishToActive(
	ctx context.Context,
	subject string,
	payload []byte,
	options ...jetstream.PublishOpt,
) (*jetstream.PubAck, error) {
	const attempts = 8
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		// This hook announces an attempted cross-cutover append. Keep it before
		// resolving the current broker route so rewrite concurrency tests can
		// observe the exact no-owner/expected-stream retry window.
		if l.publishAttemptTestHook != nil {
			l.publishAttemptTestHook()
		}
		name, stream, err := l.resolveActiveStream(ctx)
		if err == nil {
			// The metadata check gives ordinary retries the fixed fail-closed
			// error. The broker route installed in the same UpdateStream as the
			// binding is the race-free authority: if another replica binds after
			// this check, JetStream no longer accepts subject events.> into name.
			if err = l.requireNoPendingBackupRestoreStream(ctx, stream); err == nil {
				if l.publishAfterRestoreCheckTestHook != nil {
					l.publishAfterRestoreCheckTestHook()
				}
				opts := append([]jetstream.PublishOpt{}, options...)
				opts = append(opts, jetstream.WithExpectStream(name))
				ack, publishErr := l.js.Publish(ctx, subject, payload, opts...)
				if publishErr == nil {
					if active, streamErr := l.js.Stream(ctx, ack.Stream); streamErr == nil {
						l.setActiveStreamNamed(ack.Stream, active)
					}
					return ack, nil
				}
				err = publishErr
			}
			if errors.Is(err, ErrBackupRestoreIncomplete) {
				return nil, err
			}
		}
		lastErr = err
		l.activeMu.Lock()
		l.activeName = ""
		l.stream = nil
		l.activeMu.Unlock()

		timer := time.NewTimer(time.Duration(attempt+1) * 5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("active generation unavailable after refresh: %w", lastErr)
}

func normalizedSchemaVersion(version int) int {
	if version == 0 {
		return DefaultSchemaVersion
	}
	return version
}

// compile-time guard against accidentally accepting a malformed generation name.
func validRewriteStreamName(name string) bool {
	return strings.HasPrefix(name, rewriteStreamPrefix) && !strings.ContainsAny(name, ".*>/\\ \t\r\n")
}
