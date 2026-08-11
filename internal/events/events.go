// SPDX-License-Identifier: MPL-2.0

package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/schedulerhistory"
	"trstctl.com/trstctl/internal/tenancy"
)

const (
	streamName    = "TRSTCTL_EVENTS"
	subjectPrefix = "events"
	subjectFilter = "events.>"

	readyTimeout       = 10 * time.Second
	eventDedupWindow   = 24 * time.Hour
	importMissingField = "events: import requires source event id and time"
)

// ErrConflictingEventIdentity means retained source history contains one event
// ID with more than one immutable envelope. Recovery must fail closed because no
// caller can safely choose which command the producer identity means.
var ErrConflictingEventIdentity = errors.New("events: conflicting event identity")

// DefaultSchemaVersion is defined in internal/eventspec (a NATS-free leaf) and
// re-exported here so existing events.DefaultSchemaVersion references keep working.
const DefaultSchemaVersion = eventspec.DefaultSchemaVersion

// Event is the immutable AN-2 event envelope. Its definition lives in
// internal/eventspec so projection-only packages (e.g. ee/succession) can construct
// and read events without linking the embedded message bus (AN-4); this alias keeps
// every events.Event reference working and is the identical type.
type Event = eventspec.Event

// NewID returns an event-log-compatible identifier for producers that need to
// derive durable payload fields from the event ID before appending the event.
func NewID() string {
	return nuid.Next()
}

// storedEvent is the on-disk JSON envelope (the stream sequence is supplied by
// JetStream and is not stored in the payload). The schema version is "v"; it is
// omitted for v1 so legacy envelopes (which never carried it) decode to the same
// bytes and read back as DefaultSchemaVersion (SCHEMA-001).
type storedEvent struct {
	ID            string    `json:"id"`
	Type          string    `json:"type"`
	TenantID      string    `json:"tenant_id"`
	Time          time.Time `json:"time"`
	SchemaVersion int       `json:"v,omitempty"`
	Data          []byte    `json:"data,omitempty"`
	Actor         *Actor    `json:"actor,omitempty"`
}

// EnvelopeDecodeError identifies a malformed event-log record before it can
// become an Event. The projection callback therefore never sees this failure;
// carrying the JetStream sequence here lets the tail persist the exact poisoned
// global cursor position instead of returning an unlocatable decode error.
type EnvelopeDecodeError struct {
	Sequence uint64
	Err      error
}

func (e *EnvelopeDecodeError) Error() string {
	return fmt.Sprintf("events: decode stored envelope at seq %d: %v", e.Sequence, e.Err)
}

func (e *EnvelopeDecodeError) Unwrap() error { return e.Err }

// Log is the append-only event log on NATS JetStream (AN-2). In embedded mode it
// runs an in-process, file-backed JetStream server needing no external services;
// in external mode it connects to a NATS cluster by URL. Switching between them
// is config-only.
type Log struct {
	srv *natsserver.Server // non-nil only in embedded mode
	nc  *nats.Conn
	js  jetstream.JetStream
	// stream is the currently resolved generation that owns events.>. It remains
	// for package-local helpers, but production operations resolve by subject
	// ownership instead of trusting this cached handle across a generation switch.
	stream jetstream.Stream
	// activeName and stream move together under activeMu.
	activeMu   sync.RWMutex
	activeName string
	mode       string
	// desiredReplicas is the durability contract the control plane was configured
	// to require for the source-of-truth event stream. Readiness compares it with
	// the observed JetStream stream config so an under-replicated external stream
	// fails visible instead of serving with a weaker RPO than operators asked for.
	desiredReplicas int
	// duplicateWindow is normally the production safety window. Tests may shorten
	// it to prove recovery does not mistake broker memory for durable authority.
	duplicateWindow time.Duration
	// infoMu serializes stream.Info() calls. The JetStream client caches the result
	// in the shared stream handle without locking, so two concurrent Info() callers
	// race on that cache (data race in (*stream).Info). LastSequence is now called
	// from a background lag sampler (SPINE-009) concurrently with API/health callers,
	// so every Info() on the shared handle goes through this lock.
	infoMu sync.Mutex
	// history coordinates read views and destructive cutover across control-plane
	// replicas. Embedded mode installs a process-local implementation. External
	// mode must be given a deployment-wide implementation before a rewrite is
	// allowed.
	history HistoryRewriteCoordinator
	// continuityVerifier validates the signed receipt both during activation and
	// during crash recovery before a frozen source may be scrubbed.
	continuityVerifier TenantDataContinuityVerifier
	// requirePrivacyEventPolicies closes the production append vocabulary. A new
	// event type or payload version cannot enter tenant history until its exact
	// privacy disposition has been registered, so a later subject erasure never
	// discovers an unsupported schema only after the mutation was accepted.
	requirePrivacyEventPolicies bool
	// rejectLegacySchedulerRuns is installed only after startup sanitation. It
	// closes every normal live/federated ingress path while the restore-only path
	// remains able to stage an authenticated pre-patch artifact for sanitation.
	rejectLegacySchedulerRuns atomic.Bool
	// backupRestoreAuthorizer is installed only by the recovery composition. Its
	// locked deployment key verifies an opaque capability bound to one
	// HMAC-verified artifact cut/digest and its exact staged history source before
	// RestoreBackupHistory may cross the live schema floor.
	backupRestoreAuthorizer *crypto.BackupRestoreAuthorizer

	// rewriteTestHook is deliberately unexported. Tests use it to leave a durable
	// stream state at a crash boundary and prove Open recovers by authority, not by
	// a defer in the same process.
	rewriteTestHook func(rewritePhase) error
	// publishAttemptTestHook lets multi-replica tests observe the
	// no-owner/expected-stream retry window without putting Append behind the
	// history barrier and inverting the backup-fence lock order.
	publishAttemptTestHook func()
	// publishAfterRestoreCheckTestHook pauses an ordinary publish after it has
	// observed no pending exact restore. Tests use the pause to bind a restore on
	// another replica and prove the broker route fence closes that TOCTOU window.
	publishAfterRestoreCheckTestHook func()
	// createRewriteTargetTestHook injects a target-create failure after the
	// source has been durably marked. It proves that this otherwise narrow
	// failure window restores the exact pre-operation source config.
	createRewriteTargetTestHook func() error
	// pruneTestHook leaves a durable checkpointed prune at a crash boundary so
	// tests can prove restart/retry removes only the remaining authorized prefix.
	pruneTestHook func(sequence uint64) error
}

// streamInfo fetches fresh stream info under infoMu so concurrent callers do not race
// on the JetStream client's internal info cache. Holding the lock across the (fast)
// JetStream round-trip is fine: the only contention is the periodic lag sampler.
func (l *Log) streamInfo(ctx context.Context) (*jetstream.StreamInfo, error) {
	_, stream, err := l.resolveActiveStream(ctx)
	if err != nil {
		return nil, err
	}
	l.infoMu.Lock()
	defer l.infoMu.Unlock()
	return stream.Info(ctx)
}

// OpenOption configures event-log coordination without coupling this package to
// PostgreSQL or another concrete distributed-lock implementation.
type OpenOption func(*Log)

// WithHistoryRewriteCoordinator wires the deployment-wide shared/exclusive
// history barrier required for generation rewrites in external NATS mode.
func WithHistoryRewriteCoordinator(coordinator HistoryRewriteCoordinator) OpenOption {
	return func(log *Log) { log.history = coordinator }
}

// WithHistoryRewriteContinuityVerifier wires the signature/evidence verifier
// needed before activation recovery can destroy a frozen source generation.
func WithHistoryRewriteContinuityVerifier(verifier TenantDataContinuityVerifier) OpenOption {
	return func(log *Log) { log.continuityVerifier = verifier }
}

// WithBackupRestoreAuthorizer installs the verify-only capability gate for the
// restore ingress. The caller owns and must destroy authorizer after Log.Close.
func WithBackupRestoreAuthorizer(authorizer *crypto.BackupRestoreAuthorizer) OpenOption {
	return func(log *Log) { log.backupRestoreAuthorizer = authorizer }
}

// WithRequiredPrivacyEventPolicies makes the event log reject any append/import
// whose exact (type, schema version) lacks a registered privacy policy. Production
// composition enables this after all core/projector/edition package init hooks have
// loaded their deterministic catalogs. Focused event-log tests may omit the option
// when intentionally exercising arbitrary synthetic event names.
func WithRequiredPrivacyEventPolicies() OpenOption {
	return func(log *Log) { log.requirePrivacyEventPolicies = true }
}

// WithDuplicateWindowForTesting shortens JetStream's finite message-ID memory so
// crash-recovery tests can cross the real broker boundary without sleeping for a
// day. Production callers must rely on the default configured below; correctness
// may never rely on this window being long enough.
func WithDuplicateWindowForTesting(window time.Duration) OpenOption {
	return func(log *Log) {
		if window > 0 {
			log.duplicateWindow = window
		}
	}
}

// Open opens the event log according to cfg and ensures one active generation
// owns events.>. opts is variadic to keep existing callers source-compatible.
func Open(ctx context.Context, cfg config.NATS, opts ...OpenOption) (*Log, error) {
	var (
		srv *natsserver.Server
		nc  *nats.Conn
		err error
	)
	switch cfg.Mode {
	case config.NATSEmbedded:
		srv, nc, err = openEmbedded(cfg)
	case config.NATSExternal:
		if cfg.URL == "" {
			return nil, errors.New("events: external nats requires a url")
		}
		nc, err = nats.Connect(cfg.URL)
	default:
		return nil, fmt.Errorf("events: invalid nats mode %q", cfg.Mode)
	}
	if err != nil {
		return nil, err
	}

	js, err := jetstream.New(nc)
	if err != nil {
		shutdown(srv, nc)
		return nil, fmt.Errorf("events: jetstream: %w", err)
	}
	l := &Log{srv: srv, nc: nc, js: js, mode: cfg.Mode, duplicateWindow: eventDedupWindow}
	for _, opt := range opts {
		if opt != nil {
			opt(l)
		}
	}
	scfg := streamConfig(cfg)
	scfg.Duplicates = l.duplicateWindow
	l.desiredReplicas = scfg.Replicas
	if cfg.Mode == config.NATSExternal && scfg.Replicas == 1 && !cfg.AllowSingleReplica {
		shutdown(srv, nc)
		return nil, errors.New("events: external JetStream with one replica requires TRSTCTL_NATS_ALLOW_SINGLE_REPLICA=true (evaluation only)")
	}
	if l.history == nil && cfg.Mode == config.NATSEmbedded {
		l.history = newLocalHistoryRewriteCoordinator()
	}
	stream, err := l.recoverOrCreateActiveStream(ctx, scfg)
	if err != nil && scfg.Replicas > 1 && isNonClusteredReplicaErr(err) {
		shutdown(srv, nc)
		return nil, fmt.Errorf("events: external JetStream requested %d replicas, but the server is not clustered; use a clustered NATS deployment or set TRSTCTL_NATS_REPLICAS=1 with TRSTCTL_NATS_ALLOW_SINGLE_REPLICA=true for evaluation: %w", scfg.Replicas, err)
	}
	if err != nil {
		shutdown(srv, nc)
		return nil, fmt.Errorf("events: ensure stream: %w", err)
	}
	l.setActiveStream(stream)
	if err := l.checkDurability(ctx); err != nil {
		shutdown(srv, nc)
		return nil, err
	}
	return l, nil
}

// OpenExternalSource opens an existing external trstctl event stream for read-only
// federation. It does not create or mutate the peer stream; it just connects to the
// already-running peer's JetStream and returns a Log value that can Replay/Close it.
func OpenExternalSource(ctx context.Context, url string) (*Log, error) {
	if url == "" {
		return nil, errors.New("events: external source nats url is required")
	}
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, fmt.Errorf("events: connect external source: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		shutdown(nil, nc)
		return nil, fmt.Errorf("events: external source jetstream: %w", err)
	}
	name, err := js.StreamNameBySubject(ctx, activeStreamProbeSubject)
	if err != nil {
		shutdown(nil, nc)
		return nil, fmt.Errorf("events: resolve external source stream: %w", err)
	}
	stream, err := js.Stream(ctx, name)
	if err != nil {
		shutdown(nil, nc)
		return nil, fmt.Errorf("events: open external source stream %q: %w", name, err)
	}
	return &Log{nc: nc, js: js, stream: stream, activeName: name, mode: config.NATSExternal}, nil
}

// jsErrCodeStreamReplicasNotSupported is JetStream's error_code for "replicas > 1
// not supported in non-clustered mode" (10074). The nats.go release pinned here
// does not export a named constant for it, so it is defined locally.
const jsErrCodeStreamReplicasNotSupported jetstream.ErrorCode = 10074

// isNonClusteredReplicaErr reports whether err is JetStream's rejection of a
// replicated stream on a non-clustered server. In strict mode this is a startup
// failure: silently downgrading the source-of-truth log would weaken the operator's
// configured RPO without a visible signal (RESIL-004).
func isNonClusteredReplicaErr(err error) bool {
	var apiErr *jetstream.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode == jsErrCodeStreamReplicasNotSupported
	}
	// Fallback to a substring match if the typed error is not surfaced.
	return strings.Contains(err.Error(), "not supported in non-clustered mode")
}

// streamConfig builds the source-of-truth event stream's JetStream config from
// cfg, resolving the replication factor (SPINE-004): embedded single-node always
// runs with one replica (there is only one server); external (clustered) mode uses
// the configured Replicas, defaulting to config.DefaultExternalReplicas so a single
// NATS node loss neither loses an acked event nor takes the log offline. The log
// itself is intentionally NOT retention-capped here — it is the source of truth.
// Audit retention advances a logical served-query floor after writing and
// verifying a signed archive, but retains every source envelope so rebuild and
// disaster recovery remain complete.
func streamConfig(cfg config.NATS) jetstream.StreamConfig {
	replicas := 1 // embedded is single-node; one replica is the only valid value
	if cfg.Mode == config.NATSExternal {
		replicas = cfg.Replicas
		if replicas <= 0 {
			replicas = config.DefaultExternalReplicas
		}
	}
	return jetstream.StreamConfig{
		Name:        streamName,
		Subjects:    []string{subjectFilter},
		Storage:     jetstream.FileStorage,
		Replicas:    replicas,
		Duplicates:  eventDedupWindow,
		AllowDirect: true, // fast GetMsg-by-sequence for replay
	}
}

func openEmbedded(cfg config.NATS) (*natsserver.Server, *nats.Conn, error) {
	if cfg.StoreDir == "" {
		return nil, nil, errors.New("events: embedded nats requires a store dir")
	}
	// Bound the single-node durability window (RESIL-001). nats-server defaults the
	// JetStream file-store fsync cadence to ~2 minutes, so an ACK is otherwise a
	// page-cache write that a power loss can drop. trstctl tightens it to a short
	// default (config.DefaultEmbeddedSyncInterval), and SyncAlways forces an fsync on
	// every append for a near-zero RPO at a throughput cost. These options only apply
	// to the embedded server; an external cluster manages its own durability.
	syncInterval, err := cfg.SyncIntervalDuration()
	if err != nil {
		return nil, nil, fmt.Errorf("events: embedded sync interval: %w", err)
	}
	if syncInterval <= 0 {
		syncInterval = config.DefaultEmbeddedSyncInterval
	}
	srv, err := natsserver.NewServer(&natsserver.Options{
		ServerName:   "trstctl-events",
		JetStream:    true,
		StoreDir:     cfg.StoreDir,
		DontListen:   true, // in-process only; no network listener
		SyncInterval: syncInterval,
		SyncAlways:   cfg.SyncAlways,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("events: embedded server: %w", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(readyTimeout) {
		srv.Shutdown()
		return nil, nil, errors.New("events: embedded server not ready")
	}
	nc, err := nats.Connect("", nats.InProcessServer(srv))
	if err != nil {
		srv.Shutdown()
		return nil, nil, fmt.Errorf("events: connect embedded: %w", err)
	}
	return srv, nc, nil
}

// Append writes e to the log and returns it with Time, ID, and Sequence set.
//
// Durability (RESIL-001): Append returns after JetStream ACKs the publish, which
// guarantees the event is committed to the stream (and, in a replicated external
// cluster with Replicas>1, to a quorum of nodes). On the embedded single-node,
// file-backed store an ACK is a write to the OS page cache that is fsync'd on the
// configured cadence (config.NATS.SyncInterval, defaulting to a tight ~1s, or every
// append when config.NATS.SyncAlways is set) — so the single-node RPO for events not
// yet backed up is at most that interval. Production should run an external
// replicated cluster, where the quorum ACK makes the loss window effectively zero.
func (l *Log) Append(ctx context.Context, e Event) (Event, error) {
	return l.append(ctx, e, false)
}

// Import appends a source-cluster event into this log while preserving the source
// event identity and timestamp. Federation uses it to make the target event log the
// local source of truth before projecting read state. The JetStream message ID is
// the event ID, so a retry after an import succeeds but before the peer checkpoint
// advances is duplicate-suppressed by the stream.
func (l *Log) Import(ctx context.Context, e Event) (Event, error) {
	return l.append(ctx, e, true)
}

// EnforceLegacySchedulerWriteFloor permanently rejects schema-v1 scheduler runs
// on this Log instance. Production calls it only after the active generation has
// passed sanitation.
func (l *Log) EnforceLegacySchedulerWriteFloor() {
	if l != nil {
		l.rejectLegacySchedulerRuns.Store(true)
	}
}

func (l *Log) append(ctx context.Context, e Event, requireSourceEnvelope bool) (Event, error) {
	if e.Type == "" {
		return Event{}, errors.New("events: event type is required")
	}
	if e.TenantID == "" {
		return Event{}, errors.New("events: tenant_id is required (AN-1)")
	}
	if requireSourceEnvelope && (e.ID == "" || e.Time.IsZero()) {
		return Event{}, errors.New(importMissingField)
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.ID == "" {
		e.ID = NewID()
	}
	// Stamp the payload-shape version (SCHEMA-001). A producer that does not set one
	// gets DefaultSchemaVersion (v1); a producer evolving an existing type's payload
	// sets the next version explicitly so the projector can dispatch on it.
	if e.SchemaVersion == 0 {
		e.SchemaVersion = DefaultSchemaVersion
	}
	if l.rejectLegacySchedulerRuns.Load() &&
		e.Type == schedulerhistory.EventType && e.SchemaVersion <= schedulerhistory.LegacySchemaVersion {
		return Event{}, schedulerhistory.ErrSanitationRequired
	}
	if l.requirePrivacyEventPolicies {
		if err := validateRegisteredPrivacyEventPayload(e.Data, e.Type, e.SchemaVersion); err != nil {
			return Event{}, err
		}
	}
	// Attribute the event to the authenticated caller carried in ctx (R2.1),
	// unless the caller set the actor explicitly. A background/system append with
	// no actor in context stays unattributed.
	if e.Actor == nil {
		if a, ok := ActorFromContext(ctx); ok {
			actor := a
			e.Actor = &actor
		}
	}
	payload, err := json.Marshal(storedEvent{
		ID: e.ID, Type: e.Type, TenantID: e.TenantID, Time: e.Time,
		SchemaVersion: e.SchemaVersion, Data: e.Data, Actor: e.Actor,
	})
	if err != nil {
		return Event{}, err
	}
	subject, err := tenancy.EventSubject(ctx, e.TenantID, subjectPrefix, e.Type)
	if err != nil {
		return Event{}, err
	}
	ack, err := l.publishToActive(ctx, subject, payload, jetstream.WithMsgID(e.ID))
	if err != nil {
		return Event{}, fmt.Errorf("events: append: %w", err)
	}
	if ack.Duplicate {
		// The acknowledged source may finish cutover after the bounded publish
		// view releases but before this canonical read. Sequence preservation lets
		// the read fall forward to the active target.
		canonicalStream, streamErr := l.js.Stream(ctx, ack.Stream)
		if streamErr != nil {
			_, canonicalStream, streamErr = l.resolveActiveStream(ctx)
		}
		if streamErr != nil {
			return Event{}, fmt.Errorf("events: open duplicate canonical stream %q: %w", ack.Stream, streamErr)
		}
		raw, err := canonicalStream.GetMsg(ctx, ack.Sequence)
		if err != nil {
			return Event{}, fmt.Errorf("events: read duplicate canonical event: %w", err)
		}
		canonical, err := decodeStored(raw.Data, raw.Sequence)
		if err != nil {
			return Event{}, err
		}
		if canonical.ID != e.ID {
			return Event{}, fmt.Errorf("events: duplicate id %q resolved to canonical id %q", e.ID, canonical.ID)
		}
		return canonical, nil
	}
	e.Sequence = ack.Sequence
	return e, nil
}

// EventByID scans retained source-of-truth history for one producer identity.
// JetStream remembers message IDs only for its finite duplicate window, so crash
// reconciliation cannot use a fresh Publish ACK to decide whether an older event
// already exists. If corrupted history contains the same ID with different bytes,
// fail closed instead of silently selecting one canonical meaning.
func (l *Log) EventByID(ctx context.Context, eventID string) (Event, bool, error) {
	if strings.TrimSpace(eventID) == "" {
		return Event{}, false, errors.New("events: event id lookup is empty")
	}
	var (
		canonical Event
		found     bool
		unsafe    bool
	)
	err := l.Replay(ctx, 0, func(event Event) error {
		if event.ID != eventID {
			return nil
		}
		requiresSanitation, inspectErr := schedulerhistory.RequiresSanitation(
			event.Type, event.SchemaVersion, event.Data,
		)
		if inspectErr != nil || requiresSanitation {
			unsafe = true
		}
		if !found {
			canonical = event
			found = true
			return nil
		}
		if canonical.Type != event.Type || canonical.TenantID != event.TenantID ||
			!canonical.Time.Equal(event.Time) || canonical.SchemaVersion != event.SchemaVersion ||
			!bytes.Equal(canonical.Data, event.Data) || !reflect.DeepEqual(canonical.Actor, event.Actor) {
			return fmt.Errorf("%w: event id %q has conflicting retained envelopes at sequences %d and %d",
				ErrConflictingEventIdentity,
				eventID, canonical.Sequence, event.Sequence)
		}
		return nil
	})
	if unsafe {
		if err != nil {
			return Event{}, false, errors.Join(schedulerhistory.ErrSanitationRequired, err)
		}
		return Event{}, false, schedulerhistory.ErrSanitationRequired
	}
	return canonical, found, err
}

// EventAtSequence reads one exact immutable envelope without replaying the
// prefix before it. Sparse command-side indexes use this after they have already
// selected an authoritative sequence under WithHistoryRead.
func (l *Log) EventAtSequence(ctx context.Context, sequence uint64) (Event, bool, error) {
	if sequence == 0 {
		return Event{}, false, errors.New("events: event sequence lookup is zero")
	}
	var (
		event Event
		found bool
	)
	err := l.withHistoryRead(ctx, func(readCtx context.Context) error {
		name, stream, head, err := l.resolveReplayStream(readCtx)
		if err != nil {
			return err
		}
		if sequence > head {
			return nil
		}
		raw, err := stream.GetMsg(readCtx, sequence)
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("events: get seq %d: %w", sequence, err)
		}
		event, err = decodeStored(raw.Data, raw.Sequence)
		if err != nil {
			return err
		}
		unsafe, inspectErr := schedulerhistory.RequiresSanitation(
			event.Type, event.SchemaVersion, event.Data,
		)
		if inspectErr != nil || unsafe {
			event = Event{}
			return schedulerhistory.ErrSanitationRequired
		}
		current, err := l.activeStreamName(readCtx)
		if err != nil {
			return fmt.Errorf("events: verify sequence lookup generation: %w", err)
		}
		if current != name {
			return fmt.Errorf("%w: sequence lookup started on %s and ended on %s",
				ErrGenerationChanged, name, current)
		}
		found = true
		return nil
	})
	return event, found, err
}

// Replay invokes fn for every event with sequence >= from (1 means from the
// beginning), in append order. It is deterministic: replaying the same log
// twice yields the same events.
func (l *Log) Replay(ctx context.Context, from uint64, fn func(Event) error) error {
	return l.withHistoryRead(ctx, func(ctx context.Context) error {
		name, stream, head, err := l.resolveReplayStream(ctx)
		if err != nil {
			return err
		}
		if l.rejectLegacySchedulerRuns.Load() {
			if err := l.preflightLegacySchedulerHistory(ctx, stream, head); err != nil {
				return err
			}
		}
		return l.replayResolved(ctx, name, stream, from, head, fn)
	})
}

// ReplayThrough is Replay bounded to the inclusive sequence through. The caller
// can pin one history-generation read, capture its head, and then rebuild exactly
// that prefix even if a new event is appended while the rebuild is running.
// Missing/deleted positions are skipped but remain covered by through, allowing a
// projection checkpoint to advance across a trailing or all-gap restored history.
func (l *Log) ReplayThrough(
	ctx context.Context,
	from, through uint64,
	fn func(Event) error,
) error {
	return l.withHistoryRead(ctx, func(ctx context.Context) error {
		name, stream, head, err := l.resolveReplayStream(ctx)
		if err != nil {
			return err
		}
		if through > head {
			return fmt.Errorf(
				"events: replay cut %d is beyond active generation head %d",
				through, head,
			)
		}
		if l.rejectLegacySchedulerRuns.Load() {
			if err := l.preflightLegacySchedulerHistory(ctx, stream, through); err != nil {
				return err
			}
		}
		return l.replayResolved(ctx, name, stream, from, through, fn)
	})
}

func (l *Log) preflightLegacySchedulerHistory(
	ctx context.Context,
	stream jetstream.Stream,
	through uint64,
) error {
	for sequence := uint64(1); sequence <= through; sequence++ {
		raw, err := stream.GetMsg(ctx, sequence)
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("events: inspect scheduler history seq %d: %w", sequence, err)
		}
		event, err := decodeStored(raw.Data, raw.Sequence)
		if err != nil {
			return err
		}
		unsafe, inspectErr := schedulerhistory.RequiresSanitation(
			event.Type, event.SchemaVersion, event.Data,
		)
		if inspectErr != nil || unsafe {
			return schedulerhistory.ErrSanitationRequired
		}
	}
	return nil
}

func (l *Log) replayActive(ctx context.Context, from uint64, fn func(Event) error) error {
	name, stream, head, err := l.resolveReplayStream(ctx)
	if err != nil {
		return err
	}
	return l.replayResolved(ctx, name, stream, from, head, fn)
}

func (l *Log) resolveReplayStream(
	ctx context.Context,
) (string, jetstream.Stream, uint64, error) {
	name, stream, err := l.resolveActiveStream(ctx)
	if err != nil {
		return "", nil, 0, fmt.Errorf("events: resolve replay stream: %w", err)
	}
	info, err := l.infoForStream(ctx, stream)
	if err != nil {
		return "", nil, 0, fmt.Errorf("events: stream info: %w", err)
	}
	if backupRestoreMetadataPending(info.Config.Metadata) {
		return "", nil, 0, ErrBackupRestoreIncomplete
	}
	return name, stream, info.State.LastSeq, nil
}

func (l *Log) replayResolved(
	ctx context.Context,
	name string,
	stream jetstream.Stream,
	from, through uint64,
	fn func(Event) error,
) error {
	if from == 0 {
		from = 1
	}
	for seq := from; seq <= through; seq++ {
		raw, err := stream.GetMsg(ctx, seq)
		if err != nil {
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				continue // a purged sequence; append-only so this is unexpected but safe
			}
			return fmt.Errorf("events: get seq %d: %w", seq, err)
		}
		var s storedEvent
		if err := json.Unmarshal(raw.Data, &s); err != nil {
			return fmt.Errorf("events: decode seq %d: %w", seq, err)
		}
		// A legacy envelope predating the schema-version field (or a v1 envelope that
		// omits it) reads back as DefaultSchemaVersion, so replay treats it as the
		// baseline payload shape rather than version 0 (SCHEMA-001).
		ver := s.SchemaVersion
		if ver == 0 {
			ver = DefaultSchemaVersion
		}
		if err := fn(Event{
			ID: s.ID, Type: s.Type, TenantID: s.TenantID, Time: s.Time,
			SchemaVersion: ver, Data: s.Data, Sequence: raw.Sequence, Actor: s.Actor,
		}); err != nil {
			return err
		}
	}
	current, err := l.activeStreamName(ctx)
	if err != nil {
		return fmt.Errorf("events: verify replay generation: %w", err)
	}
	if current != name {
		return fmt.Errorf("%w: replay started on %s and ended on %s", ErrGenerationChanged, name, current)
	}
	return nil
}

// Delete removes a single event by its stream sequence. Production logical audit
// retention must not call it: deleting a shared AN-2 envelope makes projection
// rebuild lossy. It remains as a low-level exact-history/legacy-recovery primitive;
// callers must coordinate the history cut and accept that Replay will observe a
// gap.
func (l *Log) Delete(ctx context.Context, seq uint64) error {
	if l.history == nil {
		return errors.New("events: delete requires a history coordinator")
	}
	return l.withHistoryOperationLock(ctx, func(ctx context.Context) error {
		return l.history.WithCutover(ctx, func(ctx context.Context) error {
			if err := l.requireNoPendingBackupRestoreBeforeRecovery(ctx); err != nil {
				return err
			}
			state, err := l.findRewriteStreams(ctx)
			if err != nil {
				return err
			}
			if state != nil {
				if err := l.recoverRewriteStreams(ctx, *state); err != nil {
					return fmt.Errorf("events: recover unfinished rewrite before delete: %w", err)
				}
			}
			_, stream, err := l.resolveActiveStream(ctx)
			if err != nil {
				return fmt.Errorf("events: resolve delete stream: %w", err)
			}
			if err := l.requireNoPendingBackupRestoreStream(ctx, stream); err != nil {
				return err
			}
			if err := stream.DeleteMsg(ctx, seq); err != nil {
				return fmt.Errorf("events: delete seq %d: %w", seq, err)
			}
			return nil
		})
	})
}

// PruneTenantThroughCheckpoint is the legacy physical-prefix deletion primitive.
// It remains only for exact-history recovery/conformance tests. Production audit
// retention must never call it: an archive bundle lacks the exact stored event
// envelopes needed to rebuild every projection. The method still serializes the
// historical operation so tests can reproduce and prove fail-closed recovery from
// data created by an older destructive implementation.
//
// Deprecated: use logical audit checkpoints and retain the complete AN-2 source.
func (l *Log) PruneTenantThroughCheckpoint(
	ctx context.Context,
	tenantID string,
	boundarySequence uint64,
	checkpoint func(context.Context) error,
) error {
	if tenantID == "" {
		return errors.New("events: legacy prefix delete requires tenant_id (AN-1)")
	}
	if boundarySequence == 0 {
		return errors.New("events: legacy prefix delete requires a non-zero checkpoint boundary")
	}
	if l.history == nil {
		return errors.New("events: legacy prefix delete requires a history coordinator")
	}
	return l.withHistoryOperationLock(ctx, func(ctx context.Context) error {
		return l.history.WithCutover(ctx, func(ctx context.Context) error {
			if err := l.requireNoPendingBackupRestoreBeforeRecovery(ctx); err != nil {
				return err
			}
			state, err := l.findRewriteStreams(ctx)
			if err != nil {
				return err
			}
			if state != nil {
				if err := l.recoverRewriteStreams(ctx, *state); err != nil {
					return fmt.Errorf("events: recover unfinished rewrite before retention prune: %w", err)
				}
			}
			_, stream, err := l.resolveActiveStream(ctx)
			if err != nil {
				return fmt.Errorf("events: resolve retention stream: %w", err)
			}
			if err := l.requireNoPendingBackupRestoreStream(ctx, stream); err != nil {
				return err
			}
			info, err := l.infoForStream(ctx, stream)
			if err != nil {
				return fmt.Errorf("events: retention stream info: %w", err)
			}
			first := info.State.FirstSeq
			if first == 0 {
				first = 1
			}
			sequences := make([]uint64, 0)
			for seq := first; seq <= boundarySequence; seq++ {
				raw, err := stream.GetMsg(ctx, seq)
				if errors.Is(err, jetstream.ErrMsgNotFound) {
					continue
				}
				if err != nil {
					return fmt.Errorf("events: inspect retention seq %d: %w", seq, err)
				}
				event, err := decodeStored(raw.Data, raw.Sequence)
				if err != nil {
					return fmt.Errorf("events: decode retention seq %d: %w", seq, err)
				}
				if event.TenantID == tenantID {
					sequences = append(sequences, seq)
				}
			}
			if checkpoint != nil {
				if len(sequences) == 0 || sequences[len(sequences)-1] != boundarySequence {
					return fmt.Errorf(
						"events: retention boundary %d is not the last live event for tenant %s",
						boundarySequence, tenantID,
					)
				}
				if err := checkpoint(ctx); err != nil {
					return fmt.Errorf("events: save retention checkpoint: %w", err)
				}
			}
			for _, seq := range sequences {
				if l.pruneTestHook != nil {
					if err := l.pruneTestHook(seq); err != nil {
						return err
					}
				}
				if err := stream.SecureDeleteMsg(ctx, seq); err != nil &&
					!errors.Is(err, jetstream.ErrMsgNotFound) {
					return fmt.Errorf("events: secure-delete retained seq %d: %w", seq, err)
				}
			}
			return nil
		})
	})
}

// Ping reports whether the event log is reachable — the NATS connection is up and
// JetStream answers with the configured durability. It backs the control plane's
// readiness probe (R2.2 / RESIL-004) so readiness flips when the event spine is
// unavailable or under-replicated.
func (l *Log) Ping(ctx context.Context) error {
	if l.nc != nil && !l.nc.IsConnected() {
		return errors.New("events: nats connection is down")
	}
	return l.withHistoryRead(ctx, func(readCtx context.Context) error {
		_, stream, err := l.resolveActiveStream(readCtx)
		if err != nil {
			return fmt.Errorf("events: resolve readiness stream: %w", err)
		}
		if err := l.requireNoPendingBackupRestoreStream(readCtx, stream); err != nil {
			return err
		}
		return l.checkDurability(readCtx)
	})
}

// StreamReplicas returns the source-of-truth event stream's configured replication
// factor (SPINE-004). It is exported so a config test can assert the stream is
// created replicated in external mode and single-replica in embedded mode.
func (l *Log) StreamReplicas(ctx context.Context) (int, error) {
	info, err := l.streamInfo(ctx)
	if err != nil {
		return 0, fmt.Errorf("events: stream info: %w", err)
	}
	return info.Config.Replicas, nil
}

// ReplicaStatus is the observed vs configured durability state of the
// source-of-truth JetStream stream.
type ReplicaStatus struct {
	Desired  int
	Actual   int
	Degraded bool
}

// StreamReplicaStatus returns the source-of-truth stream's actual and desired
// replica counts. It is used by readiness and metrics so an operator can see
// whether the event log is meeting the configured HA/RPO contract (RESIL-004).
func (l *Log) StreamReplicaStatus(ctx context.Context) (ReplicaStatus, error) {
	info, err := l.streamInfo(ctx)
	if err != nil {
		return ReplicaStatus{}, fmt.Errorf("events: stream info: %w", err)
	}
	return l.replicaStatus(info), nil
}

func (l *Log) checkDurability(ctx context.Context) error {
	info, err := l.streamInfo(ctx)
	if err != nil {
		return fmt.Errorf("events: jetstream unreachable: %w", err)
	}
	status := l.replicaStatus(info)
	if status.Degraded {
		return fmt.Errorf("events: jetstream durability degraded: stream replicas=%d desired=%d", status.Actual, status.Desired)
	}
	return nil
}

func (l *Log) replicaStatus(info *jetstream.StreamInfo) ReplicaStatus {
	actual := 0
	if info != nil {
		actual = info.Config.Replicas
	}
	desired := l.desiredReplicas
	if desired <= 0 {
		desired = actual
	}
	degraded := l.mode == config.NATSExternal && actual < desired
	return ReplicaStatus{Desired: desired, Actual: actual, Degraded: degraded}
}

// StreamStats is the live size/cursor snapshot of the source-of-truth event stream.
type StreamStats struct {
	Messages     uint64
	Bytes        uint64
	LastSequence uint64
}

// StreamStats returns the source-of-truth JetStream stream's live size counters.
// Perf/endurance capture uses this instead of reaching through the Log internals.
func (l *Log) StreamStats(ctx context.Context) (StreamStats, error) {
	info, err := l.streamInfo(ctx)
	if err != nil {
		return StreamStats{}, fmt.Errorf("events: stream info: %w", err)
	}
	return StreamStats{
		Messages:     info.State.Msgs,
		Bytes:        info.State.Bytes,
		LastSequence: info.State.LastSeq,
	}, nil
}

// LastSequence returns the highest sequence currently in the event stream (0 when
// empty). The tailing projection worker uses it to compute projection lag — the gap
// between the log's head and the last sequence the read model has applied (SPINE-009).
func (l *Log) LastSequence(ctx context.Context) (uint64, error) {
	info, err := l.streamInfo(ctx)
	if err != nil {
		return 0, fmt.Errorf("events: stream info: %w", err)
	}
	return info.State.LastSeq, nil
}

// decodeStored converts a stored JetStream message at seq into an Event, applying
// the legacy/zero schema-version normalization (SCHEMA-001).
func decodeStored(data []byte, seq uint64) (Event, error) {
	var s storedEvent
	if err := json.Unmarshal(data, &s); err != nil {
		return Event{}, &EnvelopeDecodeError{Sequence: seq, Err: err}
	}
	ver := s.SchemaVersion
	if ver == 0 {
		ver = DefaultSchemaVersion
	}
	return Event{
		ID: s.ID, Type: s.Type, TenantID: s.TenantID, Time: s.Time,
		SchemaVersion: ver, Data: s.Data, Sequence: seq, Actor: s.Actor,
	}, nil
}

// tailConsumerName is the legacy generation's durable projection consumer. New
// generations resume from the relational projection checkpoint because consumer
// cursors belong to one stream and cannot move across a generation switch.
const tailConsumerName = "trstctl_projector"

// TailCheckpointSource returns the durable sequence already committed by the
// callback's read model. TailFrom invokes it when creating a consumer for a stream
// generation; sequence preservation makes checkpoint+1 the first safe delivery on
// the replacement generation.
type TailCheckpointSource func(context.Context) (uint64, error)

// Tail keeps the original source-compatible entry point. The original stream can
// resume its legacy server-side durable cursor. If this process observes a
// generation switch, its in-memory last-success sequence is enough to continue;
// restarting directly on a replacement generation requires TailFrom.
func (l *Log) Tail(ctx context.Context, fn func(Event) error) error {
	return l.tailFrom(ctx, nil, fn)
}

// TailFrom follows the active stream generation and resumes each new generation
// from the caller's durable projection checkpoint. It holds the shared history
// barrier for one bounded fetch/apply/ack cycle, then releases it so a rewrite can
// cut over without waiting for the lifetime of the tailer.
func (l *Log) TailFrom(
	ctx context.Context,
	checkpoint TailCheckpointSource,
	fn func(Event) error,
) error {
	if checkpoint == nil {
		return errors.New("events: TailFrom requires a durable checkpoint source")
	}
	return l.tailFrom(ctx, checkpoint, fn)
}

func (l *Log) tailFrom(
	ctx context.Context,
	checkpoint TailCheckpointSource,
	fn func(Event) error,
) error {
	if fn == nil {
		return errors.New("events: tail callback is required")
	}
	var (
		consumer           jetstream.Consumer
		consumerGeneration string
		lastApplied        uint64
		haveLastApplied    bool
	)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := l.withHistoryRead(ctx, func(readCtx context.Context) error {
			name, stream, err := l.resolveActiveStream(readCtx)
			if err != nil {
				return fmt.Errorf("events: resolve tail generation: %w", err)
			}
			// Exact restore binds the existing active stream before publishing its
			// first envelope. A long-lived tailer may already have a consumer for
			// that same stream, so checking only during consumer construction would
			// let it apply an artifact-bound partial prefix. Recheck inside every
			// shared history view before fetching; the restore's exclusive cutover
			// cannot install or clear the binding between this check and the fetch.
			if err := l.requireNoPendingBackupRestoreStream(readCtx, stream); err != nil {
				return err
			}
			if consumer == nil || consumerGeneration != name {
				consumer = nil
				consumerGeneration = name

				if checkpoint == nil && !haveLastApplied && name == streamName {
					consumer, err = stream.CreateOrUpdateConsumer(readCtx, jetstream.ConsumerConfig{
						Durable:       tailConsumerName,
						AckPolicy:     jetstream.AckExplicitPolicy,
						DeliverPolicy: jetstream.DeliverAllPolicy,
						FilterSubject: subjectFilter,
						MaxAckPending: 1,
					})
					if err != nil {
						return fmt.Errorf("events: create legacy tail consumer: %w", err)
					}
					info, err := consumer.Info(readCtx)
					if err != nil {
						return fmt.Errorf("events: read legacy tail checkpoint: %w", err)
					}
					lastApplied = info.AckFloor.Stream
					haveLastApplied = true
				} else {
					if checkpoint == nil {
						if !haveLastApplied {
							return errors.New("events: replacement generation tail requires TailFrom with a durable checkpoint source")
						}
					} else {
						// Re-read PostgreSQL for every generation. Another replica
						// may have advanced the shared consumer/checkpoint while this
						// tailer was idle on the previous stream.
						lastApplied, err = checkpoint(readCtx)
						if err != nil {
							return fmt.Errorf("events: read durable tail checkpoint: %w", err)
						}
						haveLastApplied = true
					}
					consumer, err = l.sharedTailConsumer(
						readCtx, stream, lastApplied, checkpoint, name == streamName,
					)
					if err != nil {
						return err
					}
				}
			}

			batch, err := consumer.Fetch(1, jetstream.FetchMaxWait(250*time.Millisecond))
			if err != nil {
				if readCtx.Err() != nil {
					return readCtx.Err()
				}
				return fmt.Errorf("events: tail fetch: %w", err)
			}
			for msg := range batch.Messages() {
				md, metadataErr := msg.Metadata()
				if metadataErr != nil {
					_ = msg.Nak()
					return fmt.Errorf("events: tail metadata: %w", metadataErr)
				}
				ev, decodeErr := decodeStored(msg.Data(), md.Sequence.Stream)
				if decodeErr != nil {
					_ = msg.Nak()
					return decodeErr
				}
				if l.rejectLegacySchedulerRuns.Load() {
					unsafe, inspectErr := schedulerhistory.RequiresSanitation(
						ev.Type, ev.SchemaVersion, ev.Data,
					)
					if inspectErr != nil || unsafe {
						_ = msg.Nak()
						return schedulerhistory.ErrSanitationRequired
					}
				}
				if applyErr := fn(ev); applyErr != nil {
					_ = msg.Nak()
					return fmt.Errorf("events: tail apply seq %d: %w", ev.Sequence, applyErr)
				}
				if ackErr := msg.Ack(); ackErr != nil {
					return fmt.Errorf("events: tail ack seq %d: %w", ev.Sequence, ackErr)
				}
				lastApplied = ev.Sequence
				haveLastApplied = true
			}
			if batchErr := batch.Error(); batchErr != nil && !errors.Is(batchErr, nats.ErrTimeout) {
				if readCtx.Err() != nil {
					return readCtx.Err()
				}
				return fmt.Errorf("events: tail batch: %w", batchErr)
			}
			return nil
		})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
	}
}

func (l *Log) sharedTailConsumer(
	ctx context.Context,
	stream jetstream.Stream,
	durableSequence uint64,
	checkpoint TailCheckpointSource,
	allowLegacyDeliverAll bool,
) (jetstream.Consumer, error) {
	consumer, err := stream.Consumer(ctx, tailConsumerName)
	if err == nil {
		return validateSharedTailConsumer(
			ctx, consumer, durableSequence, checkpoint, allowLegacyDeliverAll,
		)
	}
	if !errors.Is(err, jetstream.ErrConsumerNotFound) {
		return nil, fmt.Errorf("events: open shared tail consumer: %w", err)
	}
	consumer, err = stream.CreateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       tailConsumerName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverByStartSequencePolicy,
		OptStartSeq:   durableSequence + 1,
		FilterSubject: subjectFilter,
		MaxAckPending: 1,
	})
	if err == nil {
		return consumer, nil
	}
	// Another replica can win the absent/create race. Its durable is the one
	// shared cursor for this generation; open and validate it rather than trying
	// to update its immutable start sequence with this replica's newer checkpoint.
	winner, winnerErr := stream.Consumer(ctx, tailConsumerName)
	if winnerErr != nil {
		return nil, fmt.Errorf(
			"events: create shared tail consumer at seq %d: %w",
			durableSequence+1, errors.Join(err, winnerErr),
		)
	}
	return validateSharedTailConsumer(
		ctx, winner, durableSequence, checkpoint, allowLegacyDeliverAll,
	)
}

func validateSharedTailConsumer(
	ctx context.Context,
	consumer jetstream.Consumer,
	durableSequence uint64,
	checkpoint TailCheckpointSource,
	allowLegacyDeliverAll bool,
) (jetstream.Consumer, error) {
	info, err := consumer.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("events: read shared tail consumer: %w", err)
	}
	cfg := info.Config
	if cfg.Durable != tailConsumerName ||
		cfg.AckPolicy != jetstream.AckExplicitPolicy ||
		cfg.FilterSubject != subjectFilter ||
		cfg.MaxAckPending != 1 {
		return nil, errors.New("events: shared tail consumer has an unsafe configuration")
	}
	switch cfg.DeliverPolicy {
	case jetstream.DeliverAllPolicy:
		if !allowLegacyDeliverAll {
			return nil, errors.New("events: replacement generation cannot use a legacy deliver-all tail cursor")
		}
	case jetstream.DeliverByStartSequencePolicy:
		if cfg.OptStartSeq == 0 {
			return nil, errors.New("events: shared tail consumer has no start sequence")
		}
	default:
		return nil, errors.New("events: shared tail consumer has an unsafe delivery policy")
	}
	refreshCheckpoint := func() error {
		if checkpoint == nil {
			return nil
		}
		refreshed, err := checkpoint(ctx)
		if err != nil {
			return fmt.Errorf("events: refresh durable tail checkpoint: %w", err)
		}
		durableSequence = refreshed
		return nil
	}
	if cfg.DeliverPolicy == jetstream.DeliverByStartSequencePolicy &&
		cfg.OptStartSeq > durableSequence+1 {
		if err := refreshCheckpoint(); err != nil {
			return nil, err
		}
	}
	if cfg.DeliverPolicy == jetstream.DeliverByStartSequencePolicy &&
		cfg.OptStartSeq > durableSequence+1 {
		return nil, fmt.Errorf(
			"events: shared tail consumer starts at %d beyond durable checkpoint %d",
			cfg.OptStartSeq, durableSequence,
		)
	}
	if info.AckFloor.Stream > durableSequence {
		if err := refreshCheckpoint(); err != nil {
			return nil, err
		}
	}
	if info.AckFloor.Stream > durableSequence {
		return nil, fmt.Errorf(
			"events: shared tail cursor %d is ahead of durable projection checkpoint %d",
			info.AckFloor.Stream, durableSequence,
		)
	}
	return consumer, nil
}

// Close closes the connection and, in embedded mode, shuts the server down.
func (l *Log) Close() error {
	shutdown(l.srv, l.nc)
	return nil
}

func shutdown(srv *natsserver.Server, nc *nats.Conn) {
	if nc != nil {
		nc.Close()
	}
	if srv != nil {
		srv.Shutdown()
		srv.WaitForShutdown()
	}
}
