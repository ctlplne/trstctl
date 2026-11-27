// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"trstctl.com/trstctl/internal/crypto/eventauth"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/inputtext"
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

// MaxEventDataBytes bounds one original producer payload before it reaches
// JetStream. A larger event must be split into bounded records by its producer.
const MaxEventDataBytes = 1 << 20

var ErrEventPayloadTooLarge = errors.New("events: event payload exceeds 1 MiB")

var ErrEventWireTooLarge = errors.New("events: encoded event exceeds the broker payload limit")

// ErrConflictingEventIdentity means retained source history contains one event
// ID with more than one immutable envelope. Recovery must fail closed because no
// caller can safely choose which command the producer identity means.
var ErrConflictingEventIdentity = errors.New("events: conflicting event identity")

// ErrPublish marks an append that reached the bus and was not acknowledged: the
// envelope had already passed validation, so a producer may retry it under the
// same ID and rely on the stream's duplicate window. Appends the log refuses
// for a deterministic reason do not carry it.
var ErrPublish = errors.New("events: publish not acknowledged")

// DefaultSchemaVersion is defined in internal/eventspec (a NATS-free leaf) and
// re-exported here so existing events.DefaultSchemaVersion references keep working.
const DefaultSchemaVersion = eventspec.DefaultSchemaVersion

// Event is the immutable AN-2 event envelope. Its definition lives in
// internal/eventspec so projection-only packages (e.g. internal/succession) can construct
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
	ID                   string                      `json:"id"`
	Type                 string                      `json:"type"`
	TenantID             string                      `json:"tenant_id"`
	Time                 time.Time                   `json:"time"`
	SchemaVersion        int                         `json:"v,omitempty"`
	Data                 []byte                      `json:"data,omitempty"`
	Actor                *Actor                      `json:"actor,omitempty"`
	Protection           *eventspec.ProtectedPayload `json:"protection,omitempty"`
	PayloadSchemaVersion int                         `json:"payload_v,omitempty"`
	Authentication       []byte                      `json:"auth,omitempty"`
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
	// appendAdmission encloses normalized Append and Import payloads before
	// either reaches the common JetStream publish path.
	appendAdmission AppendAdmission
	// ingressWireStage commits the exact serialized candidate hash before the
	// first broker call. Production supplies a target-local journal adapter.
	ingressWireStage IngressWireStage
	// ingressCanonicalProof receives the raw-wire identity resolved from the
	// acknowledged stream before the caller may settle its journal row.
	ingressCanonicalProof IngressCanonicalProof
	// fixtureAppendAdmission is an explicit test-owned mode for standalone
	// event-log fixtures that have no PostgreSQL-backed ingress adapter.
	fixtureAppendAdmission bool
	// requiredAppendAdmission prevents a production composition from silently
	// publishing when its PostgreSQL-backed admission adapter is absent.
	requiredAppendAdmission bool
	// backupHistoryAdmission surrounds the raw stream restore path, including
	// direct library calls that bypass server maintenance commands.
	backupHistoryAdmission         BackupHistoryAdmission
	backupHistoryJournal           BackupHistoryJournal
	requiredBackupHistoryAdmission bool
	// appendObserver, when set, hears how long each Append and Import took
	// (measurement only: the perf harness's per-request breakdown, CI-L37).
	appendObserver func(time.Duration)
	srv            *natsserver.Server // non-nil only in embedded mode
	nc             *nats.Conn
	js             jetstream.JetStream
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
	eventProtection             *EventProtection
	eventAuth                   *eventauth.File
	// rejectLegacySchedulerRuns is installed only after startup sanitation. It
	// closes every normal live/federated ingress path while the restore-only path
	// remains able to stage an authenticated pre-patch artifact for sanitation.
	rejectLegacySchedulerRuns atomic.Bool
	// legacySafety is a process-local verified prefix. Stream metadata fences it
	// against deletion and generation changes; a cold process must verify again.
	legacySafetyMu      sync.Mutex
	legacySafety        schedulerSafetyState
	legacySafeThrough   uint64
	legacySafetyPresent bool
	// idIndexMu serializes this process's event-ID projection catch-up. The
	// projection itself is a separate file-backed JetStream stream and survives
	// process crashes; cross-replica writes use per-subject compare-and-swap.
	idIndexMu sync.Mutex
	// backgroundIDIndex runs the identity indexer (WithBackgroundEventIDIndexer);
	// idIndexKick wakes it after an append, idIndexStop and idIndexDone end it
	// at Close.
	backgroundIDIndex bool
	idIndexAppends    atomic.Uint64
	idIndexKick       chan struct{}
	idIndexStop       context.CancelFunc
	idIndexDone       chan struct{}
	idIndexCloseOnce  sync.Once
	// tenantIndexMu serializes this process's source-ordered tenant index
	// catch-up. The index stream's last-sequence CAS orders other replicas.
	tenantIndexMu sync.Mutex
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
	// eventIDLookupPinnedTestHook runs after an identity lookup pinned its head
	// and before it takes the index lock: the window in which a concurrent
	// lookup can index past that head.
	eventIDLookupPinnedTestHook func()
}

// streamInfo fetches metadata through a private client handle. NATS Stream handles
// contain a mutable metadata cache, so an independently resolved handle is the
// concurrency boundary between a lag/readiness sample and an overlapping replay.
func (l *Log) streamInfo(ctx context.Context) (*jetstream.StreamInfo, error) {
	_, stream, err := l.resolveActiveStream(ctx)
	if err != nil {
		return nil, err
	}
	return cachedInfoForResolvedStream(stream)
}

// OpenOption configures event-log coordination without coupling this package to
// PostgreSQL or another concrete distributed-lock implementation.
type OpenOption func(*Log)

// AppendAdmission owns prepublish checks and may refuse without invoking
// publish. Its callback must remain active through the broker ACK, including
// when event protection wraps the payload before publication.
type AppendAdmission func(context.Context, Event, func(context.Context) (Event, error)) (Event, error)

// IngressWireStage records the candidate wire hash under the active ingress
// token. A failure must keep the broker untouched; an ambiguous later ACK
// leaves this staged hash pending for canonical reconciliation.
type IngressWireStage func(context.Context, Event, string) error

// IngressCanonicalProof receives the attempted event, authenticated returned
// canonical event, raw NATS wire hash and whether the broker discarded a
// duplicate candidate. A failed proof leaves the admitted attempt unresolved.
type IngressCanonicalProof func(context.Context, Event, Event, string, bool) error

// BackupHistoryAdmission stays live through stream binding, every raw write,
// and the final broker confirmation. Production supplies a target-local guard.
type BackupHistoryAdmission func(context.Context, uint64, string, func(context.Context) (int, error)) (int, error)

// BackupHistoryJournal durably stages one exact raw record before broker I/O.
// run returns nil only after the target record has been read back and matched.
// A failed or ambiguous run leaves the start pending for same-artifact resume.
type BackupHistoryJournal func(context.Context, uint64, string, string, BackupHistoryRecord,
	func(context.Context) error) error

func WithBackupHistoryJournal(journal BackupHistoryJournal) OpenOption {
	return func(log *Log) { log.backupHistoryJournal = journal }
}

func WithAppendAdmission(admit AppendAdmission) OpenOption {
	return func(log *Log) { log.appendAdmission = admit }
}

func WithIngressWireStage(stage IngressWireStage) OpenOption {
	return func(log *Log) { log.ingressWireStage = stage }
}

func WithIngressCanonicalProof(proof IngressCanonicalProof) OpenOption {
	return func(log *Log) { log.ingressCanonicalProof = proof }
}

// WithFixtureAppendAdmission permits standalone test logs to append without a
// production store adapter. It cannot satisfy a required-production source.
// Source census limits its callers to tests and test support.
func WithFixtureAppendAdmission() OpenOption {
	return func(log *Log) { log.fixtureAppendAdmission = true }
}

// WithRequiredAppendAdmission makes a missing ingress adapter a write refusal
// for both Append and Import. Production composition installs this separately
// from the adapter so an accidentally omitted or nil adapter fails closed.
func WithRequiredAppendAdmission() OpenOption {
	return func(log *Log) { log.requiredAppendAdmission = true }
}

var ErrAppendAdmissionUnavailable = errors.New("events: required append admission is unavailable")

// Production sources cannot physically remove the AN-2 event history through
// the legacy recovery/conformance helpers. The exact restore owner has its own
// separately admitted raw-history path.
var ErrLegacyHistoryMutationUnavailable = errors.New("events: legacy physical history mutation is unavailable on a production source")

func WithBackupHistoryAdmission(admit BackupHistoryAdmission) OpenOption {
	return func(log *Log) { log.backupHistoryAdmission = admit }
}

// WithRequiredBackupHistoryAdmission makes both raw restore APIs refuse a
// missing target-local admission adapter before reading their source artifact.
func WithRequiredBackupHistoryAdmission() OpenOption {
	return func(log *Log) { log.requiredBackupHistoryAdmission = true }
}

var ErrBackupHistoryAdmissionUnavailable = errors.New("events: required backup-history admission is unavailable")

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

// WithBackgroundEventIDIndexer keeps the event identity projection within one
// lookup's reach in the background: one goroutine, woken every
// eventIDIndexerKickEvery appends and every eventIDIndexerInterval, indexes
// in eventIDIndexBatch pages once the projection is more than
// eventIDIndexerLag events behind, under the same history read view and lock
// a lookup takes, releasing them between pages.
// Without it the projection advanced only at Open and by a bounded step per
// lookup, so a burst of appends with no lookups (an inventory import) left
// every keyed lookup refusing with ErrEventIDIndexBehind until enough lookups
// had caught it up. A lookup still fails closed, exactly as before, when the
// projection is behind its pinned head by more than its bounded catch-up.
func WithBackgroundEventIDIndexer() OpenOption {
	return func(log *Log) { log.backgroundIDIndex = true }
}

// WithAppendObserver has the log report each Append's and Import's wall time to
// observe, after it returns. It measures and changes nothing; the perf harness
// uses it to split an issuance's time (CI-L37).
func WithAppendObserver(observe func(time.Duration)) OpenOption {
	return func(log *Log) { log.appendObserver = observe }
}

// Open opens the event log according to cfg and ensures one active generation
// owns events.>. opts is variadic to keep existing callers source-compatible.
func Open(ctx context.Context, cfg config.NATS, opts ...OpenOption) (*Log, error) {
	var authenticator *eventauth.File
	if cfg.EventAuthKeyFile != "" {
		authenticator = &eventauth.File{Path: cfg.EventAuthKeyFile}
		if err := authenticator.Validate(); err != nil {
			return nil, fmt.Errorf("events: event authentication key: %w", err)
		}
	}
	var (
		srv *natsserver.Server
		nc  *nats.Conn
		err error
	)
	switch cfg.Mode {
	case config.NATSEmbedded:
		srv, nc, err = openEmbedded(cfg)
	case config.NATSExternal:
		nc, err = dialExternalNATS(cfg)
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
	l := &Log{srv: srv, nc: nc, js: js, mode: cfg.Mode, duplicateWindow: eventDedupWindow, eventAuth: authenticator}
	for _, opt := range opts {
		if opt != nil {
			opt(l)
		}
	}
	if l.requiredAppendAdmission && l.fixtureAppendAdmission {
		shutdown(srv, nc)
		return nil, ErrAppendAdmissionUnavailable
	}
	if l.eventProtection != nil && (l.eventProtection.Keys == nil || l.eventProtection.Admission == nil) {
		shutdown(srv, nc)
		return nil, ErrEventProtectionUnavailable
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
	if err := l.warmEventIDIndex(ctx); err != nil && !errors.Is(err, ErrBackupRestoreIncomplete) {
		shutdown(srv, nc)
		return nil, fmt.Errorf("events: rebuild event identity index: %w", err)
	}
	if err := l.warmTenantIndex(ctx); err != nil && !errors.Is(err, ErrBackupRestoreIncomplete) {
		shutdown(srv, nc)
		return nil, fmt.Errorf("events: rebuild tenant event index: %w", err)
	}
	if l.backgroundIDIndex && l.desiredReplicas >= 1 {
		l.startEventIDIndexer()
	}
	return l, nil
}

// OpenExternalSource opens an existing external trstctl event stream for read-only
// federation. It does not create or mutate the peer stream; it just connects to the
// already-running peer's JetStream and returns a Log value that can Replay/Close it.
func OpenExternalSource(ctx context.Context, cfg config.NATS) (*Log, error) {
	var authenticator *eventauth.File
	if cfg.EventAuthKeyFile != "" {
		authenticator = &eventauth.File{Path: cfg.EventAuthKeyFile}
		if err := authenticator.Validate(); err != nil {
			return nil, fmt.Errorf("events: external source authentication key: %w", err)
		}
	}
	nc, err := dialExternalNATS(cfg)
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
	return &Log{nc: nc, js: js, stream: stream, activeName: name, mode: config.NATSExternal, eventAuth: authenticator}, nil
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
	if l.appendObserver != nil {
		defer l.observeAppend(time.Now())
	}
	out, err := l.append(ctx, e, false)
	if err == nil {
		l.kickEventIDIndexer()
	}
	return out, err
}

func (l *Log) observeAppend(start time.Time) { l.appendObserver(time.Since(start)) }

// Import appends a source-cluster event into this log while preserving the source
// event identity and timestamp. Federation uses it to make the target event log the
// local source of truth before projecting read state. The JetStream message ID is
// the event ID, so a retry after an import succeeds but before the peer checkpoint
// advances is duplicate-suppressed by the stream.
func (l *Log) Import(ctx context.Context, e Event) (Event, error) {
	if l.appendObserver != nil {
		defer l.observeAppend(time.Now())
	}
	out, err := l.append(ctx, e, true)
	if err == nil {
		l.kickEventIDIndexer()
	}
	return out, err
}

// EnforceLegacySchedulerWriteFloor permanently rejects schema-v1 scheduler runs
// on this Log instance. Production calls it only after the active generation has
// passed sanitation.
func (l *Log) EnforceLegacySchedulerWriteFloor() {
	if l != nil {
		l.rejectLegacySchedulerRuns.Store(true)
	}
}

// ValidateEventText applies the same PostgreSQL text safety check to newly
// appended events and to retained pre-upgrade events during projection replay.
// Opaque non-JSON Data remains opaque, as required by the event-log contract.
func ValidateEventText(e Event) error {
	for _, field := range []string{e.ID, e.Type, e.TenantID} {
		if err := inputtext.ValidateString(field); err != nil {
			return fmt.Errorf("events: unsafe envelope text: %w", err)
		}
	}
	if e.Actor != nil {
		if err := inputtext.ValidateString(e.Actor.Subject); err != nil {
			return fmt.Errorf("events: unsafe actor subject: %w", err)
		}
		for _, role := range e.Actor.Roles {
			if err := inputtext.ValidateString(role); err != nil {
				return fmt.Errorf("events: unsafe actor role: %w", err)
			}
		}
	}
	if err := inputtext.ValidateJSONStrings(e.Data); err != nil {
		return fmt.Errorf("events: unsafe payload text: %w", err)
	}
	return nil
}

func (l *Log) append(ctx context.Context, e Event, requireSourceEnvelope bool) (Event, error) {
	if e.Protection != nil || e.SensitiveErased {
		return Event{}, errors.New("events: append requires an original readable producer payload")
	}
	explicitTime := !e.Time.IsZero()
	if e.Type == "" {
		return Event{}, errors.New("events: event type is required")
	}
	if e.TenantID == "" {
		return Event{}, errors.New("events: tenant_id is required (AN-1)")
	}
	// An exact retained-history import may need to preserve an older event
	// that predates this limit. Only live producer appends are admission-limited.
	if !requireSourceEnvelope && len(e.Data) > MaxEventDataBytes {
		return Event{}, ErrEventPayloadTooLarge
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
	// PostgreSQL cannot project U+0000 into text or jsonb. Validate the exact
	// producer envelope before admission or JetStream publication; otherwise one
	// rejected projection leaves an immutable poison event for every later replay.
	if err := ValidateEventText(e); err != nil {
		return Event{}, err
	}
	if l.appendAdmission != nil {
		producerDigest, err := appendProducerDigest(e, explicitTime)
		if err != nil {
			return Event{}, err
		}
		producerScope := &ingressProducerScope{digest: producerDigest, explicitTime: explicitTime, imported: requireSourceEnvelope, history: l}
		producerScope.active = true
		defer func() {
			producerScope.mu.Lock()
			producerScope.active = false
			producerScope.mu.Unlock()
			producerScope.historyCalls.Wait()
			secret.Wipe(producerDigest)
		}()
		var callbackMu sync.Mutex
		var callbackInFlight sync.WaitGroup
		callbackActive, callbackUsed := true, false
		defer func() {
			callbackMu.Lock()
			callbackActive = false
			callbackMu.Unlock()
			callbackInFlight.Wait()
		}()
		return l.appendAdmission(context.WithValue(ctx, ingressProducerContextKey{}, producerScope), e, func(admitted context.Context) (Event, error) {
			callbackMu.Lock()
			if !callbackActive || callbackUsed {
				callbackMu.Unlock()
				return Event{}, ErrAppendAdmissionUnavailable
			}
			callbackUsed = true
			callbackInFlight.Add(1)
			callbackMu.Unlock()
			defer callbackInFlight.Done()
			return l.withAppendGrant(admitted, e, explicitTime, func(granted context.Context) (Event, error) {
				return l.appendWithEventProtection(granted, e, explicitTime)
			})
		})
	}
	if l.requiredAppendAdmission || !l.fixtureAppendAdmission {
		return Event{}, ErrAppendAdmissionUnavailable
	}
	if SealedBearingEvent(e) {
		return Event{}, ErrFixtureSealedAdmissionRequired
	}
	return l.withAppendGrant(ctx, e, explicitTime, func(granted context.Context) (Event, error) {
		return l.appendWithEventProtection(granted, e, explicitTime)
	})
}

func (l *Log) publishPreparedEvent(ctx context.Context, e Event) (Event, error) {
	if err := l.requireAppendGrant(ctx, e); err != nil {
		return Event{}, err
	}
	stored, err := storedForEvent(e)
	if err != nil {
		return Event{}, err
	}
	payload, err := l.marshalStored(stored)
	if err != nil {
		return Event{}, err
	}
	if l.nc == nil || l.nc.MaxPayload() <= 0 || int64(len(payload)) > l.nc.MaxPayload() {
		return Event{}, ErrEventWireTooLarge
	}
	subject, err := tenancy.EventSubject(ctx, e.TenantID, subjectPrefix, e.Type)
	if err != nil {
		return Event{}, err
	}
	if l.ingressWireStage != nil {
		if err := l.ingressWireStage(ctx, e, crypto.SHA256Hex(payload)); err != nil {
			return Event{}, err
		}
	}
	ack, err := l.publishToActive(ctx, subject, payload, jetstream.WithMsgID(e.ID))
	if err != nil {
		return Event{}, fmt.Errorf("events: append: %w: %w", ErrPublish, err)
	}
	if ack.Duplicate {
		// The acknowledged source may finish cutover after the bounded publish
		// view releases but before this canonical read. Sequence preservation lets
		// the read fall forward to the active target.
		canonical, rawHash, err := l.acknowledgedCanonicalRaw(ctx, ack.Stream, ack.Sequence)
		if err != nil {
			return Event{}, err
		}
		if canonical.ID != e.ID {
			return Event{}, fmt.Errorf("events: duplicate id %q resolved to canonical id %q", e.ID, canonical.ID)
		}
		sealedBearing := sealedBearingEventType(e.Type) || sealedBearingEventType(canonical.Type) ||
			hasSealedBearingField(e.Data) || hasSealedBearingField(canonical.Data)
		if (canonical.Protection != nil || sealedBearing) &&
			(canonical.TenantID != e.TenantID || canonical.Type != e.Type || canonical.SchemaVersion != e.SchemaVersion) {
			return Event{}, ErrConflictingEventIdentity
		}
		if sealedBearing && canonical.Protection == nil &&
			(!bytes.Equal(canonical.Data, e.Data) || !sameProtectedActorEncoding(canonical.Actor, e.Actor)) {
			return Event{}, ErrConflictingEventIdentity
		}
		opened, err := l.openProtectedEvent(ctx, canonical)
		if err != nil {
			return Event{}, err
		}
		if canonical.Protection != nil {
			grant, _ := ctx.Value(appendGrantContextKey{}).(*appendGrant)
			if grant == nil || !bytes.Equal(opened.Data, e.Data) ||
				!sameProtectedActorEncoding(opened.Actor, e.Actor) ||
				(grant.explicitTime && !opened.Time.Equal(e.Time)) {
				return Event{}, ErrConflictingEventIdentity
			}
		}
		if l.ingressCanonicalProof != nil {
			if err := l.ingressCanonicalProof(ctx, e, opened, rawHash, true); err != nil {
				return Event{}, err
			}
		}
		return opened, nil
	}
	e.Sequence = ack.Sequence
	if l.ingressCanonicalProof != nil {
		canonical, rawHash, err := l.acknowledgedCanonicalRaw(ctx, ack.Stream, ack.Sequence)
		if err != nil {
			return Event{}, err
		}
		if rawHash != crypto.SHA256Hex(payload) || canonical.ID != e.ID ||
			canonical.TenantID != e.TenantID || canonical.Type != e.Type ||
			!canonical.Time.Equal(e.Time) || canonical.SchemaVersion != e.SchemaVersion {
			return Event{}, ErrConflictingEventIdentity
		}
		opened, err := l.openProtectedEvent(ctx, canonical)
		if err != nil {
			return Event{}, err
		}
		if !bytes.Equal(opened.Data, e.Data) || !sameProtectedActorEncoding(opened.Actor, e.Actor) {
			return Event{}, ErrConflictingEventIdentity
		}
		if err := l.ingressCanonicalProof(ctx, e, opened, rawHash, false); err != nil {
			return Event{}, err
		}
	}
	return e, nil
}

// PreflightAppendCapacity is a conservative producer check before a command
// commits its pending row. Sensitive events may be encrypted and encoded once
// more before publication, so reserve three raw-envelope lengths plus 8 KiB
// for the protected wrapper. The exact wire check still runs before ingress
// staging in publishPreparedEvent.
func (l *Log) PreflightAppendCapacity(e Event) error {
	if l == nil || l.nc == nil || l.nc.MaxPayload() <= 0 {
		return ErrEventWireTooLarge
	}
	stored, err := storedForEvent(e)
	if err != nil {
		return err
	}
	payload, err := l.marshalStored(stored)
	if err != nil {
		return err
	}
	if int64(len(payload))*3+(8<<10) > l.nc.MaxPayload() {
		return ErrEventWireTooLarge
	}
	return nil
}

func (l *Log) acknowledgedCanonicalRaw(ctx context.Context, streamName string,
	sequence uint64,
) (Event, string, error) {
	canonicalStream, err := l.js.Stream(ctx, streamName)
	if err != nil {
		_, canonicalStream, err = l.resolveActiveStream(ctx)
	}
	if err != nil {
		return Event{}, "", fmt.Errorf("events: open acknowledged canonical stream %q: %w", streamName, err)
	}
	raw, err := canonicalStream.GetMsg(ctx, sequence)
	if err != nil {
		return Event{}, "", fmt.Errorf("events: read acknowledged canonical event: %w", err)
	}
	canonical, err := l.decodeStored(raw.Data, raw.Sequence)
	if err != nil {
		return Event{}, "", err
	}
	return canonical, crypto.SHA256Hex(raw.Data), nil
}

// EventByID reads the durable, generation-specific identity projection and then
// verifies the exact canonical source envelope. The projection cursor must cover
// the pinned head before absence or a conflict-free match is returned. A bounded
// catch-up can advance the cursor after another replica's append; larger lag is
// retried without scanning the full history on this request path.
func (l *Log) EventByID(ctx context.Context, eventID string) (Event, bool, error) {
	var event Event
	var found bool
	err := l.withHistoryRead(ctx, func(readCtx context.Context) error {
		var err error
		event, found, err = l.rawEventByID(readCtx, eventID)
		if found && (err == nil || errors.Is(err, ErrConflictingEventIdentity)) {
			var openErr error
			event, openErr = l.openProtectedEvent(readCtx, event)
			err = errors.Join(err, openErr)
		}
		return err
	})
	return event, found, err
}

// eventIDLookupPins bounds how often one identity lookup pins a fresh head
// after concurrent lookups indexed past the one it held.
const eventIDLookupPins = 8

// errEventIDIndexPastPin is a lookup's pinned head falling behind the identity
// index: another lookup, holding a newer head, indexed past it between the pin
// and the index lock. The snapshot is stale, not the index; pin again.
var errEventIDIndexPastPin = fmt.Errorf("%w: identity projection advanced past the pinned head", ErrGenerationChanged)

func (l *Log) rawEventByID(ctx context.Context, eventID string) (Event, bool, error) {
	if strings.TrimSpace(eventID) == "" {
		return Event{}, false, errors.New("events: event id lookup is empty")
	}
	for pin := 1; ; pin++ {
		canonical, found, err := l.rawEventByIDPinned(ctx, eventID)
		if errors.Is(err, errEventIDIndexPastPin) && pin < eventIDLookupPins {
			continue
		}
		return canonical, found, err
	}
}

// rawEventByIDPinned is one identity lookup against one pinned head.
func (l *Log) rawEventByIDPinned(ctx context.Context, eventID string) (Event, bool, error) {
	var (
		canonical Event
		found     bool
	)
	err := l.withHistoryRead(ctx, func(ctx context.Context) error {
		name, stream, head, err := l.resolveReplayStream(ctx)
		if err != nil {
			return err
		}
		if l.eventIDLookupPinnedTestHook != nil {
			l.eventIDLookupPinnedTestHook()
		}
		state, err := l.schedulerSafetySnapshot(ctx)
		if err != nil {
			return err
		}
		if state.Name != name || state.LastSequence < head {
			return ErrGenerationChanged
		}
		l.idIndexMu.Lock()
		index, epoch, err := l.eventIDIndexFor(ctx, state)
		if err != nil {
			l.idIndexMu.Unlock()
			return err
		}
		covered, _, err := readEventIDCursor(ctx, index, epoch, l.eventAuth)
		if err != nil {
			l.idIndexMu.Unlock()
			return err
		}
		if covered > head {
			l.idIndexMu.Unlock()
			return errEventIDIndexPastPin
		}
		limit := min(head, covered+eventIDIndexReadLimit)
		for covered < limit {
			cut := min(limit, covered+eventIDIndexBatch)
			covered, err = l.indexEventIDsThrough(ctx, stream, state, cut)
			if err != nil {
				l.idIndexMu.Unlock()
				return err
			}
		}
		if covered > head {
			l.idIndexMu.Unlock()
			return ErrGenerationChanged
		}
		if covered < head {
			l.idIndexMu.Unlock()
			return fmt.Errorf("%w: covered %d of %d", ErrEventIDIndexBehind, covered, head)
		}
		entry, _, indexed, err := readEventIDEntry(ctx, index, epoch, eventID, l.eventAuth)
		l.idIndexMu.Unlock()
		if err != nil {
			return err
		}
		if err := l.preflightLegacySchedulerHistory(ctx, stream, head); err != nil {
			if entry.Conflict {
				return errors.Join(err, ErrConflictingEventIdentity)
			}
			return err
		}
		if indexed {
			raw, err := stream.GetMsg(ctx, entry.Sequence)
			if err != nil {
				return fmt.Errorf("events: indexed canonical seq %d: %w", entry.Sequence, err)
			}
			if crypto.SHA256Hex(raw.Data) != entry.Digest {
				return errors.New("events: indexed canonical envelope differs from retained source")
			}
			canonical, err = l.decodeStored(raw.Data, entry.Sequence)
			if err != nil {
				return err
			}
			if canonical.ID != eventID {
				return errors.New("events: indexed event ID differs from retained source")
			}
			found = true
		}
		after, err := l.schedulerSafetySnapshot(ctx)
		if err != nil {
			return err
		}
		if !appendOnlySince(state, after) || l.eventIDIndexEpoch(state) != l.eventIDIndexEpoch(after) {
			return ErrGenerationChanged
		}
		if entry.Conflict {
			return fmt.Errorf("%w: event id %q has conflicting retained envelopes", ErrConflictingEventIdentity, eventID)
		}
		return nil
	})
	if err != nil && !errors.Is(err, ErrConflictingEventIdentity) {
		return Event{}, false, err
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
		event, err = l.decodeStored(raw.Data, raw.Sequence)
		if err != nil {
			return err
		}
		if err := l.verifyAuthenticatedPosition(readCtx, event); err != nil {
			return err
		}
		event, err = l.openProtectedEvent(readCtx, event)
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
	return l.preflightSchedulerPrefix(ctx, stream, through)
}

func (l *Log) resolveReplayStream(
	ctx context.Context,
) (string, jetstream.Stream, uint64, error) {
	name, stream, err := l.resolveActiveStream(ctx)
	if err != nil {
		return "", nil, 0, fmt.Errorf("events: resolve replay stream: %w", err)
	}
	info, err := cachedInfoForResolvedStream(stream)
	if err != nil {
		return "", nil, 0, fmt.Errorf("events: stream info: %w", err)
	}
	if backupRestoreMetadataPending(info.Config.Metadata) {
		return "", nil, 0, ErrBackupRestoreIncomplete
	}
	return name, l.retainedTransport(stream, info), info.State.LastSeq, nil
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
	if err := readRetainedEventsThrough(ctx, stream, from, through, func(event Event) error {
		if err := l.verifyAuthenticatedPosition(ctx, event); err != nil {
			return err
		}
		opened, err := l.openProtectedEvent(ctx, event)
		if err != nil {
			return err
		}
		return fn(opened)
	}, l.decodeStored); err != nil {
		return err
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
	if l.requiredAppendAdmission {
		return ErrLegacyHistoryMutationUnavailable
	}
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
			name, stream, err := l.resolveActiveStream(ctx)
			if err != nil {
				return fmt.Errorf("events: resolve delete stream: %w", err)
			}
			if err := l.requireNoPendingBackupRestoreStream(ctx, stream); err != nil {
				return err
			}
			if err := l.discardEventIDIndexesAtCutover(ctx, name); err != nil {
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
	if l.requiredAppendAdmission {
		return ErrLegacyHistoryMutationUnavailable
	}
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
			name, stream, err := l.resolveActiveStream(ctx)
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
				event, err := l.decodeStored(raw.Data, raw.Sequence)
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
			if len(sequences) > 0 {
				if err := l.discardEventIDIndexesAtCutover(ctx, name); err != nil {
					return err
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

// StreamSnapshot identifies the exact active history state observed under the
// generation read barrier. A caller may reuse a projection only while every
// field is unchanged: an append moves LastSequence, a deletion changes the
// retained counters, and a restore changes the generation or stream name.
type StreamSnapshot struct {
	Name          string
	Generation    string
	FirstSequence uint64
	LastSequence  uint64
	Messages      uint64
	Bytes         uint64
	NumDeleted    int
}

// Snapshot returns metadata for the active event generation without replaying
// its payloads. It does not establish that the payloads are safe to read; a
// caller must first finish a full Replay and cache only that verified snapshot.
func (l *Log) Snapshot(ctx context.Context) (StreamSnapshot, error) {
	var snapshot StreamSnapshot
	err := l.withHistoryRead(ctx, func(readCtx context.Context) error {
		name, stream, err := l.resolveActiveStream(readCtx)
		if err != nil {
			return err
		}
		info, err := cachedInfoForResolvedStream(stream)
		if err != nil {
			return err
		}
		if backupRestoreMetadataPending(info.Config.Metadata) {
			return ErrBackupRestoreIncomplete
		}
		generation := streamGeneration(info)
		if generation == "" {
			return errors.New("events: active stream has no generation identity")
		}
		snapshot = StreamSnapshot{
			Name: name, Generation: generation,
			FirstSequence: info.State.FirstSeq, LastSequence: info.State.LastSeq,
			Messages: info.State.Msgs, Bytes: info.State.Bytes,
			NumDeleted: info.State.NumDeleted,
		}
		return nil
	})
	if err != nil {
		return StreamSnapshot{}, fmt.Errorf("events: active stream snapshot: %w", err)
	}
	return snapshot, nil
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
	if err := validateStoredProtection(s); err != nil {
		return Event{}, &EnvelopeDecodeError{Sequence: seq, Err: err}
	}
	if s.Protection != nil {
		canonical, err := json.Marshal(s)
		if err != nil || !bytes.Equal(canonical, data) {
			return Event{}, &EnvelopeDecodeError{Sequence: seq, Err: eventprotect.ErrEnvelope}
		}
	}
	ver := s.SchemaVersion
	if s.Protection != nil {
		ver = s.PayloadSchemaVersion
	}
	if ver == 0 {
		ver = DefaultSchemaVersion
	}
	return Event{
		ID: s.ID, Type: s.Type, TenantID: s.TenantID, Time: s.Time,
		SchemaVersion: ver, Data: s.Data, Sequence: seq, Actor: s.Actor, Protection: s.Protection,
	}, nil
}

// tailConsumerName is the legacy generation's durable projection consumer. New
// generations resume from the relational projection checkpoint because consumer
// cursors belong to one stream and cannot move across a generation switch.
const tailConsumerName = "trstctl_projector"

// tailAckConfirmationTimeout bounds the final server-confirmed acknowledgment
// after a projection callback has durably committed. That acknowledgment uses a
// context which survives caller cancellation: otherwise a shutdown arriving in
// the few instructions between commit and ack can leave JetStream's single
// MaxAckPending slot occupied until redelivery, hiding every newer event.
const tailAckConfirmationTimeout = 5 * time.Second

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
	var callback func(context.Context, Event) error
	if fn != nil {
		callback = func(_ context.Context, event Event) error { return fn(event) }
	}
	return l.tailFrom(ctx, nil, nil, callback)
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
	var callback func(context.Context, Event) error
	if fn != nil {
		callback = func(_ context.Context, event Event) error { return fn(event) }
	}
	return l.tailFrom(ctx, checkpoint, nil, callback)
}

// TailFromAdmitted lets a production worker acquire restore and key-state
// admission before each history read. The admitted context reaches the event
// callback, so nested projection and custody checks borrow the same grants.
func (l *Log) TailFromAdmitted(
	ctx context.Context, checkpoint TailCheckpointSource,
	admit func(context.Context, func(context.Context) error) error,
	fn func(context.Context, Event) error,
) error {
	if checkpoint == nil || admit == nil {
		return errors.New("events: admitted tail requires a checkpoint and admission")
	}
	return l.tailFrom(ctx, checkpoint, admit, fn)
}

func (l *Log) tailFrom(
	ctx context.Context,
	checkpoint TailCheckpointSource,
	admit func(context.Context, func(context.Context) error) error,
	fn func(context.Context, Event) error,
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
		read := func(admitted context.Context) error {
			return l.withHistoryRead(admitted, func(readCtx context.Context) error {
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
					ev, decodeErr := l.decodeStored(msg.Data(), md.Sequence.Stream)
					if decodeErr != nil {
						_ = msg.Nak()
						return decodeErr
					}
					if err := l.verifyAuthenticatedPosition(readCtx, ev); err != nil {
						_ = msg.Nak()
						return err
					}
					ev, decodeErr = l.openProtectedEvent(readCtx, ev)
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
					if applyErr := fn(readCtx, ev); applyErr != nil {
						_ = msg.Nak()
						return fmt.Errorf("events: tail apply seq %d: %w", ev.Sequence, applyErr)
					}
					ackCtx, cancelAck := context.WithTimeout(
						context.WithoutCancel(readCtx), tailAckConfirmationTimeout,
					)
					ackErr := msg.DoubleAck(ackCtx)
					cancelAck()
					if ackErr != nil {
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
		}
		var err error
		if admit != nil {
			err = admit(ctx, read)
		} else {
			err = read(ctx)
		}
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
	l.stopEventIDIndexer()
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
