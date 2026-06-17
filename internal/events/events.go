package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nuid"

	"trstctl.com/trstctl/internal/config"
)

const (
	streamName    = "TRSTCTL_EVENTS"
	subjectPrefix = "events"
	subjectFilter = "events.>"

	readyTimeout = 10 * time.Second
)

// DefaultSchemaVersion is the schema version stamped on every appended event
// whose producer does not set one explicitly, and the version assumed for a
// legacy stored event that predates the field (SCHEMA-001). It is the baseline
// (v1) payload shape for each event type; bump the producer's SchemaVersion when
// an existing type's payload shape changes so a version-aware projector can tell
// old events from new ones on replay rather than silently mis-projecting them.
const DefaultSchemaVersion = 1

// Event is the immutable envelope appended to the AN-2 event log. The event log
// is the source of truth; both the relational read state and the audit trail
// are projections of these events.
type Event struct {
	ID       string    // unique event id (assigned on Append if empty)
	Type     string    // event type, e.g. "tenant.registered"
	TenantID string    // AN-1: every event carries its tenant
	Time     time.Time // emit time (assigned on Append if zero)
	Data     []byte    // opaque domain payload
	Sequence uint64    // stream sequence; assigned on Append and set on Replay
	Actor    *Actor    // who performed the mutation (R2.1); nil for system/background events

	// SchemaVersion is the payload-shape version of this event's Type (SCHEMA-001,
	// AN-2). It is assigned DefaultSchemaVersion on Append when left zero, and is
	// reconstructed on Replay (a legacy event with no stored version reads back as
	// DefaultSchemaVersion). A projector dispatches on (Type, SchemaVersion) so a
	// payload-shape change to an existing type cannot silently mis-project on a
	// rebuild — the new shape carries a new version and old events keep theirs.
	SchemaVersion int
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

// Log is the append-only event log on NATS JetStream (AN-2). In embedded mode it
// runs an in-process, file-backed JetStream server needing no external services;
// in external mode it connects to a NATS cluster by URL. Switching between them
// is config-only.
type Log struct {
	srv    *natsserver.Server // non-nil only in embedded mode
	nc     *nats.Conn
	js     jetstream.JetStream
	stream jetstream.Stream
	mode   string
	// desiredReplicas is the durability contract the control plane was configured
	// to require for the source-of-truth event stream. Readiness compares it with
	// the observed JetStream stream config so an under-replicated external stream
	// fails visible instead of serving with a weaker RPO than operators asked for.
	desiredReplicas int
	// infoMu serializes stream.Info() calls. The JetStream client caches the result
	// in the shared stream handle without locking, so two concurrent Info() callers
	// race on that cache (data race in (*stream).Info). LastSequence is now called
	// from a background lag sampler (SPINE-009) concurrently with API/health callers,
	// so every Info() on the shared handle goes through this lock.
	infoMu sync.Mutex
}

// streamInfo fetches fresh stream info under infoMu so concurrent callers do not race
// on the JetStream client's internal info cache. Holding the lock across the (fast)
// JetStream round-trip is fine: the only contention is the periodic lag sampler.
func (l *Log) streamInfo(ctx context.Context) (*jetstream.StreamInfo, error) {
	l.infoMu.Lock()
	defer l.infoMu.Unlock()
	return l.stream.Info(ctx)
}

// Open opens the event log according to cfg and ensures the event stream exists.
func Open(ctx context.Context, cfg config.NATS) (*Log, error) {
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
	scfg := streamConfig(cfg)
	if cfg.Mode == config.NATSExternal && scfg.Replicas == 1 && !cfg.AllowSingleReplica {
		shutdown(srv, nc)
		return nil, errors.New("events: external JetStream with one replica requires TRSTCTL_NATS_ALLOW_SINGLE_REPLICA=true (evaluation only)")
	}
	stream, err := js.CreateOrUpdateStream(ctx, scfg)
	if err != nil && scfg.Replicas > 1 && isNonClusteredReplicaErr(err) {
		shutdown(srv, nc)
		return nil, fmt.Errorf("events: external JetStream requested %d replicas, but the server is not clustered; use a clustered NATS deployment or set TRSTCTL_NATS_REPLICAS=1 with TRSTCTL_NATS_ALLOW_SINGLE_REPLICA=true for evaluation: %w", scfg.Replicas, err)
	}
	if err != nil {
		shutdown(srv, nc)
		return nil, fmt.Errorf("events: ensure stream: %w", err)
	}
	l := &Log{srv: srv, nc: nc, js: js, stream: stream, mode: cfg.Mode, desiredReplicas: scfg.Replicas}
	if err := l.checkDurability(ctx); err != nil {
		shutdown(srv, nc)
		return nil, err
	}
	return l, nil
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
// itself is intentionally NOT retention-capped here — it is the source of truth, and
// the only path that shrinks it is the signed archive-then-prune retention worker
// (Audit.Retention/ArchiveDir), so an operator opts into bounding it rather than the
// stream silently dropping events.
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
	if e.Type == "" {
		return Event{}, errors.New("events: event type is required")
	}
	if e.TenantID == "" {
		return Event{}, errors.New("events: tenant_id is required (AN-1)")
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.ID == "" {
		e.ID = nuid.Next()
	}
	// Stamp the payload-shape version (SCHEMA-001). A producer that does not set one
	// gets DefaultSchemaVersion (v1); a producer evolving an existing type's payload
	// sets the next version explicitly so the projector can dispatch on it.
	if e.SchemaVersion == 0 {
		e.SchemaVersion = DefaultSchemaVersion
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
	ack, err := l.js.Publish(ctx, subjectPrefix+"."+e.Type, payload)
	if err != nil {
		return Event{}, fmt.Errorf("events: append: %w", err)
	}
	e.Sequence = ack.Sequence
	return e, nil
}

// Replay invokes fn for every event with sequence >= from (1 means from the
// beginning), in append order. It is deterministic: replaying the same log
// twice yields the same events.
func (l *Log) Replay(ctx context.Context, from uint64, fn func(Event) error) error {
	if from == 0 {
		from = 1
	}
	info, err := l.streamInfo(ctx)
	if err != nil {
		return fmt.Errorf("events: stream info: %w", err)
	}
	for seq := from; seq <= info.State.LastSeq; seq++ {
		raw, err := l.stream.GetMsg(ctx, seq)
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
	return nil
}

// Delete removes a single event by its stream sequence. It is the one exception
// to the append-only discipline (AN-2), used solely by the audit retention worker
// (R4.4): an event is deleted only after it has been archived to cold storage as a
// signed, offline-verifiable bundle and sealed behind a signed checkpoint, so the
// authoritative history is preserved (archive + live log) and the audit chain
// stays verifiable across the prune. Replay tolerates the resulting gap.
func (l *Log) Delete(ctx context.Context, seq uint64) error {
	if err := l.stream.DeleteMsg(ctx, seq); err != nil {
		return fmt.Errorf("events: delete seq %d: %w", seq, err)
	}
	return nil
}

// Ping reports whether the event log is reachable — the NATS connection is up and
// JetStream answers with the configured durability. It backs the control plane's
// readiness probe (R2.2 / RESIL-004) so readiness flips when the event spine is
// unavailable or under-replicated.
func (l *Log) Ping(ctx context.Context) error {
	if l.nc != nil && !l.nc.IsConnected() {
		return errors.New("events: nats connection is down")
	}
	if l.stream == nil {
		return nil
	}
	return l.checkDurability(ctx)
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
		return Event{}, fmt.Errorf("events: decode seq %d: %w", seq, err)
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

// tailConsumerName is the durable name of the projection-tailing consumer
// (SPINE-009). A fixed name makes the consumer durable: its acked position (the
// cursor) is stored on the server and survives a control-plane restart, so the
// tailer resumes from the last applied event rather than replaying from the start.
const tailConsumerName = "trstctl_projector"

// Tail creates (or resumes) the durable projection consumer over the event stream
// and invokes fn for each event in order, advancing the durable cursor only after fn
// returns nil (SPINE-009). It blocks until ctx is cancelled. Because the cursor is
// server-side and durable, an event appended out of band (not by the in-process
// orchestrator) is projected promptly without a restart, and a restart resumes from
// the last applied sequence instead of re-replaying the whole log.
//
// It uses a pull consumer drained in small batches: fn applies the event, and only a
// success acks it (advancing the cursor); a failure leaves the event unacked so the
// next fetch retries it rather than silently skipping — the read model never diverges
// past a poison event without an operator signal (the lag metric stops advancing).
func (l *Log) Tail(ctx context.Context, fn func(Event) error) error {
	cons, err := l.stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       tailConsumerName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverAllPolicy, // first start: from the beginning; later: resumes from the durable cursor
		FilterSubject: subjectFilter,
		MaxAckPending: 1, // strict in-order application: one unacked event at a time
	})
	if err != nil {
		return fmt.Errorf("events: create tail consumer: %w", err)
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		batch, err := cons.Fetch(64, jetstream.FetchMaxWait(250*time.Millisecond))
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("events: tail fetch: %w", err)
		}
		for msg := range batch.Messages() {
			md, mderr := msg.Metadata()
			if mderr != nil {
				_ = msg.Nak()
				return fmt.Errorf("events: tail metadata: %w", mderr)
			}
			ev, derr := decodeStored(msg.Data(), md.Sequence.Stream)
			if derr != nil {
				_ = msg.Nak()
				return derr
			}
			if aerr := fn(ev); aerr != nil {
				// Leave the event unacked so the cursor does not advance past a failure;
				// the next fetch retries it. The caller's lag metric will plateau, which is
				// the operator signal that the projection is stuck (SPINE-009/SPINE-011).
				_ = msg.Nak()
				return fmt.Errorf("events: tail apply seq %d: %w", ev.Sequence, aerr)
			}
			if ackErr := msg.Ack(); ackErr != nil {
				return fmt.Errorf("events: tail ack seq %d: %w", ev.Sequence, ackErr)
			}
		}
		if berr := batch.Error(); berr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("events: tail batch: %w", berr)
		}
	}
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
