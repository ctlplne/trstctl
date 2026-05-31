package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nuid"

	"certctl.io/certctl/internal/config"
)

const (
	streamName    = "CERTCTL_EVENTS"
	subjectPrefix = "events"
	subjectFilter = "events.>"

	readyTimeout = 10 * time.Second
)

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
}

// storedEvent is the on-disk JSON envelope (the stream sequence is supplied by
// JetStream and is not stored in the payload).
type storedEvent struct {
	ID       string    `json:"id"`
	Type     string    `json:"type"`
	TenantID string    `json:"tenant_id"`
	Time     time.Time `json:"time"`
	Data     []byte    `json:"data,omitempty"`
	Actor    *Actor    `json:"actor,omitempty"`
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
		srv, nc, err = openEmbedded(cfg.StoreDir)
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
	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:        streamName,
		Subjects:    []string{subjectFilter},
		Storage:     jetstream.FileStorage,
		AllowDirect: true, // fast GetMsg-by-sequence for replay
	})
	if err != nil {
		shutdown(srv, nc)
		return nil, fmt.Errorf("events: ensure stream: %w", err)
	}
	return &Log{srv: srv, nc: nc, js: js, stream: stream}, nil
}

func openEmbedded(storeDir string) (*natsserver.Server, *nats.Conn, error) {
	if storeDir == "" {
		return nil, nil, errors.New("events: embedded nats requires a store dir")
	}
	srv, err := natsserver.NewServer(&natsserver.Options{
		ServerName: "certctl-events",
		JetStream:  true,
		StoreDir:   storeDir,
		DontListen: true, // in-process only; no network listener
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

// Append writes e to the log and returns it with Time, ID, and Sequence set. The
// event is durably persisted before Append returns.
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
		ID: e.ID, Type: e.Type, TenantID: e.TenantID, Time: e.Time, Data: e.Data, Actor: e.Actor,
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
	info, err := l.stream.Info(ctx)
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
		if err := fn(Event{
			ID: s.ID, Type: s.Type, TenantID: s.TenantID, Time: s.Time, Data: s.Data, Sequence: raw.Sequence, Actor: s.Actor,
		}); err != nil {
			return err
		}
	}
	return nil
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
