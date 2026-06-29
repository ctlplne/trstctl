package events

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/privacyref"
)

func TestPseudonymizeSubjectSecureRewritesHotLogStorage(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
	)
	log, err := Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	actorCtx := ContextWithActor(ctx, Actor{Subject: subject, Roles: []string{"admin"}})
	if _, err := log.Append(actorCtx, Event{
		Type:     "owner.created",
		TenantID: tenantID,
		Data:     []byte(`{"name":"alice@example.com","subject":"CN=alice@example.com","nested":["keep","alice@example.com"]}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if raw := rawStreamBytes(t, log); !bytes.Contains(raw, []byte(subject)) {
		t.Fatalf("expected raw hot-log storage to contain the subject before erasure, got %s", raw)
	}

	if err := log.PseudonymizeSubject(ctx, tenantID, subject); err != nil {
		t.Fatalf("PseudonymizeSubject: %v", err)
	}
	raw := rawStreamBytes(t, log)
	if bytes.Contains(raw, []byte(subject)) {
		t.Fatalf("hot-log storage still contains erased subject bytes: %s", raw)
	}
	placeholder := privacyref.Placeholder(privacyref.SubjectRef(tenantID, subject))
	if !bytes.Contains(raw, []byte(placeholder)) {
		t.Fatalf("hot-log storage = %s, want erasure placeholder %q", raw, placeholder)
	}

	var got []Event
	if err := log.Replay(ctx, 0, func(e Event) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("replayed %d events, want 1 sanitized event", len(got))
	}
	if got[0].Actor == nil || got[0].Actor.Subject != placeholder {
		t.Fatalf("replayed actor = %+v, want placeholder %q", got[0].Actor, placeholder)
	}
	if bytes.Contains(got[0].Data, []byte(subject)) || !bytes.Contains(got[0].Data, []byte(placeholder)) {
		t.Fatalf("replayed data = %s, want placeholder and no raw subject", got[0].Data)
	}
}

func rawStreamBytes(t *testing.T, log *Log) []byte {
	t.Helper()
	info, err := log.streamInfo(context.Background())
	if err != nil {
		t.Fatalf("streamInfo: %v", err)
	}
	var out []byte
	for seq := uint64(1); seq <= info.State.LastSeq; seq++ {
		msg, err := log.stream.GetMsg(context.Background(), seq)
		if err != nil {
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				continue
			}
			t.Fatalf("GetMsg(%d): %v", seq, err)
		}
		out = append(out, msg.Data...)
	}
	return out
}
