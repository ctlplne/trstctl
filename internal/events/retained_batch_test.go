// SPDX-License-Identifier: MPL-2.0

package events

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Recovery must inspect the complete retained cut without paying a network
// request for every event. This checks actual NATS traffic and the delivered
// sequence, rather than a mocked transport or a timing threshold.
func TestRetainedReplayBoundsTransportRequests(t *testing.T) {
	log := openBackupHistoryTestLog(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	const count = 512
	for i := 0; i < count; i++ {
		if _, err := log.Append(ctx, Event{
			Type: "test.retained-batch", TenantID: "batch-transport-tenant",
			Data: []byte(`{"public_marker":"bounded-history-read"}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	before := log.nc.Stats()
	started := time.Now()
	var seen uint64
	if err := log.ReplayThrough(ctx, 1, count, func(e Event) error {
		seen++
		if e.Sequence != seen || string(e.Data) != `{"public_marker":"bounded-history-read"}` {
			t.Fatalf("retained sequence %d returned another event", seen)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after := log.nc.Stats()
	t.Logf("512-event replay: %s, %d transport requests", time.Since(started), after.OutMsgs-before.OutMsgs)
	if seen != count {
		t.Fatalf("replay returned %d of %d retained events", seen, count)
	}
	if requests := after.OutMsgs - before.OutMsgs; requests > 32 {
		t.Fatalf("replay issued %d requests for %d retained events; batch the read without omitting source history", requests, count)
	}
}

func TestRetainedBatchPreservesSparseCutAndCallbackCancellation(t *testing.T) {
	log, _, stream, head := retainedReadFixture(t)
	ctx := t.Context()
	for _, seq := range []uint64{1, 4, head} {
		if err := stream.DeleteMsg(ctx, seq); err != nil {
			t.Fatal(err)
		}
	}
	var got []uint64
	if err := log.ReplayThrough(ctx, 1, head, func(e Event) error {
		got = append(got, e.Sequence)
		if len(got) == 1 {
			_, err := log.Append(ctx, Event{Type: "test.after-cut", TenantID: "batch-tenant", Data: []byte(`{}`)})
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var want []uint64
	for seq := uint64(2); seq < head; seq++ {
		if seq != 4 {
			want = append(want, seq)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sparse pinned replay = %v, want %v", got, want)
	}
	stop := errors.New("stop callback")
	before := log.nc.NumSubscriptions()
	seen := 0
	err := log.ReplayThrough(ctx, 1, head, func(Event) error { seen++; return stop })
	if !errors.Is(err, stop) || seen != 1 || log.nc.NumSubscriptions() != before {
		t.Fatalf("callback termination leaked work: seen=%d err=%v subscriptions=%d/%d", seen, err, log.nc.NumSubscriptions(), before)
	}
}

func TestRetainedBatchDoesNotTreatLegacy404AsEmptyHistory(t *testing.T) {
	log, stream := fakeRetainedBatch(t, func() []*nats.Msg {
		return []*nats.Msg{{Header: nats.Header{"Status": {"404"}}}}
	})
	for i := 0; i < 3; i++ {
		if _, err := log.Append(t.Context(), Event{Type: "test.fallback-gap", TenantID: "batch-tenant", Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.stream.DeleteMsg(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	var got []uint64
	if err := stream.readRetainedRange(t.Context(), 1, 3, func(raw *jetstream.RawStreamMsg) error {
		got = append(got, raw.Sequence)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []uint64{2, 3}) {
		t.Fatalf("legacy missing-first-message response hid history: %v", got)
	}
}

func batchTestMessage(sequence, prior, pending uint64) *nats.Msg {
	return &nats.Msg{Header: nats.Header{
		"Nats-Stream": {"qa-batch"}, "Nats-Subject": {"events.test.public"},
		"Nats-Sequence":      {strconv.FormatUint(sequence, 10)},
		"Nats-Last-Sequence": {strconv.FormatUint(prior, 10)},
		"Nats-Num-Pending":   {strconv.FormatUint(pending, 10)},
		"Nats-Time-Stamp":    {"2026-09-15T10:00:00Z"},
	}, Data: []byte("public event")}
}

func batchTestEnd(last, pending uint64) *nats.Msg {
	return &nats.Msg{Header: nats.Header{
		"Status": {"204"}, "Nats-Last-Sequence": {strconv.FormatUint(last, 10)},
		"Nats-Num-Pending": {strconv.FormatUint(pending, 10)},
	}}
}

func fakeRetainedBatch(t *testing.T, messages func() []*nats.Msg) (*Log, retainedBatchStream) {
	t.Helper()
	log := openBackupHistoryTestLog(t)
	sub, err := log.nc.Subscribe("_QA.BATCH.DIRECT.GET.qa-batch", func(request *nats.Msg) {
		for _, msg := range messages() {
			msg.Subject = request.Reply
			if err := log.nc.PublishMsg(msg); err != nil {
				t.Errorf("publish test response: %v", err)
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	// Unsubscribe stops future dispatch but does not join a callback already
	// publishing its response. Join the subscription worker before the earlier
	// log cleanup closes the connection or the test's lifetime ends.
	done := make(chan struct{})
	sub.SetClosedHandler(func(string) { close(done) })
	t.Cleanup(func() {
		if err := sub.Unsubscribe(); err != nil && !errors.Is(err, nats.ErrConnectionClosed) {
			t.Errorf("unsubscribe test responder: %v", err)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("test responder did not finish before connection teardown")
		}
	})
	return log, retainedBatchStream{Stream: log.stream, nc: log.nc, name: "qa-batch", prefix: "_QA.BATCH.", timeout: time.Second}
}

func TestRetainedBatchRefusesIncompleteOrConflictingTransportBeforeCallbacks(t *testing.T) {
	cases := map[string]func() []*nats.Msg{
		"missing first response": func() []*nats.Msg { return []*nats.Msg{batchTestMessage(2, 1, 0), batchTestEnd(2, 0)} },
		"wrong stream": func() []*nats.Msg {
			m := batchTestMessage(1, 0, 0)
			m.Header.Set("Nats-Stream", "another-stream")
			return []*nats.Msg{m, batchTestEnd(1, 0)}
		},
		"wrong final sequence": func() []*nats.Msg { return []*nats.Msg{batchTestMessage(1, 0, 0), batchTestEnd(2, 0)} },
		"ambiguous sequence": func() []*nats.Msg {
			m := batchTestMessage(1, 0, 0)
			m.Header.Add("Nats-Sequence", "2")
			return []*nats.Msg{m, batchTestEnd(1, 0)}
		},
		"ambiguous status": func() []*nats.Msg { m := batchTestEnd(0, 0); m.Header.Add("Status", "500"); return []*nats.Msg{m} },
		"no progress":      func() []*nats.Msg { return []*nats.Msg{batchTestEnd(0, 5)} },
		"partial 404": func() []*nats.Msg {
			return []*nats.Msg{batchTestMessage(1, 0, 0), {Header: nats.Header{"Status": {"404"}}}}
		},
		"wrong timestamp": func() []*nats.Msg {
			m := batchTestMessage(1, 0, 0)
			m.Header.Set("Nats-Time-Stamp", "invalid")
			return []*nats.Msg{m, batchTestEnd(1, 0)}
		},
		"over message count": func() []*nats.Msg {
			return []*nats.Msg{batchTestMessage(1, 0, 1), batchTestMessage(2, 1, 0), batchTestEnd(2, 0)}
		},
		"missing trailer": func() []*nats.Msg { return []*nats.Msg{batchTestMessage(1, 0, 0)} },
	}
	for name, messages := range cases {
		t.Run(name, func(t *testing.T) {
			log, stream := fakeRetainedBatch(t, messages)
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			before := log.nc.NumSubscriptions()
			seen := 0
			err := stream.readRetainedRange(ctx, 1, 1, func(*jetstream.RawStreamMsg) error { seen++; return nil })
			if err == nil || seen != 0 || log.nc.NumSubscriptions() != before {
				t.Fatalf("unsafe batch exposed a callback or leaked a subscription: seen=%d err=%v subscriptions=%d/%d", seen, err, log.nc.NumSubscriptions(), before)
			}
		})
	}
}

func TestRetainedBatchFallsBackBeforeCallbacksForOlderDirectGrammar(t *testing.T) {
	log, stream := fakeRetainedBatch(t, func() []*nats.Msg {
		m := batchTestMessage(1, 0, 0)
		m.Header.Del("Nats-Last-Sequence")
		m.Header.Del("Nats-Num-Pending")
		return []*nats.Msg{m}
	})
	for i := 0; i < 3; i++ {
		if _, err := log.Append(t.Context(), Event{Type: "test.fallback", TenantID: "batch-tenant", Data: []byte(`{"actual":true}`)}); err != nil {
			t.Fatal(err)
		}
	}
	var got []uint64
	if err := stream.readRetainedRange(t.Context(), 1, 3, func(raw *jetstream.RawStreamMsg) error {
		e, err := decodeStored(raw.Data, raw.Sequence)
		if err != nil {
			return err
		}
		if e.Type != "test.fallback" {
			t.Fatal("old direct response escaped instead of the actual source envelope")
		}
		got = append(got, raw.Sequence)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []uint64{1, 2, 3}) {
		t.Fatalf("fallback sequence = %v", got)
	}
}
