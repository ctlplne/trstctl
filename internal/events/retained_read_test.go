// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

type retainedReadTestStream struct {
	jetstream.Stream
	get func(context.Context, uint64, ...jetstream.GetMsgOpt) (*jetstream.RawStreamMsg, error)
}

func (s retainedReadTestStream) GetMsg(ctx context.Context, sequence uint64, opts ...jetstream.GetMsgOpt) (*jetstream.RawStreamMsg, error) {
	return s.get(ctx, sequence, opts...)
}

func retainedReadFixture(t *testing.T) (*Log, string, jetstream.Stream, uint64) {
	t.Helper()
	log := openBackupHistoryTestLog(t)
	for i := 0; i < 24; i++ {
		if _, err := log.Append(context.Background(), Event{Type: "test.retained-read", TenantID: "tenant-read-ahead", Data: []byte(`{"marker":"ordered"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	name, stream, head, err := log.resolveReplayStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return log, name, stream, head
}

// A stalled storage round trip must permit a bounded window of later reads,
// while callers still receive exactly the original order from real JetStream.
func TestRetainedReplayReadsAheadWithinBound(t *testing.T) {
	log, name, stream, head := retainedReadFixture(t)
	release := make(chan struct{})
	entered := make(chan uint64, 32)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var active, peak atomic.Int32
	wrapped := retainedReadTestStream{Stream: stream, get: func(ctx context.Context, seq uint64, opts ...jetstream.GetMsgOpt) (*jetstream.RawStreamMsg, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		if seq <= 8 {
			entered <- seq
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-release:
			}
		}
		return stream.GetMsg(ctx, seq, opts...)
	}}
	var got []uint64
	done := make(chan error, 1)
	go func() {
		done <- log.replayResolved(context.Background(), name, wrapped, 1, head, func(e Event) error { got = append(got, e.Sequence); return nil })
	}()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	reached := 0
wait:
	for reached < 4 {
		select {
		case <-entered:
			reached++
		case <-timer.C:
			break wait
		}
	}
	unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("replay did not finish after releasing storage")
	}
	if reached < 4 {
		t.Errorf("only %d storage read(s) progressed while the first request was stalled; sequential history reads accumulate round-trip latency", reached)
	}
	if peak.Load() > 8 {
		t.Errorf("unbounded retained reads: peak=%d", peak.Load())
	}
	want := make([]uint64, head)
	for i := range want {
		want[i] = uint64(i + 1)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("callback order=%v want=%v", got, want)
	}
	if active.Load() != 0 {
		t.Fatal("storage reads outlived replay")
	}
}

// One slow read must not idle every otherwise available lane at an artificial
// batch boundary. Publication stays ordered even when later reads finish first.
func TestRetainedReplayKeepsAvailableReadLanesBusy(t *testing.T) {
	log, name, stream, head := retainedReadFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	ahead := make(chan struct{}, 1)
	wrapped := retainedReadTestStream{Stream: stream, get: func(ctx context.Context, seq uint64, opts ...jetstream.GetMsgOpt) (*jetstream.RawStreamMsg, error) {
		if seq == 8 {
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if seq == 9 {
			ahead <- struct{}{}
		}
		return stream.GetMsg(ctx, seq, opts...)
	}}
	var got []uint64
	done := make(chan error, 1)
	go func() {
		done <- log.replayResolved(ctx, name, wrapped, 1, head, func(e Event) error {
			got = append(got, e.Sequence)
			return nil
		})
	}()
	progressed := false
	select {
	case <-ahead:
		progressed = true
	case <-time.After(time.Second):
	}
	unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("replay did not join its readers")
	}
	if !progressed {
		t.Error("one slow request idled available read lanes at the batch boundary")
	}
	want := make([]uint64, head)
	for i := range want {
		want[i] = uint64(i + 1)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("callbacks=%v want=%v", got, want)
	}
}

func TestRetainedReplayCancellationJoinsReaders(t *testing.T) {
	log, name, stream, head := retainedReadFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 32)
	var active atomic.Int32
	wrapped := retainedReadTestStream{Stream: stream, get: func(ctx context.Context, _ uint64, _ ...jetstream.GetMsgOpt) (*jetstream.RawStreamMsg, error) {
		active.Add(1)
		defer active.Add(-1)
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	done := make(chan error, 1)
	var callbacks atomic.Int32
	go func() {
		done <- log.replayResolved(ctx, name, wrapped, 1, head, func(Event) error { callbacks.Add(1); return nil })
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("no read started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled replay did not return")
	}
	if active.Load() != 0 || callbacks.Load() != 0 {
		t.Fatalf("active=%d callbacks=%d", active.Load(), callbacks.Load())
	}
}

func TestRetainedReplayStopsAtOrderedError(t *testing.T) {
	for _, cause := range []string{"callback", "storage", "wrong-sequence"} {
		t.Run(cause, func(t *testing.T) {
			log, name, stream, head := retainedReadFixture(t)
			sentinel := errors.New("retained-read fixture failure")
			wrapped := retainedReadTestStream{Stream: stream, get: func(ctx context.Context, seq uint64, opts ...jetstream.GetMsgOpt) (*jetstream.RawStreamMsg, error) {
				if seq == 2 {
					return nil, jetstream.ErrMsgNotFound
				}
				if seq == 4 && cause == "storage" {
					return nil, sentinel
				}
				raw, err := stream.GetMsg(ctx, seq, opts...)
				if seq == 4 && cause == "wrong-sequence" && err == nil {
					raw.Sequence = 99
				}
				return raw, err
			}}
			var got []uint64
			err := log.replayResolved(context.Background(), name, wrapped, 1, head, func(e Event) error {
				got = append(got, e.Sequence)
				if cause == "callback" && e.Sequence == 4 {
					return sentinel
				}
				return nil
			})
			want := []uint64{1, 3}
			if cause == "callback" {
				want = append(want, 4)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("callbacks=%v want=%v", got, want)
			}
			if cause == "wrong-sequence" {
				if err == nil || !strings.Contains(err.Error(), "wrong sequence") {
					t.Fatalf("error=%v", err)
				}
			} else if !errors.Is(err, sentinel) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
