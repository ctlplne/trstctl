// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

func retainedDecodePage(t testing.TB, count int) []*jetstream.RawStreamMsg {
	t.Helper()
	page := make([]*jetstream.RawStreamMsg, count)
	for i := range page {
		body, err := json.Marshal(storedEvent{
			ID: fmt.Sprintf("decode-%d", i), Type: "test.retained-decode", TenantID: "decode-tenant",
			Time:  time.Date(2026, 9, 15, 12, 0, i%60, 0, time.UTC),
			Data:  bytes.Repeat([]byte("public-event-payload"), 128),
			Actor: &Actor{Subject: "operator", Roles: []string{"reader"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		page[i] = &jetstream.RawStreamMsg{Sequence: uint64(i*3 + 1), Data: body}
	}
	return page
}

func TestRetainedDecodePagePreservesOrderAndIndependentCallbackData(t *testing.T) {
	page := retainedDecodePage(t, retainedBatchMessages)
	var got []Event
	if err := visitDecodedRetainedPage(t.Context(), page, func(event Event) error {
		if len(got) > 0 {
			// A callback may keep or modify a previous event. Its buffers must
			// not alias a concurrent decode or a later callback's envelope.
			got[len(got)-1].Data[0] = '!'
			got[len(got)-1].Actor.Roles[0] = "changed"
		}
		i := len(got)
		if event.Sequence != uint64(i*3+1) || event.ID != fmt.Sprintf("decode-%d", i) || event.SchemaVersion != DefaultSchemaVersion ||
			!bytes.Equal(event.Data, bytes.Repeat([]byte("public-event-payload"), 128)) || event.Actor.Roles[0] != "reader" {
			t.Fatalf("callback %d received another or mutated event", i)
		}
		got = append(got, event)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(page) {
		t.Fatalf("decoded %d of %d envelopes", len(got), len(page))
	}
}

func TestRetainedDecodePageKeepsFirstErrorAndCancellationOrder(t *testing.T) {
	page := retainedDecodePage(t, retainedBatchMessages)
	// Both are malformed. A fast later decoder must not hide the first error,
	// or prevent callbacks for the valid source prefix from running in order.
	page[2].Data = []byte(`{"data":"not valid base64!"}`)
	page[4].Data = []byte(`{"v":"wrong type"}`)
	var seen []uint64
	err := visitDecodedRetainedPage(t.Context(), page, func(event Event) error {
		seen = append(seen, event.Sequence)
		return nil
	})
	var decodeErr *EnvelopeDecodeError
	if !errors.As(err, &decodeErr) || decodeErr.Sequence != page[2].Sequence || !reflect.DeepEqual(seen, []uint64{1, 4}) {
		t.Fatalf("error order changed: seen=%v err=%v", seen, err)
	}
	stop := errors.New("first callback refused")
	seen = nil
	err = visitDecodedRetainedPage(t.Context(), page, func(event Event) error { seen = append(seen, event.Sequence); return stop })
	if !errors.Is(err, stop) || !reflect.DeepEqual(seen, []uint64{1}) {
		t.Fatalf("later decode error hid callback failure: seen=%v err=%v", seen, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	seen = nil
	err = visitDecodedRetainedPage(ctx, page, func(event Event) error { seen = append(seen, event.Sequence); cancel(); return nil })
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(seen, []uint64{1}) {
		t.Fatalf("callback cancellation exposed later work: seen=%v err=%v", seen, err)
	}
	err = visitDecodedRetainedPage(ctx, page, func(Event) error { t.Fatal("callback after cancellation"); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled page: %v", err)
	}
}
