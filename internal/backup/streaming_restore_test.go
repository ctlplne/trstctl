package backup

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

const streamingTenant = "11111111-1111-1111-1111-111111111111"

func TestReadAndVerifySpoolsLargeStreamWithBoundedHeap(t *testing.T) {
	const records = 4096
	stream := syntheticEventBackup(t, records, 2048, []byte("streaming-integrity-key"))

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	h, spool, tr, err := readAndVerify(strings.NewReader(stream), []byte("streaming-integrity-key"))
	if err != nil {
		t.Fatalf("readAndVerify: %v", err)
	}
	defer spool.cleanup()

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(stream)
	runtime.KeepAlive(h)
	runtime.KeepAlive(tr)
	runtime.KeepAlive(spool)

	if h.Format != formatTag || tr.Records != records || spool.records != records {
		t.Fatalf("verified shape header=%+v trailer=%+v spool.records=%d", h, tr, spool.records)
	}
	var live uint64
	if after.Alloc > before.Alloc {
		live = after.Alloc - before.Alloc
	}
	if live > uint64(len(stream)/2) {
		t.Fatalf("restore verifier retained %d bytes of heap for a %d-byte stream; want bounded spool-backed verification", live, len(stream))
	}
}

func TestRestoreLargeStreamRejectsCorruptTrailerBeforeMutation(t *testing.T) {
	stream := syntheticEventBackup(t, 1024, 1024, nil)
	tampered := strings.Replace(stream, `"records":1024`, `"records":1023`, 1)
	if tampered == stream {
		t.Fatal("test setup did not corrupt the trailer")
	}

	dst := openStreamingLog(t)
	n, err := RestoreLog(context.Background(), dst, strings.NewReader(tampered))
	if err == nil {
		t.Fatal("restore must reject a large stream with a corrupt trailer")
	}
	if n != 0 {
		t.Fatalf("restore appended %d events before rejecting corrupt trailer; want 0", n)
	}
	if got := collectStreamingEvents(t, dst); len(got) != 0 {
		t.Fatalf("target log has %d events after corrupt restore; want 0", len(got))
	}
}

func syntheticEventBackup(t *testing.T, records int, payloadBytes int, key []byte) string {
	t.Helper()
	var b strings.Builder
	dig := newDigest(key)
	enc := json.NewEncoder(io.MultiWriter(&b, dig))
	if err := enc.Encode(header{Format: formatTag, Version: version, CreatedAt: time.Unix(0, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("x", payloadBytes)
	for i := 0; i < records; i++ {
		data, err := json.Marshal(struct {
			Index int    `json:"index"`
			Blob  string `json:"blob"`
		}{Index: i, Blob: payload})
		if err != nil {
			t.Fatal(err)
		}
		if err := enc.Encode(record{
			ID: fmt.Sprintf("evt-%06d", i), Type: "owner.created", TenantID: streamingTenant,
			Time: time.Unix(int64(i), 0).UTC(), Data: json.RawMessage(data),
		}); err != nil {
			t.Fatal(err)
		}
	}
	tr := trailer{Format: trailerTag, SHA256: dig.sumHex(), Records: records}
	if len(key) > 0 {
		tr.HMACSHA256 = dig.macHex()
	}
	if err := json.NewEncoder(&b).Encode(tr); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func openStreamingLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func collectStreamingEvents(t *testing.T, log *events.Log) []events.Event {
	t.Helper()
	var got []events.Event
	if err := log.Replay(context.Background(), 0, func(e events.Event) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	return got
}

func TestRestoreRejectsStructurallyInvalidRecordBeforeMutation(t *testing.T) {
	stream := syntheticInvalidRecordBackup(t)
	dst := openStreamingLog(t)
	n, err := RestoreLog(context.Background(), dst, strings.NewReader(stream))
	if err == nil || !strings.Contains(err.Error(), "tenant_id is required") {
		t.Fatalf("RestoreLog error = %v, want structural preflight rejection", err)
	}
	if n != 0 {
		t.Fatalf("restore appended %d events before structural rejection; want 0", n)
	}
	if got := collectStreamingEvents(t, dst); len(got) != 0 {
		t.Fatalf("target log has %d events after structural rejection; want 0", len(got))
	}
}

func syntheticInvalidRecordBackup(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	dig := newDigest(nil)
	enc := json.NewEncoder(io.MultiWriter(&b, dig))
	if err := enc.Encode(header{Format: formatTag, Version: version, CreatedAt: time.Unix(0, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := enc.Encode(record{ID: "evt-000001", Type: "owner.created", Time: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(&b).Encode(trailer{Format: trailerTag, SHA256: dig.sumHex(), Records: 1}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestRestoreSpoolContainsOnlyRecordLines(t *testing.T) {
	stream := syntheticEventBackup(t, 2, 16, nil)
	_, spool, _, err := readAndVerify(strings.NewReader(stream), nil)
	if err != nil {
		t.Fatalf("readAndVerify: %v", err)
	}
	defer spool.cleanup()
	if err := spool.rewind(); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(spool.file)
	lines := 0
	for sc.Scan() {
		lines++
		var rec record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("spool line %d is not a record: %v", lines, err)
		}
		if rec.Type == "" || rec.TenantID == "" {
			t.Fatalf("spool line %d has invalid record %+v", lines, rec)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if lines != 2 {
		t.Fatalf("spool lines = %d, want 2 record lines", lines)
	}
}
