package backup_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

const drTenant = "11111111-1111-1111-1111-111111111111"

func openLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func appendEvent(t *testing.T, log *events.Log, ctx context.Context, typ string, data string) {
	t.Helper()
	if _, err := log.Append(ctx, events.Event{Type: typ, TenantID: drTenant, Data: []byte(data)}); err != nil {
		t.Fatalf("append: %v", err)
	}
}

func collect(t *testing.T, log *events.Log) []events.Event {
	t.Helper()
	var got []events.Event
	if err := log.Replay(context.Background(), 0, func(e events.Event) error { got = append(got, e); return nil }); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	return got
}

// TestBackupRestoreRoundTrip is the R2.4 source-of-truth backup acceptance: the
// event log backs up to a portable stream and restores into a fresh log
// byte-for-byte — type, tenant, data, and the recorded actor (R2.1) all survive.
func TestBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	src := openLog(t)
	actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: "alice@example.com", Roles: []string{"admin"}})
	appendEvent(t, src, actorCtx, "owner.created", `{"name":"payments"}`)
	appendEvent(t, src, ctx, "certificate.recorded", `{"serial":"01"}`)
	appendEvent(t, src, actorCtx, "identity.issued", `{}`)

	var buf bytes.Buffer
	n, err := backup.WriteLog(ctx, src, &buf)
	if err != nil {
		t.Fatalf("WriteLog: %v", err)
	}
	if n != 3 {
		t.Fatalf("backed up %d events, want 3", n)
	}

	dst := openLog(t)
	m, err := backup.RestoreLog(ctx, dst, &buf)
	if err != nil {
		t.Fatalf("RestoreLog: %v", err)
	}
	if m != 3 {
		t.Fatalf("restored %d events, want 3", m)
	}

	got := collect(t, dst)
	if len(got) != 3 {
		t.Fatalf("restored log has %d events, want 3", len(got))
	}
	if got[0].Type != "owner.created" || got[0].TenantID != drTenant {
		t.Errorf("event 0 = %+v", got[0])
	}
	if got[0].Actor == nil || got[0].Actor.Subject != "alice@example.com" {
		t.Errorf("actor not preserved on restore: %+v", got[0].Actor)
	}
	if string(got[1].Data) != `{"serial":"01"}` {
		t.Errorf("data not preserved on restore: %s", got[1].Data)
	}
	if got[1].Actor != nil {
		t.Errorf("event 1 should remain unattributed, got %+v", got[1].Actor)
	}
}

// TestRestoreRefusesNonEmptyLog: restoring into a log that already has events is
// rejected, so a misdirected restore can't silently duplicate the stream.
func TestRestoreRefusesNonEmptyLog(t *testing.T) {
	ctx := context.Background()
	src := openLog(t)
	appendEvent(t, src, ctx, "owner.created", `{}`)
	var buf bytes.Buffer
	if _, err := backup.WriteLog(ctx, src, &buf); err != nil {
		t.Fatal(err)
	}

	dst := openLog(t)
	appendEvent(t, dst, ctx, "owner.created", `{}`)
	if _, err := backup.RestoreLog(ctx, dst, &buf); err == nil {
		t.Fatal("restore into a non-empty log must error")
	}
}

// TestRestoreRejectsBadHeader: a stream that is not a trstctl backup is rejected.
func TestRestoreRejectsBadHeader(t *testing.T) {
	dst := openLog(t)
	if _, err := backup.RestoreLog(context.Background(), dst, strings.NewReader("garbage\n{}\n")); err == nil {
		t.Fatal("restore must reject a stream with no valid backup header")
	}
}

// makeBackup writes a small backup (optionally keyed) and returns its bytes.
func makeBackup(t *testing.T, key []byte) []byte {
	t.Helper()
	ctx := context.Background()
	src := openLog(t)
	appendEvent(t, src, ctx, "owner.created", `{"name":"payments"}`)
	appendEvent(t, src, ctx, "certificate.recorded", `{"serial":"01"}`)
	appendEvent(t, src, ctx, "identity.issued", `{"id":"abc"}`)
	var buf bytes.Buffer
	if _, err := backup.WriteLogWithKey(ctx, src, &buf, key); err != nil {
		t.Fatalf("WriteLogWithKey: %v", err)
	}
	return buf.Bytes()
}

// TestRestoreRejectsTamperedBackup is the OPS-006 acceptance: a single flipped
// byte anywhere in a record makes --restore (RestoreLog) fail closed with an
// integrity error, while the untouched backup restores cleanly. It FAILS on the
// pre-fix tree, which validated only format+version and never hashed the bytes.
func TestRestoreRejectsTamperedBackup(t *testing.T) {
	good := makeBackup(t, nil)

	// (1) The pristine backup restores its three events.
	{
		dst := openLog(t)
		n, err := backup.RestoreLog(context.Background(), dst, bytes.NewReader(good))
		if err != nil {
			t.Fatalf("pristine backup must restore: %v", err)
		}
		if n != 3 {
			t.Fatalf("restored %d events, want 3", n)
		}
	}

	// (2) Flip a byte inside the serial of the second record ("01" -> "02"); the
	// SHA-256 over the stream no longer matches the trailer, so restore must reject
	// it WITHOUT appending anything.
	tampered := bytes.Replace(good, []byte(`"serial":"01"`), []byte(`"serial":"02"`), 1)
	if bytes.Equal(tampered, good) {
		t.Fatal("test setup: expected to mutate the serial in the backup bytes")
	}
	dst := openLog(t)
	n, err := backup.RestoreLog(context.Background(), dst, bytes.NewReader(tampered))
	if err == nil {
		t.Fatal("restore must REJECT a bit-flipped backup (OPS-006)")
	}
	if !strings.Contains(err.Error(), "integrity") {
		t.Errorf("rejection should be an integrity error, got: %v", err)
	}
	if n != 0 {
		t.Errorf("a tampered backup must not append any events, appended %d", n)
	}
	// The target log is untouched: nothing was restored.
	if got := collect(t, dst); len(got) != 0 {
		t.Errorf("target log should be empty after a rejected restore, has %d events", len(got))
	}
}

// TestRestoreRejectsTruncatedBackup: a stream cut short (lost trailer, or a
// dropped record) is rejected fail-closed.
func TestRestoreRejectsTruncatedBackup(t *testing.T) {
	good := makeBackup(t, nil)

	// Drop the final line (the integrity trailer).
	lines := bytes.Split(bytes.TrimRight(good, "\n"), []byte("\n"))
	if len(lines) < 3 {
		t.Fatalf("unexpected backup shape: %d lines", len(lines))
	}
	noTrailer := append(bytes.Join(lines[:len(lines)-1], []byte("\n")), '\n')

	dst := openLog(t)
	if _, err := backup.RestoreLog(context.Background(), dst, bytes.NewReader(noTrailer)); err == nil {
		t.Fatal("restore must reject a backup with no integrity trailer (truncated)")
	}

	// Drop a data record (the trailer's record count no longer matches, AND the
	// hash no longer matches).
	dropped := bytes.Join(append([][]byte{lines[0], lines[2]}, lines[3:]...), []byte("\n"))
	dropped = append(dropped, '\n')
	dst2 := openLog(t)
	if _, err := backup.RestoreLog(context.Background(), dst2, bytes.NewReader(dropped)); err == nil {
		t.Fatal("restore must reject a backup with a removed record (OPS-006)")
	}
}

// TestKeyedBackupRequiresValidMAC: a keyed (HMAC) backup verifies only under the
// right key — restoring under the wrong key, or with no key when the caller
// requires one, fails; the matching key restores.
func TestKeyedBackupRequiresValidMAC(t *testing.T) {
	ctx := context.Background()
	key := []byte("deployment-integrity-key-32-bytes!")
	keyed := makeBackup(t, key)

	// Right key: restores.
	{
		dst := openLog(t)
		n, err := backup.RestoreLogWithKey(ctx, dst, bytes.NewReader(keyed), key)
		if err != nil {
			t.Fatalf("keyed backup must restore under the right key: %v", err)
		}
		if n != 3 {
			t.Fatalf("restored %d events, want 3", n)
		}
	}

	// Wrong key: the SHA-256 still matches (untampered), but the MAC must not
	// verify, so restore is rejected fail-closed.
	{
		dst := openLog(t)
		_, err := backup.RestoreLogWithKey(ctx, dst, bytes.NewReader(keyed), []byte("a-different-wrong-integrity-key!!"))
		if err == nil {
			t.Fatal("keyed backup must be rejected under the wrong integrity key")
		}
		if !strings.Contains(err.Error(), "integrity") {
			t.Errorf("wrong-key rejection should be an integrity error, got: %v", err)
		}
	}

	// A caller that requires a key but is handed a checksum-only (keyless) backup
	// must reject it (a downgrade attempt).
	{
		keyless := makeBackup(t, nil)
		dst := openLog(t)
		if _, err := backup.RestoreLogWithKey(ctx, dst, bytes.NewReader(keyless), key); err == nil {
			t.Fatal("a key-requiring restore must reject a backup that carries no HMAC")
		}
	}
}
