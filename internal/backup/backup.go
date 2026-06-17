// Package backup serializes the event log — the AN-2 source of truth — to a
// portable, versioned, INTEGRITY-PROTECTED stream, and restores it into a fresh
// log. Because the relational read model is a pure projection of the log (R1.1),
// restoring the log and rebuilding the projections reconstructs the whole control
// plane after a disaster (R2.4). The backup carries the full event envelope,
// including the recorded actor (R2.1), so the recovered audit trail is intact.
//
// Integrity (OPS-006). A backup is a disaster-recovery artifact for a credential
// and audit platform; a tampered or truncated backup that restores without
// complaint is an integrity hole. Every stream therefore ends with a trailer line
// carrying a SHA-256 over all preceding bytes (header + records), so a bit-flip,
// a truncation, or a removed record is detected on restore and rejected
// fail-closed. When an integrity key is supplied (WriteLogWithKey), the trailer
// also carries an HMAC-SHA256 over the same bytes, so an attacker who can rewrite
// the stream cannot forge a matching trailer without the key. All hashing/MAC
// routes through the crypto boundary (internal/crypto, AN-3).
package backup

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

const (
	formatTag  = "trstctl-event-log-backup"
	trailerTag = "trstctl-event-log-backup-trailer"
	version    = 1
)

// header is the first line of a backup stream — a self-describing, versioned
// envelope so a restore can refuse a stranger's file or a future format.
type header struct {
	Format    string    `json:"format"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

// record is one event as written to the backup. Sequence is intentionally omitted
// — it is reassigned contiguously when the events are re-appended on restore.
type record struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	TenantID string          `json:"tenant_id"`
	Time     time.Time       `json:"time"`
	Data     json.RawMessage `json:"data,omitempty"`
	Actor    *events.Actor   `json:"actor,omitempty"`
}

// trailer is the final line of a backup stream — the integrity check over every
// byte that precedes it (OPS-006). SHA256 is always present; HMACSHA256 is present
// only when the backup was written with an integrity key. Records is the event
// count, a cheap structural cross-check.
type trailer struct {
	Format     string `json:"format"`
	SHA256     string `json:"sha256"`
	HMACSHA256 string `json:"hmac_sha256,omitempty"`
	Records    int    `json:"records"`
}

// WriteLog streams every event in log to w as a versioned, SHA-256-integrity-
// protected backup and returns the count. The format is newline-delimited JSON: a
// header line, one record per event in append order, and a trailing integrity
// line. It is equivalent to WriteLogWithKey(ctx, log, w, nil) — a keyless
// (checksum-only) backup.
func WriteLog(ctx context.Context, log *events.Log, w io.Writer) (int, error) {
	return WriteLogWithKey(ctx, log, w, nil)
}

// WriteLogWithKey is WriteLog with an optional integrity key. When key is
// non-empty the trailer additionally carries an HMAC-SHA256 over the stream,
// binding the backup to the key so a tamperer who can recompute the SHA-256
// cannot forge the trailer. The MAC routes through the crypto boundary (AN-3).
func WriteLogWithKey(ctx context.Context, log *events.Log, w io.Writer, key []byte) (int, error) {
	bw := bufio.NewWriter(w)
	// Tee every byte we write into a digest so the trailer covers the exact stream.
	dig := newDigest(key)
	mw := io.MultiWriter(bw, dig)
	enc := json.NewEncoder(mw)

	if err := enc.Encode(header{Format: formatTag, Version: version, CreatedAt: time.Now().UTC()}); err != nil {
		return 0, err
	}
	n := 0
	err := log.Replay(ctx, 0, func(e events.Event) error {
		if err := enc.Encode(record{
			ID: e.ID, Type: e.Type, TenantID: e.TenantID, Time: e.Time,
			Data: json.RawMessage(e.Data), Actor: e.Actor,
		}); err != nil {
			return err
		}
		n++
		return nil
	})
	if err != nil {
		return n, err
	}

	// The trailer is written to bw only (NOT into the digest): it carries the hash
	// of everything before it.
	tr := trailer{Format: trailerTag, SHA256: dig.sumHex(), Records: n}
	if len(key) > 0 {
		tr.HMACSHA256 = dig.macHex()
	}
	if err := json.NewEncoder(bw).Encode(tr); err != nil {
		return n, err
	}
	return n, bw.Flush()
}

// RestoreLog reads a backup stream from r, VERIFIES its integrity trailer, and —
// only if the trailer matches — appends its events, in order, into log, which must
// be empty so a misdirected restore cannot duplicate a stream. It preserves each
// event's id, time, and actor; the sequence is reassigned contiguously by the log.
// It is equivalent to RestoreLogWithKey(ctx, log, r, nil): it accepts a
// checksum-only backup, and accepts a keyed backup but does not verify its MAC.
// Use RestoreLogWithKey to require a valid MAC. A truncated, bit-flipped, or
// trailer-less stream is rejected fail-closed.
func RestoreLog(ctx context.Context, log *events.Log, r io.Reader) (int, error) {
	return RestoreLogWithKey(ctx, log, r, nil)
}

// RestoreLogWithKey is RestoreLog that additionally requires a valid HMAC-SHA256
// under key: a backup written without a MAC, or whose MAC does not verify, is
// rejected. The integrity check (SHA-256 and, when key is set, the MAC) is
// performed BEFORE any event is appended, so a tampered backup never mutates the
// target log.
func RestoreLogWithKey(ctx context.Context, log *events.Log, r io.Reader, key []byte) (int, error) {
	if !empty(ctx, log) {
		return 0, errors.New("backup: restore target log is not empty (restore into a fresh event store)")
	}

	// Parse and verify the stream while spooling record lines to disk. We still
	// verify integrity BEFORE appending anything, but memory stays bounded by the
	// largest line rather than the whole backup.
	h, spool, tr, err := readAndVerify(r, key)
	if err != nil {
		return 0, err
	}
	defer spool.cleanup()
	if h.Format != formatTag {
		return 0, fmt.Errorf("backup: not a trstctl event-log backup (format %q)", h.Format)
	}
	if h.Version != version {
		return 0, fmt.Errorf("backup: unsupported backup version %d (want %d)", h.Version, version)
	}
	if tr.Records != spool.records {
		return 0, fmt.Errorf("backup: integrity: trailer claims %d records but stream has %d", tr.Records, spool.records)
	}
	if err := spool.rewind(); err != nil {
		return 0, err
	}

	n := 0
	sc := bufio.NewScanner(bufio.NewReader(spool.file))
	sc.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)
	for sc.Scan() {
		var rec record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return n, fmt.Errorf("backup: replay spooled record %d: %w", n+1, err)
		}
		if _, err := log.Append(ctx, events.Event{
			ID: rec.ID, Type: rec.Type, TenantID: rec.TenantID, Time: rec.Time,
			Data: []byte(rec.Data), Actor: rec.Actor,
		}); err != nil {
			return n, fmt.Errorf("backup: append record %d: %w", n+1, err)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return n, fmt.Errorf("backup: replay spooled stream: %w", err)
	}
	return n, nil
}

// readAndVerify streams the backup, recomputes the SHA-256 (and, when key is set,
// the HMAC) over every byte up to the trailer line, and verifies those digests
// against the trailer. Validated record lines are spooled to a temporary file and
// replayed only after this function succeeds, so restore never holds the full
// backup or decoded record set in memory and never mutates the target on a corrupt
// trailer.
func readAndVerify(r io.Reader, key []byte) (h header, spool *restoreSpool, tr trailer, err error) {
	var (
		haveHdr bool
		haveTr  bool
	)
	spool, err = newRestoreSpool()
	if err != nil {
		return h, nil, tr, err
	}
	cleanupSpool := spool
	defer func() {
		if err != nil && cleanupSpool != nil {
			cleanupSpool.cleanup()
			spool = nil
		}
	}()
	dig := newDigest(key)
	sc := bufio.NewScanner(bufio.NewReader(r))
	// Backups can carry large event payloads; raise the line cap well above the
	// 64 KiB default so a big single event is not a spurious integrity failure.
	sc.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)

	for sc.Scan() {
		if haveTr {
			// Nothing may follow the trailer; trailing bytes mean tampering/append.
			return h, nil, tr, errors.New("backup: integrity: data found after the trailer line")
		}
		line := sc.Bytes()
		// Probe the discriminator without consuming the bytes for the digest.
		var probe struct {
			Format string `json:"format"`
		}
		_ = json.Unmarshal(line, &probe)

		switch {
		case !haveHdr:
			if err := json.Unmarshal(line, &h); err != nil {
				return h, nil, tr, fmt.Errorf("backup: read header: %w", err)
			}
			haveHdr = true
			feed(dig, line)
		case probe.Format == trailerTag:
			if err := json.Unmarshal(line, &tr); err != nil {
				return h, nil, tr, fmt.Errorf("backup: read trailer: %w", err)
			}
			haveTr = true
			// The trailer line itself is NOT fed into the digest.
		default:
			var rec record
			if err := json.Unmarshal(line, &rec); err != nil {
				return h, nil, tr, fmt.Errorf("backup: decode record %d: %w", spool.records+1, err)
			}
			if rec.Type == "" {
				return h, nil, tr, fmt.Errorf("backup: decode record %d: event type is required", spool.records+1)
			}
			if rec.TenantID == "" {
				return h, nil, tr, fmt.Errorf("backup: decode record %d: tenant_id is required", spool.records+1)
			}
			feed(dig, line)
			if err := spool.writeLine(line); err != nil {
				return h, nil, tr, err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return h, nil, tr, fmt.Errorf("backup: read stream: %w", err)
	}
	if !haveHdr {
		return h, nil, tr, errors.New("backup: read header: empty stream")
	}
	if !haveTr {
		// A backup with no trailer is unverifiable — treat it as corrupt/truncated
		// and refuse it (fail closed), rather than restoring unchecked bytes.
		return h, nil, tr, errors.New("backup: integrity trailer missing (stream truncated or not a trstctl backup); refusing to restore")
	}

	// Verify SHA-256 (always) using constant-time comparison.
	wantSum, err := hex.DecodeString(tr.SHA256)
	if err != nil || len(wantSum) == 0 {
		return h, nil, tr, errors.New("backup: integrity: trailer has no valid sha256")
	}
	if !crypto.ConstantTimeEqual(dig.sum(), wantSum) {
		return h, nil, tr, errors.New("backup: integrity check FAILED — the backup is corrupt or has been tampered with (sha256 mismatch); refusing to restore")
	}

	// Verify HMAC when an integrity key was supplied.
	if len(key) > 0 {
		if tr.HMACSHA256 == "" {
			return h, nil, tr, errors.New("backup: integrity: an integrity key was provided but the backup carries no HMAC; refusing to restore")
		}
		wantMAC, err := hex.DecodeString(tr.HMACSHA256)
		if err != nil || len(wantMAC) == 0 {
			return h, nil, tr, errors.New("backup: integrity: trailer has no valid hmac_sha256")
		}
		if !crypto.ConstantTimeEqual(dig.mac(), wantMAC) {
			return h, nil, tr, errors.New("backup: integrity check FAILED — the backup's HMAC does not verify under the configured integrity key; refusing to restore")
		}
	}

	if err := spool.sync(); err != nil {
		return h, nil, tr, err
	}
	return h, spool, tr, nil
}

// digest accumulates the bytes of a backup stream and produces the trailer's
// SHA-256 and (when keyed) HMAC-SHA256, all via the crypto boundary (AN-3). The
// scanner strips newlines, so feed() re-adds the '\n' that the writer emitted
// after each line — keeping the read-side bytes identical to the write-side.
type digest struct {
	inner *crypto.SHA256HMACDigest
}

func newDigest(key []byte) *digest {
	return &digest{inner: crypto.NewSHA256HMACDigest(key)}
}

// Write makes *digest an io.Writer so the WRITE path can tee the exact encoded
// bytes (json.Encoder already appends '\n') straight into the digest.
func (d *digest) Write(p []byte) (int, error) {
	return d.inner.Write(p)
}

func (d *digest) sum() []byte    { return d.inner.SHA256Sum() }
func (d *digest) sumHex() string { return d.inner.SHA256Hex() }
func (d *digest) mac() []byte    { return d.inner.HMACSHA256() }
func (d *digest) macHex() string { return d.inner.HMACSHA256Hex() }

// feed appends a scanned line plus the newline the writer emitted after it, so the
// read-side digest covers exactly the write-side bytes.
func feed(d *digest, line []byte) {
	_, _ = d.Write(line)
	_, _ = d.Write([]byte{'\n'})
}

type restoreSpool struct {
	file    *os.File
	records int
}

func newRestoreSpool() (*restoreSpool, error) {
	f, err := os.CreateTemp("", "trstctl-event-restore-*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("backup: create restore spool: %w", err)
	}
	return &restoreSpool{file: f}, nil
}

func (s *restoreSpool) writeLine(line []byte) error {
	if _, err := s.file.Write(line); err != nil {
		return fmt.Errorf("backup: write restore spool: %w", err)
	}
	if _, err := s.file.Write([]byte{'\n'}); err != nil {
		return fmt.Errorf("backup: write restore spool: %w", err)
	}
	s.records++
	return nil
}

func (s *restoreSpool) sync() error {
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("backup: sync restore spool: %w", err)
	}
	return nil
}

func (s *restoreSpool) rewind() error {
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("backup: rewind restore spool: %w", err)
	}
	return nil
}

func (s *restoreSpool) cleanup() {
	if s == nil || s.file == nil {
		return
	}
	name := s.file.Name()
	_ = s.file.Close()
	_ = os.Remove(name)
}

// empty reports whether the log has no events (short-circuiting on the first one).
func empty(ctx context.Context, log *events.Log) bool {
	found := false
	stop := errors.New("stop")
	err := log.Replay(ctx, 0, func(events.Event) error { found = true; return stop })
	if err != nil && !errors.Is(err, stop) {
		// On a replay error, treat the log as non-empty so a restore never appends
		// into an unknown state.
		return false
	}
	return !found
}
