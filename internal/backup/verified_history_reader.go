// SPDX-License-Identifier: BUSL-1.1
package backup

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/events"
)

// VerifiedHistoryReader is a finite, read-only view of an HMAC-verified exact
// backup artifact. Each lookup scans a private spool with bounded line memory;
// it never consults a target log or read model. It is valid only inside the
// WithVerifiedHistoryReader callback.
type VerifiedHistoryReader struct {
	spool    *restoreSpool
	cut      uint64
	mu       sync.Mutex
	active   int
	closed   bool
	finished *sync.Cond
}

// WithVerifiedHistoryReader completes the artifact HMAC and structural checks
// before exposing any source event. The private spool is destroyed when visit
// returns, including on failure.
func WithVerifiedHistoryReader(ctx context.Context, artifact io.Reader, key []byte,
	visit func(*VerifiedHistoryReader) error,
) error {
	if artifact == nil || len(key) == 0 || visit == nil {
		return errors.New("backup: verified history reader requires artifact, integrity key and callback")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	header, spool, trailer, err := readAndVerify(artifact, key)
	if err != nil {
		return err
	}
	defer spool.cleanup()
	if err := validateVerifiedStream(header, trailer, spool.records, spool.entries); err != nil {
		return err
	}
	if header.HistoryLayout != exactHistoryLayout {
		return errors.New("backup: artifact history reader requires exact source layout")
	}
	reader := &VerifiedHistoryReader{spool: spool, cut: header.EventCutSequence}
	reader.finished = sync.NewCond(&reader.mu)
	defer reader.close()
	return visit(reader)
}

func (reader *VerifiedHistoryReader) alive(ctx context.Context) error {
	if reader == nil || reader.spool == nil {
		return errors.New("backup: verified history reader is closed")
	}
	reader.mu.Lock()
	closed := reader.closed
	reader.mu.Unlock()
	if closed {
		return errors.New("backup: verified history reader is closed")
	}
	return ctx.Err()
}

func (reader *VerifiedHistoryReader) begin(ctx context.Context) error {
	if reader == nil || reader.spool == nil {
		return errors.New("backup: verified history reader is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed {
		return errors.New("backup: verified history reader is closed")
	}
	reader.active++
	return nil
}

func (reader *VerifiedHistoryReader) end() {
	reader.mu.Lock()
	reader.active--
	if reader.active == 0 {
		reader.finished.Broadcast()
	}
	reader.mu.Unlock()
}

func (reader *VerifiedHistoryReader) close() {
	reader.mu.Lock()
	reader.closed = true
	for reader.active != 0 {
		reader.finished.Wait()
	}
	reader.mu.Unlock()
}

func (reader *VerifiedHistoryReader) WithHistoryRead(ctx context.Context,
	visit func(context.Context) error,
) error {
	if err := reader.begin(ctx); err != nil {
		return err
	}
	defer reader.end()
	if visit == nil {
		return errors.New("backup: verified history read requires callback")
	}
	if err := visit(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

func (reader *VerifiedHistoryReader) LastSequence(ctx context.Context) (uint64, error) {
	if err := reader.alive(ctx); err != nil {
		return 0, err
	}
	return reader.cut, nil
}

func (reader *VerifiedHistoryReader) scan(ctx context.Context,
	visit func(record, events.Event) error,
) error {
	if err := reader.begin(ctx); err != nil {
		return err
	}
	defer reader.end()
	file, err := os.Open(reader.spool.file.Name())
	if err != nil {
		return fmt.Errorf("backup: reopen verified history spool: %w", err)
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(bufio.NewReader(file))
	scanner.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var rec record
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			return fmt.Errorf("backup: decode verified history spool: %w", err)
		}
		if rec.Kind == "gap" {
			continue
		}
		if rec.Kind != "event" {
			return errors.New("backup: verified history spool has unknown entry")
		}
		event, err := events.DecodeBackupHistoryEvent(events.BackupHistoryRecord{
			Sequence: rec.Sequence, Subject: rec.Subject,
			MessageID: rec.MessageID, Stored: rec.Stored,
		})
		if err != nil {
			return fmt.Errorf("backup: decode verified source event: %w", err)
		}
		if err := visit(rec, event); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("backup: scan verified history spool: %w", err)
	}
	return ctx.Err()
}

func artifactMetadata(event events.Event) events.EnvelopeMetadata {
	meta := events.EnvelopeMetadata{
		ID: event.ID, Type: event.Type, TenantID: event.TenantID,
		Time: event.Time, SchemaVersion: event.SchemaVersion,
		Sequence: event.Sequence,
	}
	if event.Protection != nil {
		meta.DeclaredKeyID = event.Protection.KeyID
	}
	return meta
}

func (reader *VerifiedHistoryReader) ReplayTypesThrough(ctx context.Context,
	from, through uint64, types []string, visit func(events.Event) error,
) error {
	if err := reader.alive(ctx); err != nil {
		return err
	}
	if visit == nil || through > reader.cut {
		return errors.New("backup: typed artifact replay has invalid cut or callback")
	}
	selected := make(map[string]bool, len(types))
	for _, kind := range types {
		if kind == "" || strings.ContainsAny(kind, "*>") {
			return errors.New("backup: typed artifact replay has invalid type")
		}
		selected[kind] = true
	}
	if from == 0 {
		from = 1
	}
	return reader.scan(ctx, func(_ record, event events.Event) error {
		if event.Sequence >= from && event.Sequence <= through && selected[event.Type] {
			return visit(event)
		}
		return nil
	})
}

// ReplayThrough walks every live source position in the verified finite cut.
// Gaps carry no event payload; the restore policy decides separately whether
// the artifact's gap layout is acceptable for serving.
func (reader *VerifiedHistoryReader) ReplayThrough(ctx context.Context,
	from, through uint64, visit func(events.Event) error,
) error {
	if err := reader.alive(ctx); err != nil {
		return err
	}
	if visit == nil || through > reader.cut {
		return errors.New("backup: artifact replay has invalid cut or callback")
	}
	if from == 0 {
		from = 1
	}
	return reader.scan(ctx, func(_ record, event events.Event) error {
		if event.Sequence >= from && event.Sequence <= through {
			return visit(event)
		}
		return nil
	})
}

func (reader *VerifiedHistoryReader) ReplayTenantMetadataTypesThrough(ctx context.Context,
	tenantID string, from, through uint64, types []string,
	visit func(events.EnvelopeMetadata) error,
) error {
	if tenantID == "" || visit == nil {
		return errors.New("backup: tenant artifact replay requires scope and callback")
	}
	return reader.ReplayTypesThrough(ctx, from, through, types, func(event events.Event) error {
		if event.TenantID != tenantID {
			return nil
		}
		return visit(artifactMetadata(event))
	})
}

func (reader *VerifiedHistoryReader) TenantMetadataByID(ctx context.Context,
	tenantID, id string,
) (events.EnvelopeMetadata, bool, error) {
	if tenantID == "" || id == "" {
		return events.EnvelopeMetadata{}, false, errors.New("backup: artifact identity lookup requires tenant and id")
	}
	var found bool
	var result events.EnvelopeMetadata
	err := reader.scan(ctx, func(_ record, event events.Event) error {
		if event.ID != id {
			return nil
		}
		if found || event.TenantID != tenantID {
			return events.ErrConflictingEventIdentity
		}
		result, found = artifactMetadata(event), true
		return nil
	})
	if err != nil {
		return events.EnvelopeMetadata{}, false, err
	}
	return result, found, nil
}

func (reader *VerifiedHistoryReader) EventAtSequence(ctx context.Context,
	sequence uint64,
) (events.Event, bool, error) {
	if err := reader.alive(ctx); err != nil {
		return events.Event{}, false, err
	}
	if sequence == 0 || sequence > reader.cut {
		return events.Event{}, false, errors.New("backup: artifact sequence is beyond verified cut")
	}
	var found bool
	var result events.Event
	err := reader.scan(ctx, func(_ record, event events.Event) error {
		if event.Sequence == sequence {
			result, found = event, true
		}
		return nil
	})
	if err != nil {
		return events.Event{}, false, err
	}
	return result, found, nil
}
