// SPDX-License-Identifier: LicenseRef-trstctl-EE

package gate

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

const refusalLogFile = "gated-destruction-refusals.jsonl"

type MemorySink struct {
	mu     sync.Mutex
	events []eventspec.Event
}

func NewMemorySink() *MemorySink { return &MemorySink{} }

func (s *MemorySink) Append(ctx context.Context, e eventspec.Event) (eventspec.Event, error) {
	if err := ctx.Err(); err != nil {
		return eventspec.Event{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e = finalizeEvent(e, uint64(len(s.events)+1), time.Now().UTC())
	s.events = append(s.events, cloneEvent(e))
	return cloneEvent(e), nil
}

func (s *MemorySink) Events() []eventspec.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]eventspec.Event, len(s.events))
	for i, ev := range s.events {
		out[i] = cloneEvent(ev)
	}
	return out
}

type FileSink struct {
	mu   sync.Mutex
	path string
	seq  uint64
}

func NewRefusalSink(dir string) (RefusalAppendSink, error) {
	if strings.TrimSpace(dir) == "" {
		return NewMemorySink(), nil
	}
	return NewFileSink(filepath.Join(dir, refusalLogFile))
}

func NewFileSink(path string) (*FileSink, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: refusal sink path is required", ErrInvalidEvidence)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("vdec gate: create refusal sink dir: %w", err)
	}
	seq, err := countJSONLines(path)
	if err != nil {
		return nil, err
	}
	return &FileSink{path: path, seq: seq}, nil
}

func (s *FileSink) Append(ctx context.Context, e eventspec.Event) (eventspec.Event, error) {
	if err := ctx.Err(); err != nil {
		return eventspec.Event{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e = finalizeEvent(e, s.seq+1, time.Now().UTC())
	raw, err := json.Marshal(e)
	if err != nil {
		return eventspec.Event{}, fmt.Errorf("vdec gate: encode refusal event: %w", err)
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return eventspec.Event{}, fmt.Errorf("vdec gate: open refusal sink: %w", err)
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		_ = f.Close()
		return eventspec.Event{}, fmt.Errorf("vdec gate: append refusal event: %w", err)
	}
	if err := f.Close(); err != nil {
		return eventspec.Event{}, fmt.Errorf("vdec gate: close refusal sink: %w", err)
	}
	s.seq++
	return cloneEvent(e), nil
}

func finalizeEvent(e eventspec.Event, seq uint64, now time.Time) eventspec.Event {
	if e.Sequence == 0 {
		e.Sequence = seq
	}
	if e.Time.IsZero() {
		e.Time = now
	}
	if e.SchemaVersion == 0 {
		e.SchemaVersion = SchemaV1
	}
	if e.ID == "" {
		body := struct {
			Type     string    `json:"type"`
			TenantID string    `json:"tenant_id"`
			Time     time.Time `json:"time"`
			Sequence uint64    `json:"sequence"`
			Data     []byte    `json:"data"`
		}{Type: e.Type, TenantID: e.TenantID, Time: e.Time, Sequence: e.Sequence, Data: e.Data}
		raw, _ := json.Marshal(body)
		sum := crypto.SHA256Sum(raw)
		e.ID = "vdec-refusal-" + hex.EncodeToString(sum[:12])
	}
	return e
}

func cloneEvent(ev eventspec.Event) eventspec.Event {
	out := ev
	out.Data = append([]byte(nil), ev.Data...)
	if ev.Actor != nil {
		actor := *ev.Actor
		actor.Roles = append([]string(nil), ev.Actor.Roles...)
		out.Actor = &actor
	}
	return out
}

func countJSONLines(path string) (uint64, error) {
	dir, name := filepath.Split(path)
	if strings.TrimSpace(dir) == "" {
		dir = "."
	}
	// Replay the refusal log through a directory handle rather than by name:
	// the sequence recovered here is what the next refusal event is numbered
	// from, so a symlink planted in the floor dir must not be able to redirect
	// that read outside dir.
	root, err := os.OpenRoot(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("vdec gate: open refusal sink dir for replay: %w", err)
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(name)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("vdec gate: open refusal sink for replay: %w", err)
	}
	defer func() { _ = f.Close() }()
	var n uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			n++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("vdec gate: scan refusal sink: %w", err)
	}
	return n, nil
}
