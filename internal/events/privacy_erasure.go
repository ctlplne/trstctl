package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/privacyref"
	"trstctl.com/trstctl/internal/tenancy"
)

// PseudonymizeSubject rewrites the hot event stream so exact occurrences of an
// erased subject are replaced by the tenant-bound erasure placeholder in stored
// event payloads and actor subjects. It secure-deletes the old JetStream messages
// before republishing the same envelopes in original order, so tenant-facing
// replay and raw hot-log storage no longer contain the erased subject bytes.
//
// This is intentionally narrow: it is the storage-level companion to the
// privacy.subject.erased event. Cold archives and backups created before this
// rewrite need their own operator retention/deletion process, documented under
// privacy retention.
func (l *Log) PseudonymizeSubject(ctx context.Context, tenantID, subject string) error {
	if tenantID == "" {
		return errors.New("events: subject pseudonymization requires tenant_id (AN-1)")
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return errors.New("events: subject pseudonymization requires subject")
	}

	l.rewriteMu.Lock()
	defer l.rewriteMu.Unlock()

	info, err := l.streamInfo(ctx)
	if err != nil {
		return fmt.Errorf("events: pseudonymize stream info: %w", err)
	}
	if info.State.LastSeq == 0 {
		return nil
	}

	stored := make([]storedEvent, 0, info.State.Msgs)
	seqs := make([]uint64, 0, info.State.Msgs)
	var changed bool
	for seq := uint64(1); seq <= info.State.LastSeq; seq++ {
		raw, err := l.stream.GetMsg(ctx, seq)
		if err != nil {
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				continue
			}
			return fmt.Errorf("events: pseudonymize get seq %d: %w", seq, err)
		}
		var s storedEvent
		if err := json.Unmarshal(raw.Data, &s); err != nil {
			return fmt.Errorf("events: pseudonymize decode seq %d: %w", seq, err)
		}
		if s.TenantID == tenantID && pseudonymizeStoredSubject(&s, subject) {
			changed = true
		}
		stored = append(stored, s)
		seqs = append(seqs, seq)
	}
	if !changed {
		return nil
	}

	payloads := make([][]byte, len(stored))
	subjects := make([]string, len(stored))
	for i, s := range stored {
		payload, err := json.Marshal(s)
		if err != nil {
			return fmt.Errorf("events: pseudonymize marshal event %q: %w", s.ID, err)
		}
		subj, err := tenancy.EventSubject(ctx, s.TenantID, subjectPrefix, s.Type)
		if err != nil {
			return err
		}
		payloads[i] = payload
		subjects[i] = subj
	}

	for _, seq := range seqs {
		if err := l.stream.SecureDeleteMsg(ctx, seq); err != nil && !errors.Is(err, jetstream.ErrMsgNotFound) {
			return fmt.Errorf("events: pseudonymize secure-delete seq %d: %w", seq, err)
		}
	}
	if err := l.stream.Purge(ctx); err != nil {
		return fmt.Errorf("events: pseudonymize purge stream: %w", err)
	}
	for i, payload := range payloads {
		if _, err := l.js.Publish(ctx, subjects[i], payload); err != nil {
			return fmt.Errorf("events: pseudonymize republish event %d: %w", i+1, err)
		}
	}
	return nil
}

func pseudonymizeStoredSubject(s *storedEvent, subject string) bool {
	ref := privacyref.SubjectRef(s.TenantID, subject)
	placeholder := privacyref.Placeholder(ref)
	var changed bool
	if s.Actor != nil {
		actor := *s.Actor
		if next := strings.ReplaceAll(actor.Subject, subject, placeholder); next != actor.Subject {
			actor.Subject = next
			s.Actor = &actor
			changed = true
		}
	}
	if len(s.Data) > 0 {
		if next, ok := pseudonymizeDataBytes(s.Data, subject, placeholder); ok {
			s.Data = next
			changed = true
		}
	}
	return changed
}

func pseudonymizeDataBytes(data []byte, subject, placeholder string) ([]byte, bool) {
	var v any
	if err := json.Unmarshal(data, &v); err == nil {
		if pseudonymizeValue(&v, subject, placeholder) {
			out, err := json.Marshal(v)
			if err == nil {
				return out, true
			}
		}
	}
	next := bytes.ReplaceAll(data, []byte(subject), []byte(placeholder))
	return next, !bytes.Equal(next, data)
}

func pseudonymizeValue(v *any, subject, placeholder string) bool {
	switch x := (*v).(type) {
	case string:
		next := strings.ReplaceAll(x, subject, placeholder)
		if next != x {
			*v = next
			return true
		}
	case []any:
		var changed bool
		for i := range x {
			if pseudonymizeValue(&x[i], subject, placeholder) {
				changed = true
			}
		}
		return changed
	case map[string]any:
		var changed bool
		for k, val := range x {
			if pseudonymizeValue(&val, subject, placeholder) {
				x[k] = val
				changed = true
			}
		}
		return changed
	}
	return false
}
