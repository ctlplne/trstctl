// SPDX-License-Identifier: MPL-2.0

package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/tenancy"
)

// TenantDataTransform receives one immutable event payload for a single tenant.
// Returning changed=false preserves the canonical bytes. A changed payload must
// remain valid for that event type/schema so deterministic replay still rebuilds
// the same state.
type TenantDataTransform func(eventType string, schemaVersion int, data []byte) (next []byte, changed bool, err error)

// RewriteTenantData securely replaces selected Data bytes in one tenant's hot
// JetStream history while preserving every event envelope and global event order.
// It is the storage seam used by tenant-key-domain migration to rewrap ciphertext
// already present in immutable events without ever materializing record plaintext.
//
// The entire transform is preflighted before the first secure delete. A malformed
// or unsupported tenant event therefore aborts with the original stream untouched.
// Appends are fenced by rewriteMu for the full read/transform/replace operation.
// Cold archives and backups are separate artifacts and must remain visible as
// legacy-history exposure until independently reprotected or retired.
func (l *Log) RewriteTenantData(ctx context.Context, tenantID string, transform TenantDataTransform) (int, error) {
	if tenantID == "" {
		return 0, errors.New("events: tenant data rewrite requires tenant_id (AN-1)")
	}
	if transform == nil {
		return 0, errors.New("events: tenant data rewrite requires transform")
	}

	l.rewriteMu.Lock()
	defer l.rewriteMu.Unlock()

	info, err := l.streamInfo(ctx)
	if err != nil {
		return 0, fmt.Errorf("events: tenant data rewrite stream info: %w", err)
	}
	if info.State.LastSeq == 0 {
		return 0, nil
	}

	stored := make([]storedEvent, 0, info.State.Msgs)
	seqs := make([]uint64, 0, info.State.Msgs)
	changedCount := 0
	for seq := uint64(1); seq <= info.State.LastSeq; seq++ {
		raw, err := l.stream.GetMsg(ctx, seq)
		if err != nil {
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				continue
			}
			return 0, fmt.Errorf("events: tenant data rewrite get seq %d: %w", seq, err)
		}
		var item storedEvent
		if err := json.Unmarshal(raw.Data, &item); err != nil {
			return 0, fmt.Errorf("events: tenant data rewrite decode seq %d: %w", seq, err)
		}
		if item.TenantID == tenantID {
			input := append([]byte(nil), item.Data...)
			next, changed, err := transform(item.Type, normalizedSchemaVersion(item.SchemaVersion), input)
			if err != nil {
				return 0, fmt.Errorf("events: tenant data rewrite transform event %q: %w", item.ID, err)
			}
			if changed {
				item.Data = append([]byte(nil), next...)
				changedCount++
			}
		}
		stored = append(stored, item)
		seqs = append(seqs, seq)
	}
	if changedCount == 0 {
		return 0, nil
	}

	payloads := make([][]byte, len(stored))
	subjects := make([]string, len(stored))
	for i, item := range stored {
		payload, err := json.Marshal(item)
		if err != nil {
			return 0, fmt.Errorf("events: tenant data rewrite marshal event %q: %w", item.ID, err)
		}
		subject, err := tenancy.EventSubject(ctx, item.TenantID, subjectPrefix, item.Type)
		if err != nil {
			return 0, err
		}
		payloads[i] = payload
		subjects[i] = subject
	}

	for _, seq := range seqs {
		if err := l.stream.SecureDeleteMsg(ctx, seq); err != nil && !errors.Is(err, jetstream.ErrMsgNotFound) {
			return 0, fmt.Errorf("events: tenant data rewrite secure-delete seq %d: %w", seq, err)
		}
	}
	if err := l.stream.Purge(ctx); err != nil {
		return 0, fmt.Errorf("events: tenant data rewrite purge stream: %w", err)
	}
	for i, payload := range payloads {
		if _, err := l.js.Publish(ctx, subjects[i], payload); err != nil {
			return 0, fmt.Errorf("events: tenant data rewrite republish event %d: %w", i+1, err)
		}
	}
	return changedCount, nil
}

func normalizedSchemaVersion(version int) int {
	if version == 0 {
		return DefaultSchemaVersion
	}
	return version
}
