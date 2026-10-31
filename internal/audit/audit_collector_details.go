// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

// CollectorDetails resolves current readable fields for a previously queued
// standing feed instruction. It is not an operator archive-download API. The
// immutable record core must still match the retained source exactly; a hash
// alone is insufficient because a caller could alter data without rehashing.
// Retention does not discard the source, so an already queued batch can finish
// after its online audit prefix retires. No readable fields enter that command.
func (s *Service) CollectorDetails(ctx context.Context, tenantID string, records []Record) ([]ReadableEvent, error) {
	if tenantID == "" {
		return nil, ErrMissingTenant
	}
	if len(records) == 0 || len(records) > 500 {
		return nil, fmt.Errorf("audit: collector source range is empty or exceeds 500 records")
	}
	for i, record := range records {
		if record.TenantID != tenantID || record.ID == "" || record.Sequence == 0 || (i > 0 && record.Sequence <= records[i-1].Sequence) {
			return nil, fmt.Errorf("audit: collector source escaped exact tenant/range authority")
		}
	}
	source := *s
	source.checkpoints = nil // Only the exact already-queued source may be resolved.
	view, err := source.SearchReadableView(ctx, Query{TenantID: tenantID, AfterSequence: records[0].Sequence - 1, AsOfSequence: records[len(records)-1].Sequence, ExcludeTypePrefixes: []string{"audit.feed."}})
	if err != nil {
		return nil, err
	}
	current := make(map[uint64]Record, len(view.Records))
	for _, record := range view.Records {
		current[record.Sequence] = record
	}
	details := make(map[uint64]ReadableEvent, len(view.ReadableEvents))
	for _, detail := range view.ReadableEvents {
		details[detail.Sequence] = detail
	}
	out := make([]ReadableEvent, 0, len(view.ReadableEvents))
	for _, queued := range records {
		actual, found := current[queued.Sequence]
		if !found {
			return nil, fmt.Errorf("audit: queued collector source is unavailable")
		}
		// Selection-dependent hashes are verified by the receiver against the queued
		// predecessor. Source matching compares every canonical hash input instead.
		actual.Hash = ""
		queued.Hash = ""
		actual.Time = actual.Time.UTC()
		queued.Time = queued.Time.UTC()
		want, err := json.Marshal(queued)
		if err != nil {
			return nil, err
		}
		got, err := json.Marshal(actual)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(want, got) {
			return nil, fmt.Errorf("audit: queued collector source changed")
		}
		if detail, found := details[queued.Sequence]; found {
			if detail.ID != queued.ID {
				return nil, fmt.Errorf("audit: collector detail source identity changed")
			}
			out = append(out, detail)
		}
	}
	return out, nil
}
