// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"trstctl.com/trstctl/internal/auditsink"
)

// ReadableEvent is an authorized presentation of protected fields, separate
// from the ciphertext Record whose hash/signature remains stable after erasure.
// It has no hash field and is never included in Bundle or managed archives.
type ReadableEvent = auditsink.ReadableEvent

type ReadableView struct {
	Records        []Record
	PrevHash       string
	ArchivedPrefix ArchivedPrefix
	ReadableEvents []ReadableEvent
}

// SearchReadableView captures core and readable views in ONE pinned history
// read, then limits both to exactly the final selected records. Callers must
// label/export readable fields separately; they are outside the signed core.
func (s *Service) SearchReadableView(ctx context.Context, q Query) (ReadableView, error) {
	views := map[uint64]ReadableEvent{}
	records, seed, prefix, err := s.searchWithCapturedViews(ctx, q, views)
	if err != nil {
		return ReadableView{}, err
	}
	result := ReadableView{Records: records, PrevHash: seed, ArchivedPrefix: prefix}
	for _, record := range records {
		if view, found := views[record.Sequence]; found {
			result.ReadableEvents = append(result.ReadableEvents, view)
		}
	}
	return result, nil
}
