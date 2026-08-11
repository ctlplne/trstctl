// SPDX-License-Identifier: MPL-2.0

package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/crypto"
)

// TenantDataRewriteHistoryPairs yields the exact source/target history pair
// covered by one signed rewrite report. A compact gap must be present on both
// sides with identical bounds. Live records must carry their exact stored event
// envelope, subject, and canonical message ID.
type TenantDataRewriteHistoryPairs func(
	yield func(source, target BackupHistoryRecord) error,
) error

// VerifyTenantDataRewriteDigestProof recomputes the three content roots in a
// signed rewrite report from an exact source/target pair. It is intentionally
// independent of mutable stream metadata so disaster recovery can prove a
// deterministic descendant after the superseded generation was securely
// deleted. Signature verification remains the caller's responsibility.
func VerifyTenantDataRewriteDigestProof(
	report TenantDataRewriteReport,
	pairs TenantDataRewriteHistoryPairs,
) error {
	if pairs == nil {
		return errors.New("events: tenant rewrite digest proof source is required")
	}
	if report.FirstSequence == 0 || report.SourceCutSequence < report.FirstSequence ||
		report.SourceCutSequence == ^uint64(0) ||
		report.ReceiptSequence != report.SourceCutSequence+1 {
		return errors.New("events: tenant rewrite digest proof has invalid sequence bounds")
	}

	envelopeDigest := crypto.SHA256Hex([]byte("trstctl.event-rewrite.envelopes.v1"))
	mappingDigest := crypto.SHA256Hex([]byte("trstctl.event-rewrite.mapping.v1"))
	targetContentDigest := crypto.SHA256Hex([]byte("trstctl.event-rewrite.target-content.v1"))
	changed := 0
	next := report.FirstSequence
	err := pairs(func(source, target BackupHistoryRecord) error {
		if source.IsGap() || target.IsGap() {
			if !source.IsGap() || !target.IsGap() ||
				source.Sequence != target.Sequence || source.GapThrough != target.GapThrough {
				return errors.New("events: tenant rewrite digest proof changed a history gap")
			}
			if source.GapThrough < report.FirstSequence {
				return nil
			}
			first := source.Sequence
			if first < report.FirstSequence {
				first = report.FirstSequence
			}
			if first != next || source.GapThrough > report.SourceCutSequence {
				return errors.New("events: tenant rewrite digest proof has a non-contiguous gap")
			}
			for sequence := first; sequence <= source.GapThrough; sequence++ {
				gap := struct {
					Sequence uint64 `json:"sequence"`
					Gap      bool   `json:"gap"`
				}{Sequence: sequence, Gap: true}
				envelopeDigest = digestChain(envelopeDigest, gap)
				targetContentDigest = digestChain(targetContentDigest, gap)
			}
			next = source.GapThrough + 1
			return nil
		}

		if source.Sequence < report.FirstSequence && target.Sequence < report.FirstSequence {
			return nil
		}
		if source.Sequence != next || target.Sequence != next || next > report.SourceCutSequence {
			return errors.New("events: tenant rewrite digest proof has non-contiguous live history")
		}
		sourceRaw, err := backupHistoryRaw(source)
		if err != nil {
			return err
		}
		targetRaw, err := backupHistoryRaw(target)
		if err != nil {
			return err
		}
		beforeInvariant, err := rewriteInvariantFor(sourceRaw)
		if err != nil {
			return err
		}
		afterInvariant, err := rewriteInvariantFor(targetRaw)
		if err != nil {
			return err
		}
		beforeCanonical, beforeErr := json.Marshal(beforeInvariant)
		afterCanonical, afterErr := json.Marshal(afterInvariant)
		if beforeErr != nil || afterErr != nil {
			return errors.Join(beforeErr, afterErr)
		}
		if !bytes.Equal(beforeCanonical, afterCanonical) {
			return fmt.Errorf("events: tenant rewrite digest proof changed immutable envelope at seq %d", next)
		}
		envelopeDigest = digestChain(envelopeDigest, beforeInvariant)
		targetContentDigest = digestTargetContent(targetContentDigest, targetRaw)
		if !bytes.Equal(sourceRaw.Data, targetRaw.Data) {
			var before storedEvent
			if err := json.Unmarshal(sourceRaw.Data, &before); err != nil {
				return errors.New("events: tenant rewrite digest proof source envelope is malformed")
			}
			mappingDigest = digestChain(mappingDigest, struct {
				Sequence uint64 `json:"sequence"`
				EventID  string `json:"event_id"`
				Before   string `json:"before_sha256"`
				After    string `json:"after_sha256"`
			}{
				Sequence: next, EventID: before.ID,
				Before: crypto.SHA256Hex(sourceRaw.Data), After: crypto.SHA256Hex(targetRaw.Data),
			})
			changed++
		}
		next++
		return nil
	})
	if err != nil {
		return err
	}
	if next != report.SourceCutSequence+1 {
		return errors.New("events: tenant rewrite digest proof does not cover the signed source cut")
	}
	if changed != report.ChangedEvents || mappingDigest != report.MappingDigest {
		return errors.New("events: tenant rewrite mapping/count does not match signed report")
	}
	if envelopeDigest != report.EnvelopeDigest {
		return errors.New("events: tenant rewrite envelope root does not match signed report")
	}
	if targetContentDigest != report.TargetContentDigest {
		return errors.New("events: tenant rewrite target-content root does not match signed report")
	}
	return nil
}

func backupHistoryRaw(record BackupHistoryRecord) (*jetstream.RawStreamMsg, error) {
	if record.IsGap() || record.Sequence == 0 || strings.TrimSpace(record.Subject) == "" ||
		strings.TrimSpace(record.MessageID) == "" || len(record.Stored) == 0 {
		return nil, errors.New("events: tenant rewrite digest proof record is incomplete")
	}
	return &jetstream.RawStreamMsg{
		Subject: record.Subject, Sequence: record.Sequence,
		Header: nats.Header{jetstream.MsgIDHeader: []string{record.MessageID}},
		Data:   record.Stored,
	}, nil
}

// ValidateTenantDataRewriteLineage proves that sequential signed reports form
// one generation chain and that its final target is the generation currently
// serving events. This makes a receipt copied from another sanitation run
// unusable even when tenant, count, and cut happen to match.
func ValidateTenantDataRewriteLineage(
	reports []TenantDataRewriteReport,
	activeStream, activeGeneration string,
) error {
	if len(reports) == 0 || strings.TrimSpace(activeStream) == "" ||
		strings.TrimSpace(activeGeneration) == "" {
		return errors.New("events: tenant rewrite lineage is incomplete")
	}
	operations := make(map[string]struct{}, len(reports))
	for index, report := range reports {
		if strings.TrimSpace(report.OperationID) == "" ||
			strings.TrimSpace(report.SourceStream) == "" ||
			strings.TrimSpace(report.SourceGeneration) == "" ||
			report.TargetGeneration != report.OperationID ||
			report.TargetStream != rewriteStreamPrefix+report.OperationID ||
			report.SourceStream == report.TargetStream ||
			strings.TrimSpace(report.SourceConfigDigest) == "" ||
			strings.TrimSpace(report.TargetConfigDigest) == "" {
			return errors.New("events: tenant rewrite lineage contains an invalid generation identity")
		}
		if _, duplicate := operations[report.OperationID]; duplicate {
			return errors.New("events: tenant rewrite lineage reuses an operation identity")
		}
		operations[report.OperationID] = struct{}{}
		if index == 0 {
			continue
		}
		previous := reports[index-1]
		if report.SourceStream != previous.TargetStream ||
			report.SourceGeneration != previous.TargetGeneration ||
			report.FirstSequence != previous.FirstSequence ||
			report.SourceCutSequence != previous.ReceiptSequence {
			return errors.New("events: tenant rewrite lineage has a broken generation link")
		}
	}
	last := reports[len(reports)-1]
	if last.TargetStream != activeStream || last.TargetGeneration != activeGeneration {
		return errors.New("events: tenant rewrite lineage does not terminate at the active generation")
	}
	return nil
}

// ActiveHistoryIdentity returns the stream and generation currently owning the
// event subject. Callers should hold one history-read wall when comparing this
// identity with exported records from the same view.
func (l *Log) ActiveHistoryIdentity(ctx context.Context) (string, string, error) {
	if l == nil {
		return "", "", errors.New("events: active history log is nil")
	}
	var streamName, generation string
	err := l.withHistoryRead(ctx, func(ctx context.Context) error {
		name, stream, err := l.resolveActiveStream(ctx)
		if err != nil {
			return err
		}
		info, err := l.infoForStream(ctx, stream)
		if err != nil {
			return err
		}
		streamName = name
		generation = streamGeneration(info)
		if streamName == "" || generation == "" {
			return errors.New("events: active history identity is incomplete")
		}
		return nil
	})
	return streamName, generation, err
}
