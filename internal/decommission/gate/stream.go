// SPDX-License-Identifier: BUSL-1.1

package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/signing"
)

// VerifyGatedDestroyStream enforces the same required-set, audit-head and
// quorum checks as the unary gate while retaining only one key's dependency
// state. The signer transport has already hashed the exact public byte stream
// into req.SatisfactionEvidenceDigest before this method runs.
func (g *Gate) VerifyGatedDestroyStream(ctx context.Context, req signing.GatedDestroyRequest, evidence io.Reader) (signing.GatedDestroyDecision, error) {
	if err := ctx.Err(); err != nil {
		return signing.GatedDestroyDecision{}, err
	}
	if req.TenantID == "" || req.SubjectRef == "" || req.LedgerPosition == 0 || req.AssertedFinalEpoch == 0 ||
		len(req.SatisfactionEvidenceDigest) != 32 {
		return signing.GatedDestroyDecision{}, fmt.Errorf("%w: streamed command metadata or evidence digest missing", ErrInvalidEvidence)
	}
	decoder := json.NewDecoder(evidence)
	if err := expectJSONDelimiter(decoder, '{'); err != nil {
		return signing.GatedDestroyDecision{}, err
	}
	var version int
	var finalEpoch uint64
	var sawVersion, sawEpoch, sawEvents bool
	head := NewAuditChainHead()
	folder := depstate.NewKeyFolder(req.TenantID, req.SubjectRef)
	var position uint64
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return signing.GatedDestroyDecision{}, fmt.Errorf("%w: segment field: %v", ErrInvalidEvidence, err)
		}
		switch key {
		case "version":
			if sawVersion {
				return signing.GatedDestroyDecision{}, fmt.Errorf("%w: duplicate segment version", ErrInvalidEvidence)
			}
			sawVersion = true
			if err := decoder.Decode(&version); err != nil {
				return signing.GatedDestroyDecision{}, err
			}
		case "final_epoch":
			if sawEpoch {
				return signing.GatedDestroyDecision{}, fmt.Errorf("%w: duplicate final epoch", ErrInvalidEvidence)
			}
			sawEpoch = true
			if err := decoder.Decode(&finalEpoch); err != nil {
				return signing.GatedDestroyDecision{}, err
			}
		case "events":
			if sawEvents {
				return signing.GatedDestroyDecision{}, fmt.Errorf("%w: duplicate events", ErrInvalidEvidence)
			}
			sawEvents = true
			if err := expectJSONDelimiter(decoder, '['); err != nil {
				return signing.GatedDestroyDecision{}, err
			}
			for decoder.More() {
				if err := ctx.Err(); err != nil {
					return signing.GatedDestroyDecision{}, err
				}
				var ev eventspec.Event
				if err := decoder.Decode(&ev); err != nil {
					return signing.GatedDestroyDecision{}, fmt.Errorf("%w: segment event: %v", ErrInvalidEvidence, err)
				}
				position++
				if ev.Sequence == 0 {
					ev.Sequence = position
				}
				if ev.Sequence > req.LedgerPosition {
					continue
				}
				head = ExtendAuditChainHead(head, ev)
				if err := folder.Apply(ev); err != nil {
					return signing.GatedDestroyDecision{}, fmt.Errorf("%w: fold segment event %d: %v", ErrInvalidEvidence, position, err)
				}
			}
			if err := expectJSONDelimiter(decoder, ']'); err != nil {
				return signing.GatedDestroyDecision{}, err
			}
		default:
			return signing.GatedDestroyDecision{}, fmt.Errorf("%w: unexpected segment field %v", ErrInvalidEvidence, key)
		}
	}
	if err := expectJSONDelimiter(decoder, '}'); err != nil {
		return signing.GatedDestroyDecision{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return signing.GatedDestroyDecision{}, fmt.Errorf("%w: trailing segment content", ErrInvalidEvidence)
	}
	if !sawEvents || (sawVersion && version != 0 && version != SchemaV1) ||
		(sawEpoch && finalEpoch != 0 && finalEpoch != req.AssertedFinalEpoch) ||
		!bytes.Equal(head, req.AuditChainHead) {
		return signing.GatedDestroyDecision{}, fmt.Errorf("%w: segment epoch or audit head mismatch", ErrInvalidEvidence)
	}
	state, found := folder.Snapshot()
	if !found {
		state = depstate.KeyState{TenantID: req.TenantID, KeyID: req.SubjectRef, LedgerPosition: req.LedgerPosition}
	}
	return g.verifyGatedDestroyState(ctx, req, state)
}

func expectJSONDelimiter(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: segment delimiter: %v", ErrInvalidEvidence, err)
	}
	if token != want {
		return fmt.Errorf("%w: expected segment delimiter %q", ErrInvalidEvidence, want)
	}
	return nil
}
