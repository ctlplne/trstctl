// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"time"

	"trstctl.com/trstctl/internal/projections"
)

// InvalidWorkloadJWTKeyRotationError is a rotation the projection would refuse.
type InvalidWorkloadJWTKeyRotationError struct{ Reason string }

func (e *InvalidWorkloadJWTKeyRotationError) Error() string { return "orchestrator: " + e.Reason }

// RotateWorkloadJWTKey records a rotation of the workload JWT signing key
// (N5-L3) whose key the signer already holds: the new generation is published
// now, signs from activatesAt, and the previous one stays published until
// previousRetiresAt. The caller serializes rotations and picks the generation.
func (o *Orchestrator) RotateWorkloadJWTKey(ctx context.Context, tenantID string, generation int, publishedAt, activatesAt, previousRetiresAt time.Time) error {
	pl := projections.WorkloadJWTKeyRotated{
		Generation: generation, KeyID: projections.WorkloadJWTKeyID(generation),
		PublishedAt: publishedAt.UTC(), ActivatesAt: activatesAt.UTC(), PreviousRetiresAt: previousRetiresAt.UTC(),
	}
	if err := projections.ValidateWorkloadJWTKeyRotated(pl); err != nil {
		return &InvalidWorkloadJWTKeyRotationError{Reason: err.Error()}
	}
	payload, err := json.Marshal(pl)
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventWorkloadJWTKeyRotated, tenantID, payload)
	return err
}
