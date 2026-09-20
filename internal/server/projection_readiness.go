// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
)

const projectionHealthUnavailable = "projection tail health unavailable"

// probeProjectionTail answers the one readiness question ordinary lag cannot:
// did the tail record a specific event it could not apply? A read model can be a
// few events behind while healthy and catching up, so positive lag by itself does
// not remove a replica from service. A persisted failed sequence does.
//
// The persisted LastError is intentionally never copied into the returned error.
// Projection failures may wrap SQL, connector, or payload details. Operators get
// the safe coordinates needed to find the event and size the gap; raw detail stays
// in the protected server log / PostgreSQL health record.
func (s *Server) probeProjectionTail(ctx context.Context) error {
	if s.store == nil || s.log == nil {
		return errors.New(projectionHealthUnavailable)
	}
	health, err := s.store.ProjectionTailHealth(ctx)
	if err != nil {
		return errors.New(projectionHealthUnavailable)
	}
	if health.FailedSequence == 0 {
		return nil
	}

	head, err := s.log.LastSequence(ctx)
	if err != nil {
		return fmt.Errorf(
			"projection tail failed: applied_sequence=%d failed_sequence=%d lag=unknown",
			health.AppliedSequence, health.FailedSequence,
		)
	}
	var lag uint64
	if head > health.AppliedSequence {
		lag = head - health.AppliedSequence
	}
	return fmt.Errorf(
		"projection tail failed: applied_sequence=%d failed_sequence=%d lag=%d",
		health.AppliedSequence, health.FailedSequence, lag,
	)
}
