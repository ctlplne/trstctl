// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// EventWorkloadJWTKeyRotated records a rotation of the workload JWT signing
// key (N5-L3): the key that signs JWT-SVIDs and the tokens trstctl's OpenID
// issuer publishes. The rotator is the event's actor.
const EventWorkloadJWTKeyRotated = "workload.jwt_key.rotated"

// WorkloadJWTKeyRotated is one rotation: generation Generation is published at
// PublishedAt, signs from ActivatesAt, and the generation before it stays
// published until PreviousRetiresAt, so a verifier that cached either key set
// verifies every token signed in between.
type WorkloadJWTKeyRotated struct {
	Generation        int       `json:"generation"`
	KeyID             string    `json:"key_id"`
	PublishedAt       time.Time `json:"published_at"`
	ActivatesAt       time.Time `json:"activates_at"`
	PreviousRetiresAt time.Time `json:"previous_retires_at"`
}

// WorkloadJWTKeyID is the key ID tokens signed by a generation name. The first
// generation keeps the key ID the SPIFFE protocol has always used.
func WorkloadJWTKeyID(generation int) string {
	if generation <= 1 {
		return "spiffe-jwt"
	}
	return "spiffe-jwt-g" + strconv.Itoa(generation)
}

// maxWorkloadJWTKeyWindow bounds how far ahead a key is published and how long
// the key it replaces stays published.
const maxWorkloadJWTKeyWindow = 30 * 24 * time.Hour

// ValidateWorkloadJWTKeyRotated checks a rotation's generation, key ID and
// times: published, then signing, then the previous key retired.
func ValidateWorkloadJWTKeyRotated(pl WorkloadJWTKeyRotated) error {
	switch {
	case pl.Generation < 2:
		return errors.New("a rotation starts generation 2 or later")
	case pl.KeyID != WorkloadJWTKeyID(pl.Generation):
		return fmt.Errorf("generation %d names key %q", pl.Generation, WorkloadJWTKeyID(pl.Generation))
	case pl.PublishedAt.IsZero() || pl.ActivatesAt.Before(pl.PublishedAt) || !pl.PreviousRetiresAt.After(pl.ActivatesAt):
		return errors.New("a rotation publishes the key, then signs with it, then retires the previous one")
	case pl.ActivatesAt.Sub(pl.PublishedAt) > maxWorkloadJWTKeyWindow || pl.PreviousRetiresAt.Sub(pl.ActivatesAt) > maxWorkloadJWTKeyWindow:
		return errors.New("a rotation's windows are at most 30 days")
	}
	return nil
}

func (p *Projector) applyWorkloadJWTKeyTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != EventWorkloadJWTKeyRotated {
		return false, nil
	}
	var pl WorkloadJWTKeyRotated
	if err := decode(e, &pl); err != nil {
		return true, err
	}
	if err := ValidateWorkloadJWTKeyRotated(pl); err != nil {
		return true, fmt.Errorf("projections: %s: %w", e.Type, err)
	}
	return true, p.store.ApplyWorkloadJWTKeyRotatedTx(ctx, tx, e.TenantID, store.WorkloadJWTKeyRotation{
		Generation: pl.Generation, KeyID: pl.KeyID, PublishedAt: pl.PublishedAt,
		ActivatesAt: pl.ActivatesAt, PreviousRetiresAt: pl.PreviousRetiresAt,
	}, e.Sequence)
}
