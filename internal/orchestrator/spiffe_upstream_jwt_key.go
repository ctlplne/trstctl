// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// SPIFFEUpstreamJWTKeyInput is a JWT signing key a SPIRE server publishes
// through the trstctl upstream authority plugin (A205).
type SPIFFEUpstreamJWTKeyInput struct {
	KeyID        string
	PublicKeyDER []byte
	// ExpiresAt is nil for a key without an expiry.
	ExpiresAt *time.Time
	Tainted   bool
}

// InvalidSPIFFEUpstreamJWTKeyError is a key the projection would refuse.
type InvalidSPIFFEUpstreamJWTKeyError struct{ Reason string }

func (e *InvalidSPIFFEUpstreamJWTKeyError) Error() string { return "orchestrator: " + e.Reason }

// ErrSPIFFEUpstreamJWTKeyConflict refuses a key ID already published with a
// different public key or expiry.
var ErrSPIFFEUpstreamJWTKeyConflict = errors.New("orchestrator: that JWT key ID is published with a different key or expiry")

// PublishSPIFFEUpstreamJWTKey records a SPIRE server's JWT signing key and
// returns every unexpired key the tenant's servers have published, the set a
// server adds to its bundle. Publishing a key already recorded changes
// nothing, except that it may taint the key; the same ID with a different key
// or expiry is refused.
func (o *Orchestrator) PublishSPIFFEUpstreamJWTKey(ctx context.Context, tenantID string, in SPIFFEUpstreamJWTKeyInput) ([]store.SPIFFEUpstreamJWTKey, error) {
	pl := projections.SPIFFEUpstreamJWTKeyPublished{
		KeyID: strings.TrimSpace(in.KeyID), PublicKey: in.PublicKeyDER, Tainted: in.Tainted,
	}
	if in.ExpiresAt != nil {
		expires := in.ExpiresAt.UTC().Truncate(time.Second)
		pl.ExpiresAt = &expires
	}
	if err := projections.ValidateSPIFFEUpstreamJWTKeyPublished(pl); err != nil {
		return nil, &InvalidSPIFFEUpstreamJWTKeyError{Reason: err.Error()}
	}
	current, err := o.store.GetSPIFFEUpstreamJWTKey(ctx, tenantID, pl.KeyID)
	switch {
	case err == nil:
		if !bytes.Equal(current.PublicKeyDER, pl.PublicKey) || !sameOptionalTime(current.ExpiresAt, pl.ExpiresAt) {
			return nil, ErrSPIFFEUpstreamJWTKeyConflict
		}
		if current.Tainted || !pl.Tainted {
			return o.store.ListSPIFFEUpstreamJWTKeys(ctx, tenantID, time.Now())
		}
	case !store.IsNotFound(err):
		return nil, err
	}
	data, err := json.Marshal(pl)
	if err != nil {
		return nil, err
	}
	if _, err := o.emit(ctx, projections.EventSPIFFEUpstreamJWTKeyPublished, tenantID, data); err != nil {
		if errors.Is(err, store.ErrSPIFFEUpstreamJWTKeyConflict) {
			return nil, ErrSPIFFEUpstreamJWTKeyConflict
		}
		return nil, err
	}
	return o.store.ListSPIFFEUpstreamJWTKeys(ctx, tenantID, time.Now())
}

func sameOptionalTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}
