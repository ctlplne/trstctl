// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// EventSPIFFEUpstreamJWTKeyPublished records a JWT signing key a SPIRE server
// published through the trstctl upstream authority plugin (A205).
const EventSPIFFEUpstreamJWTKeyPublished = "spiffe.upstream_jwt_key.published"

// SPIFFEUpstreamJWTKeyPublished is one published key: public material only.
// The publisher is the event's actor.
type SPIFFEUpstreamJWTKeyPublished struct {
	KeyID string `json:"key_id"`
	// PublicKey is the PKIX DER public key (base64 in JSON).
	PublicKey []byte     `json:"public_key"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Tainted   bool       `json:"tainted,omitempty"`
}

var spiffeJWTKeyIDRE = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`)

// ValidateSPIFFEUpstreamJWTKeyPublished checks a published key: a printable
// key ID and a PKIX public key of a supported algorithm.
func ValidateSPIFFEUpstreamJWTKeyPublished(pl SPIFFEUpstreamJWTKeyPublished) error {
	if !spiffeJWTKeyIDRE.MatchString(pl.KeyID) {
		return errors.New("a JWT key needs a key ID of 1 to 256 printable characters")
	}
	if len(pl.PublicKey) > 4096 {
		return errors.New("the JWT public key is too large")
	}
	if err := crypto.ValidatePublicKeyDER(pl.PublicKey); err != nil {
		return fmt.Errorf("the JWT public key is not a supported PKIX key: %w", err)
	}
	return nil
}

func (p *Projector) applySPIFFEUpstreamJWTKeyTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != EventSPIFFEUpstreamJWTKeyPublished {
		return false, nil
	}
	var pl SPIFFEUpstreamJWTKeyPublished
	if err := decode(e, &pl); err != nil {
		return true, err
	}
	if err := ValidateSPIFFEUpstreamJWTKeyPublished(pl); err != nil {
		return true, fmt.Errorf("projections: %s: %w", e.Type, err)
	}
	publisher := ""
	if e.Actor != nil {
		publisher = e.Actor.Subject
	}
	return true, p.store.ApplySPIFFEUpstreamJWTKeyPublishedTx(ctx, tx, store.SPIFFEUpstreamJWTKey{
		TenantID: e.TenantID, KeyID: pl.KeyID, PublicKeyDER: pl.PublicKey, ExpiresAt: pl.ExpiresAt,
		Tainted: pl.Tainted, PublishedBy: publisher, PublishedAt: e.Time, UpdatedAt: e.Time,
		EventSequence: e.Sequence,
	})
}
