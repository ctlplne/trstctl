// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// Leaked-secret moves (P6).
const (
	// EventDiscoveryFindingSecretMoved links a leaked-secret finding to the
	// native secret its value moved into. No value is carried.
	EventDiscoveryFindingSecretMoved = "discovery.finding.secret_moved" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	// EventDiscoveryFindingSecretConsumerRead records the first read of a
	// moved secret's version newer than the moved one.
	EventDiscoveryFindingSecretConsumerRead = "discovery.finding.secret_consumer_read" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
)

// DiscoveryFindingSecretMoved is the payload of discovery.finding.secret_moved:
// the secret and version that hold the moved value, who moved it, and the
// history commits that still held it (locations only).
type DiscoveryFindingSecretMoved struct {
	FindingID     string                        `json:"finding_id"`
	SecretName    string                        `json:"secret_name"`
	SecretVersion int                           `json:"secret_version"`
	MovedBy       string                        `json:"moved_by"`
	Residue       []store.SecretResidueLocation `json:"residue,omitempty"`
}

// DiscoveryFindingSecretConsumerRead is the payload of
// discovery.finding.secret_consumer_read.
type DiscoveryFindingSecretConsumerRead struct {
	FindingID  string    `json:"finding_id"`
	SecretName string    `json:"secret_name"`
	Version    int       `json:"version"`
	Reader     string    `json:"reader"`
	ReadAt     time.Time `json:"read_at"`
}

func init() {
	knownSchemaVersions[EventDiscoveryFindingSecretMoved] = map[int]bool{1: true}
	knownSchemaVersions[EventDiscoveryFindingSecretConsumerRead] = map[int]bool{1: true}
}

func (p *Projector) applyDiscoverySecretMoveTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventDiscoveryFindingSecretMoved:
		var pl DiscoveryFindingSecretMoved
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.FindingID == "" || pl.SecretName == "" || pl.SecretVersion < 1 || e.Time.IsZero() {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		return true, p.store.ApplyDiscoveryFindingSecretMovedTx(ctx, tx, store.DiscoveryFindingSecretMove{
			TenantID: e.TenantID, FindingID: pl.FindingID, SecretName: pl.SecretName, SecretVersion: pl.SecretVersion,
			MovedBy: pl.MovedBy, MovedAt: e.Time, Residue: pl.Residue,
		}, e.Sequence)
	case EventDiscoveryFindingSecretConsumerRead:
		var pl DiscoveryFindingSecretConsumerRead
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.FindingID == "" || pl.SecretName == "" || pl.Version < 2 || pl.ReadAt.IsZero() {
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		}
		return true, p.store.ApplyDiscoveryFindingSecretConsumerReadTx(ctx, tx, e.TenantID, pl.FindingID, pl.Version, pl.Reader, pl.ReadAt, e.Sequence)
	default:
		return false, nil
	}
}
