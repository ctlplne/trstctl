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

// Credential usage events (M1).
const (
	// EventCredentialUsed is an API token's authenticated use: the first in a
	// window per client network and action, and again each time the window's
	// count doubles (2, 4, … 1024).
	EventCredentialUsed = "credential.used"
	// EventCredentialUsageGap is a window in which uses could not be recorded.
	EventCredentialUsageGap = "credential.usage_gap"
)

// Usage actions, so a later reader can tell routine calls from secret reads and
// lease requests.
const (
	CredentialActionAPICall      = "api_call"
	CredentialActionSecretRead   = "secret_read"
	CredentialActionLeaseRequest = "lease_request"
)

// CredentialUsed is the payload of credential.used.
type CredentialUsed struct {
	Kind         string    `json:"kind"`
	CredentialID string    `json:"credential_id"`
	Principal    string    `json:"principal"`
	SourceKind   string    `json:"source_kind"`
	Source       string    `json:"source"`
	Action       string    `json:"action"`
	WindowStart  time.Time `json:"window_start"`
	UsedAt       time.Time `json:"used_at"`
	Count        int       `json:"count"`
}

// CredentialUsageGap is the payload of credential.usage_gap.
type CredentialUsageGap struct {
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Dropped int64     `json:"dropped"`
}

func init() {
	knownSchemaVersions[EventCredentialUsed] = map[int]bool{1: true}
	knownSchemaVersions[EventCredentialUsageGap] = map[int]bool{1: true}
}

func (p *Projector) applyCredentialUsageTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventCredentialUsed:
		var pl CredentialUsed
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		switch {
		case pl.Kind != store.CredentialUsageAPIToken || pl.CredentialID == "" || pl.SourceKind != store.CredentialUsageSourceNetwork ||
			pl.Source == "" || pl.UsedAt.IsZero() || pl.WindowStart.IsZero() || pl.Count < 1:
			return true, fmt.Errorf("projections: %s payload is incomplete", e.Type)
		case pl.Action != CredentialActionAPICall && pl.Action != CredentialActionSecretRead && pl.Action != CredentialActionLeaseRequest:
			return true, fmt.Errorf("projections: %s action %q is unknown", e.Type, pl.Action)
		}
		return true, p.store.ApplyCredentialUseTx(ctx, tx, store.CredentialUse{
			TenantID: e.TenantID, Kind: pl.Kind, CredentialID: pl.CredentialID, Principal: pl.Principal,
			SourceKind: pl.SourceKind, Source: pl.Source, UsedAt: pl.UsedAt,
		}, e.Sequence)
	case EventCredentialUsageGap:
		var pl CredentialUsageGap
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		return true, p.store.ApplyCredentialUsageGapTx(ctx, tx, e.TenantID, store.CredentialUsageGap{
			ID: e.ID, From: pl.From, To: pl.To, Dropped: pl.Dropped,
		}, e.Sequence)
	default:
		return false, nil
	}
}

// applyMachineLoginUseTx folds a machine login into usage: a use of its login
// method by the workload it attested.
func (p *Projector) applyMachineLoginUseTx(ctx context.Context, tx pgx.Tx, e events.Event, pl MachineSessionStarted, issuedAt time.Time) error {
	return p.store.ApplyCredentialUseTx(ctx, tx, store.CredentialUse{
		TenantID: e.TenantID, Kind: store.CredentialUsageMachineAuth, CredentialID: pl.Method, Principal: pl.Principal,
		SourceKind: store.CredentialUsageSourceAttestation, Source: pl.Principal, UsedAt: issuedAt,
	}, e.Sequence)
}
