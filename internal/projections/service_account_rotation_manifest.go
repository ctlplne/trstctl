// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/servicedependents"
)

const EventServiceDependentManifestOpened = "pam.service_dependents.manifest_opened"
const EventServiceDependentManifestPageRecorded = "pam.service_dependents.manifest_page_recorded"
const EventServiceDependentManifestSealed = "pam.service_dependents.manifest_sealed"

type ServiceDependentManifestOpened struct {
	Header servicedependents.RotationManifestHeader `json:"header"`
	Actor  string                                   `json:"actor"`
	At     time.Time                                `json:"at"`
}
type ServiceDependentManifestPageRecorded struct {
	Page  servicedependents.RotationManifestPage `json:"page"`
	Actor string                                 `json:"actor"`
	At    time.Time                              `json:"at"`
}
type ServiceDependentManifestSealed struct {
	Seal  servicedependents.RotationManifestSeal `json:"seal"`
	Actor string                                 `json:"actor"`
	At    time.Time                              `json:"at"`
}

func validateManifestEnvelope(e events.Event, sourceID, actor string, at time.Time) error {
	if schemaVersionOf(e) != 1 || e.ID != sourceID || actor == "" || len(actor) > 512 || at.IsZero() || !e.Time.Equal(at) {
		return errors.New("dependent manifest: exact versioned source, author and event time required")
	}
	return validateApprovalActor(e, actor)
}
func (p *Projector) applyServiceDependentManifestTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventServiceDependentManifestOpened:
		var v ServiceDependentManifestOpened
		if err := decode(e, &v); err != nil {
			return true, err
		}
		if err := ValidateServiceDependentManifestOpened(e, v); err != nil {
			return true, err
		}
		return true, p.store.ApplyServiceDependentManifestOpenedTx(ctx, tx, e.TenantID, v.Header, v.Actor, v.At)
	case EventServiceDependentManifestPageRecorded:
		var v ServiceDependentManifestPageRecorded
		if err := decode(e, &v); err != nil {
			return true, err
		}
		header, err := p.store.GetServiceDependentManifestTx(ctx, tx, e.TenantID, v.Page.ID, false)
		if err != nil {
			return true, err
		}
		if err := ValidateServiceDependentManifestPage(e, v, header.Header); err != nil {
			return true, err
		}
		return true, p.store.ApplyServiceDependentManifestPageTx(ctx, tx, e.TenantID, v.Page, v.Actor, v.At)
	case EventServiceDependentManifestSealed:
		var v ServiceDependentManifestSealed
		if err := decode(e, &v); err != nil {
			return true, err
		}
		header, err := p.store.GetServiceDependentManifestTx(ctx, tx, e.TenantID, v.Seal.ID, false)
		if err != nil {
			return true, err
		}
		if err := ValidateServiceDependentManifestSealed(e, v, header.Header); err != nil {
			return true, err
		}
		return true, p.store.ApplyServiceDependentManifestSealedTx(ctx, tx, e.TenantID, v.Seal, v.Actor, v.At)
	}
	return false, nil
}

func ValidateServiceDependentManifestOpened(e events.Event, v ServiceDependentManifestOpened) error {
	if e.Type != EventServiceDependentManifestOpened || v.Header.Validate() != nil || !v.At.Equal(v.Header.CreatedAt) {
		return errors.New("dependent manifest: frozen header source differs")
	}
	return validateManifestEnvelope(e, servicedependents.RotationManifestHeaderSourceID(e.TenantID, v.Header.ID), v.Actor, v.At)
}
func ValidateServiceDependentManifestPage(e events.Event, v ServiceDependentManifestPageRecorded, header servicedependents.RotationManifestHeader) error {
	if e.Type != EventServiceDependentManifestPageRecorded || v.Page.Validate(header) != nil || v.At.Before(header.CreatedAt) || !v.At.Before(header.ExpiresAt) {
		return errors.New("dependent manifest: frozen page source differs")
	}
	return validateManifestEnvelope(e, servicedependents.RotationManifestPageSourceID(e.TenantID, v.Page.ID, v.Page.Number), v.Actor, v.At)
}
func ValidateServiceDependentManifestSealed(e events.Event, v ServiceDependentManifestSealed, header servicedependents.RotationManifestHeader) error {
	if e.Type != EventServiceDependentManifestSealed || v.Seal.Validate(header) != nil || v.At.Before(header.CreatedAt) || !v.At.Before(v.Seal.ExpiresAt) {
		return errors.New("dependent manifest: frozen seal source differs")
	}
	return validateManifestEnvelope(e, servicedependents.RotationManifestSealSourceID(e.TenantID, v.Seal.ID), v.Actor, v.At)
}
