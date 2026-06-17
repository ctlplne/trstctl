package orchestrator

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// This file holds the served domain commands (AN-2). Each records the mutation
// as an event (the source of truth), then projects it into the read model
// through the projector — the sole read-model writer. The served API delegates
// to these instead of writing the read tables directly, so a rebuild from the
// log reproduces every change and the audit trail is complete.

// emit appends a domain event to the log and projects it into the read model,
// returning the stored event (with its assigned ID, time, and sequence). The
// append is the source of truth; the projection is the same logic a rebuild
// uses, so live state and a replayed state agree.
func (o *Orchestrator) emit(ctx context.Context, eventType, tenantID string, payload []byte) (events.Event, error) {
	return o.emitVersioned(ctx, eventType, tenantID, 0, payload)
}

func (o *Orchestrator) emitVersioned(ctx context.Context, eventType, tenantID string, schemaVersion int, payload []byte) (events.Event, error) {
	ev, err := o.log.Append(ctx, events.Event{
		Type: eventType, TenantID: tenantID, SchemaVersion: schemaVersion, Data: payload,
	})
	if err != nil {
		return events.Event{}, err
	}
	if err := o.proj.Apply(ctx, ev); err != nil {
		return events.Event{}, err
	}
	return ev, nil
}

// CreateProfile records a new certificate-profile version as a full-spec
// profile.created/profile.updated event, then projects that event into the active
// certificate_profiles read model. The event is the source of truth (AN-2): a rebuild
// from the log restores every version and active-state transition.
func (o *Orchestrator) CreateProfile(ctx context.Context, tenantID, name string, spec json.RawMessage) (store.ProfileRecord, error) {
	actor := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		actor = a.Subject
	}
	var rec store.ProfileRecord
	err := o.store.WithProjectionLock(ctx, func(ctx context.Context) error {
		version, err := o.store.NextProfileVersion(ctx, tenantID, name)
		if err != nil {
			return err
		}
		rec = store.ProfileRecord{
			ID: uuid.NewString(), TenantID: tenantID, Name: name, Version: version,
			Spec: append(json.RawMessage(nil), spec...), Active: true, CreatedBy: actor,
		}
		evType := projections.EventProfileCreated
		if rec.Version > 1 {
			evType = projections.EventProfileUpdated
		}
		payload, err := json.Marshal(projections.ProfileVersioned{
			ID: rec.ID, Name: rec.Name, Version: rec.Version, Spec: rec.Spec,
			Active: rec.Active, CreatedBy: rec.CreatedBy,
		})
		if err != nil {
			return err
		}
		ev, err := o.emitVersioned(ctx, evType, tenantID, projections.ProfileEventSchemaVersion, payload)
		if err != nil {
			return err
		}
		rec.CreatedAt = ev.Time
		return nil
	})
	if err != nil {
		return store.ProfileRecord{}, err
	}
	return rec, nil
}

// CreateOwner records an owner.created event and returns the new owner.
func (o *Orchestrator) CreateOwner(ctx context.Context, tenantID, kind, name, email string) (store.Owner, error) {
	id := uuid.NewString()
	payload, err := json.Marshal(projections.OwnerCreated{ID: id, Kind: kind, Name: name, Email: email})
	if err != nil {
		return store.Owner{}, err
	}
	ev, err := o.emit(ctx, projections.EventOwnerCreated, tenantID, payload)
	if err != nil {
		return store.Owner{}, err
	}
	return store.Owner{ID: id, TenantID: tenantID, Kind: store.OwnerKind(kind), Name: name, Email: email, CreatedAt: ev.Time}, nil
}

// UpdateOwner records an owner.updated event. It returns a not-found error
// (mapped to 404) when the owner does not exist, without emitting an event — so
// a no-op never produces a spurious event.
func (o *Orchestrator) UpdateOwner(ctx context.Context, tenantID, id, kind, name, email string) error {
	if _, err := o.store.GetOwner(ctx, tenantID, id); err != nil {
		return err
	}
	payload, err := json.Marshal(projections.OwnerUpdated{ID: id, Kind: kind, Name: name, Email: email})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventOwnerUpdated, tenantID, payload)
	return err
}

// DeleteOwner records an owner.deleted event (404 if absent, no event emitted).
func (o *Orchestrator) DeleteOwner(ctx context.Context, tenantID, id string) error {
	if _, err := o.store.GetOwner(ctx, tenantID, id); err != nil {
		return err
	}
	payload, err := json.Marshal(projections.OwnerDeleted{ID: id})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventOwnerDeleted, tenantID, payload)
	return err
}

// CreateIssuer records an issuer.created event and returns the new issuer. The
// caller is expected to have validated it (the structural issuer rules).
func (o *Orchestrator) CreateIssuer(ctx context.Context, tenantID string, in store.Issuer) (store.Issuer, error) {
	id := uuid.NewString()
	chain := in.Chain
	if chain == nil {
		chain = []string{}
	}
	payload, err := json.Marshal(projections.IssuerCreated{
		ID: id, Kind: string(in.Kind), Name: in.Name, Chain: chain, PublicKey: in.PublicKey, Internal: in.Internal,
	})
	if err != nil {
		return store.Issuer{}, err
	}
	ev, err := o.emit(ctx, projections.EventIssuerCreated, tenantID, payload)
	if err != nil {
		return store.Issuer{}, err
	}
	out := in
	out.ID, out.TenantID, out.Chain, out.CreatedAt = id, tenantID, chain, ev.Time
	return out, nil
}

// CreateIdentity records an identity.created event and returns the new identity
// in its initial lifecycle status.
func (o *Orchestrator) CreateIdentity(ctx context.Context, tenantID string, in store.Identity) (store.Identity, error) {
	id := uuid.NewString()
	payload, err := json.Marshal(projections.IdentityCreated{
		ID: id, Kind: string(in.Kind), Name: in.Name, OwnerID: in.OwnerID, IssuerID: in.IssuerID, Attributes: in.Attributes,
	})
	if err != nil {
		return store.Identity{}, err
	}
	ev, err := o.emit(ctx, projections.EventIdentityCreated, tenantID, payload)
	if err != nil {
		return store.Identity{}, err
	}
	out := in
	out.ID, out.TenantID, out.Status, out.CreatedAt = id, tenantID, string(StateRequested), ev.Time
	return out, nil
}

// RecordCertificate records a certificate.recorded event (keyed by fingerprint)
// and returns the canonical inventoried row — whose id and created_at are stable
// across a re-ingest of the same certificate.
func (o *Orchestrator) RecordCertificate(ctx context.Context, tenantID string, in store.Certificate) (store.Certificate, error) {
	id := uuid.NewString()
	sans := in.SANs
	if sans == nil {
		sans = []string{}
	}
	payload, err := json.Marshal(projections.CertificateRecorded{
		ID: id, OwnerID: in.OwnerID, Subject: in.Subject, SANs: sans, Issuer: in.Issuer, Serial: in.Serial,
		Fingerprint: in.Fingerprint, KeyAlgorithm: in.KeyAlgorithm, NotBefore: in.NotBefore, NotAfter: in.NotAfter,
		DeploymentLocation: in.DeploymentLocation, Source: in.Source,
	})
	if err != nil {
		return store.Certificate{}, err
	}
	if _, err := o.emit(ctx, projections.EventCertificateRecorded, tenantID, payload); err != nil {
		return store.Certificate{}, err
	}
	return o.store.GetCertificateByFingerprint(ctx, tenantID, in.Fingerprint)
}

// RevokeCertificate records a certificate.revoked event (keyed by the cert's
// fingerprint) and projects it, so the inventoried certificate's status becomes
// revoked. The status change is driven through the projector (the sole
// read-model writer, AN-2), so it is reconstructed from the log on a Rebuild()
// rather than lost. revokedAt is supplied by the caller so a redelivery (AN-5)
// re-applies the same revocation time deterministically.
func (o *Orchestrator) RevokeCertificate(ctx context.Context, tenantID, fingerprint, serial, reason string, revokedAt time.Time) error {
	payload, err := json.Marshal(projections.CertificateRevoked{
		Fingerprint: fingerprint, Serial: serial, Reason: reason, RevokedAt: revokedAt.UTC(),
	})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventCertificateRevoked, tenantID, payload)
	return err
}

// SupersedeCertificate records a certificate.superseded event (keyed by the
// cert's fingerprint) and projects it, so the inventoried certificate's status
// becomes superseded and renewed_at is stamped (CORRECT-002). The status change
// is driven through the projector (the sole read-model writer, AN-2), so it is
// reconstructed from the log on a Rebuild() rather than lost — the same treatment
// as RevokeCertificate. renewedAt is supplied by the caller so a redelivery (AN-5)
// re-applies the same time deterministically; supersededBySerial is the successor
// serial, recorded for the audit trail.
func (o *Orchestrator) SupersedeCertificate(ctx context.Context, tenantID, fingerprint, serial, supersededBySerial string, renewedAt time.Time) error {
	payload, err := json.Marshal(projections.CertificateSuperseded{
		Fingerprint: fingerprint, Serial: serial, SupersededBy: supersededBySerial, RenewedAt: renewedAt.UTC(),
	})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventCertificateSuperseded, tenantID, payload)
	return err
}

// RecordSuccessorCertificate records a certificate.recorded event for the
// successor produced by a renewal/rotation, carrying its predecessor link
// (replaces_id) in the event so the link survives a Rebuild() (CORRECT-002). It
// returns the canonical inventoried row. This is the event-sourced replacement
// for the former direct successor-insert write into the read table.
func (o *Orchestrator) RecordSuccessorCertificate(ctx context.Context, tenantID string, in store.Certificate, replacesID string) (store.Certificate, error) {
	id := uuid.NewString()
	sans := in.SANs
	if sans == nil {
		sans = []string{}
	}
	rep := replacesID
	payload, err := json.Marshal(projections.CertificateRecorded{
		ID: id, OwnerID: in.OwnerID, Subject: in.Subject, SANs: sans, Issuer: in.Issuer, Serial: in.Serial,
		Fingerprint: in.Fingerprint, KeyAlgorithm: in.KeyAlgorithm, NotBefore: in.NotBefore, NotAfter: in.NotAfter,
		DeploymentLocation: in.DeploymentLocation, Source: in.Source, ReplacesID: &rep,
	})
	if err != nil {
		return store.Certificate{}, err
	}
	if _, err := o.emit(ctx, projections.EventCertificateRecorded, tenantID, payload); err != nil {
		return store.Certificate{}, err
	}
	return o.store.GetCertificateByFingerprint(ctx, tenantID, in.Fingerprint)
}
