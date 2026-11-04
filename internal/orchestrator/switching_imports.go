// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/switchkit"
)

// Switching imports (A265). An import is recorded first — its header with the
// mapping report's counts, then every row in batches — and applied after:
// each mapped row's certificate is recorded (source switching:<import>) under
// the owner its export named, and the rows that became certificates are
// recorded in turn. A certificate already in the inventory is linked, never
// rewritten: re-recording it would replace its owner, names and source with
// the export's. Recording is restart-safe (every event ID is derived from the
// import), applying is restart-safe (a row is pending until its rows_applied
// event lands), and an import completes only once every row is recorded.

// SwitchingImportSource is the inventory source of an imported certificate.
func SwitchingImportSource(importID string) string { return "switching:" + importID }

// SwitchingImportID is the import an apply command records: the same command
// retried records the same import.
func SwitchingImportID(tenantID, command string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("switching-import\x00"+tenantID+"\x00"+command)).String()
}

func (o *Orchestrator) emitSwitching(ctx context.Context, tenantID, eventID, eventType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if eventID == "" {
		_, err = o.emit(ctx, eventType, tenantID, data)
		return err
	}
	ev, err := o.emitPrepared(ctx, events.Event{ID: eventID, Type: eventType, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	if ev.ID != eventID || ev.Type != eventType || !bytes.Equal(ev.Data, data) {
		return fmt.Errorf("%w: switching import event %s differs from the recorded one", store.ErrIdempotencyConflict, eventID)
	}
	return nil
}

func switchingEventID(importID, part string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("switching-import-event\x00"+importID+"\x00"+part)).String()
}

// StartSwitchingImport records an import and all of its rows. Retried with the
// same import, it records only what the first attempt did not.
func (o *Orchestrator) StartSwitchingImport(ctx context.Context, tenantID string, started projections.SwitchingImportStarted, rows []store.SwitchingImportRow) error {
	if err := o.emitSwitching(ctx, tenantID, switchingEventID(started.ID, "started"), projections.EventSwitchingImportStarted, started); err != nil {
		return err
	}
	for i := 0; i < len(rows); i += projections.SwitchingImportRowsPerEvent {
		end := min(i+projections.SwitchingImportRowsPerEvent, len(rows))
		if err := o.emitSwitching(ctx, tenantID, switchingEventID(started.ID, "rows:"+strconv.Itoa(i)),
			projections.EventSwitchingImportRowsRecorded, projections.SwitchingImportRowsRecorded{ImportID: started.ID, Rows: rows[i:end]}); err != nil {
			return err
		}
	}
	return nil
}

// ApplySwitchingImportRows applies up to limit pending rows of one import and
// reports how many it applied and whether the import is now complete.
func (o *Orchestrator) ApplySwitchingImportRows(ctx context.Context, tenantID string, imp store.SwitchingImport, limit int) (int, bool, error) {
	pending, err := o.store.PendingSwitchingImportRows(ctx, tenantID, imp.ID, limit)
	if err != nil {
		return 0, false, err
	}
	if len(pending) == 0 {
		if imp.RowsRecorded < imp.RowsTotal {
			// Recording stopped short: the rows still to come are the apply
			// command's to record when it is retried, never dropped here.
			return 0, false, nil
		}
		return 0, true, o.emitSwitching(ctx, tenantID, switchingEventID(imp.ID, "completed"), projections.EventSwitchingImportCompleted,
			projections.SwitchingImportCompleted{ImportID: imp.ID, At: time.Now().UTC()})
	}
	owners, err := o.store.ListOwners(ctx, tenantID)
	if err != nil {
		return 0, false, err
	}
	// One owner per email in each application group, matched as the preview
	// matched it: the application view (A244) groups an owner's certificates.
	byKey := map[string]string{}
	for _, owner := range owners {
		byKey[switchkit.OwnerKey(owner.Email, owner.ApplicationID)] = owner.ID
	}
	fingerprints := make([]string, 0, len(pending))
	for _, row := range pending {
		fingerprints = append(fingerprints, row.Fingerprint)
	}
	known, err := o.store.CertificatesByFingerprint(ctx, tenantID, fingerprints)
	if err != nil {
		return 0, false, err
	}
	source := SwitchingImportSource(imp.ID)
	applied := make([]store.SwitchingRowApplied, 0, len(pending))
	flush := func() error {
		if len(applied) == 0 {
			return nil
		}
		err := o.emitSwitching(ctx, tenantID, "", projections.EventSwitchingImportRowsApplied,
			projections.SwitchingImportRowsApplied{ImportID: imp.ID, Rows: applied})
		applied = applied[:0]
		return err
	}
	for _, row := range pending {
		if have, ok := known[row.Fingerprint]; ok && have.Source != source {
			applied = append(applied, store.SwitchingRowApplied{Row: row.Row, CertificateID: have.ID, Linked: true})
		} else {
			ownerID := ""
			if row.OwnerEmail != "" {
				key := switchkit.OwnerKey(row.OwnerEmail, row.Application)
				if id, ok := byKey[key]; ok {
					ownerID = id
				} else {
					name := row.OwnerEmail
					if row.Application != "" {
						name = row.Application + " (" + row.OwnerEmail + ")"
					}
					created, err := o.CreateOwnerRecord(ctx, store.Owner{TenantID: tenantID, Kind: store.OwnerTeam, Name: name,
						Email: row.OwnerEmail, ApplicationID: row.Application})
					if err != nil {
						return 0, false, err
					}
					ownerID = created.ID
					byKey[key] = ownerID
				}
			}
			// An import is an observation, as the inventory import is, with no
			// issuance idempotency key: an imported certificate is the other
			// product's to renew, so it is never a renewal candidate here.
			in := store.Certificate{TenantID: tenantID, Subject: "CN=" + row.CommonName, SANs: row.SANs, Serial: row.Serial,
				Issuer: row.Issuer, KeyAlgorithm: row.KeyAlgorithm, Fingerprint: row.Fingerprint, NotAfter: row.NotAfter,
				Source: source, ObservationOnly: true, CertificateDER: row.CertificateDER}
			if len(row.Endpoints) > 0 {
				in.DeploymentLocation = strings.Join(row.Endpoints, ",")
			}
			if ownerID != "" {
				id := ownerID
				in.OwnerID = &id
			}
			cert, err := o.RecordCertificate(ctx, tenantID, in)
			if err != nil {
				_ = flush()
				return 0, false, err
			}
			applied = append(applied, store.SwitchingRowApplied{Row: row.Row, CertificateID: cert.ID, OwnerID: ownerID})
		}
		if len(applied) == projections.SwitchingImportRowsPerEvent {
			if err := flush(); err != nil {
				return 0, false, err
			}
		}
	}
	return len(pending), false, flush()
}

// RequestSwitchingWatch starts watch round round of an import with the private
// egress the operator granted. The same round requested twice is one round.
func (o *Orchestrator) RequestSwitchingWatch(ctx context.Context, tenantID string, req projections.SwitchingWatchRequested) error {
	if req.PrivateEgressCIDRs == nil {
		req.PrivateEgressCIDRs = []string{}
	}
	return o.emitSwitching(ctx, tenantID, switchingEventID(req.ImportID, "watch:"+strconv.Itoa(req.Round)),
		projections.EventSwitchingWatchRequested, req)
}

// RecordSwitchingWatch records one batch of a watch round's observations.
func (o *Orchestrator) RecordSwitchingWatch(ctx context.Context, tenantID, importID string, round int, rows []store.SwitchingWatchResult) error {
	for i := 0; i < len(rows); i += projections.SwitchingImportRowsPerEvent {
		end := min(i+projections.SwitchingImportRowsPerEvent, len(rows))
		if err := o.emitSwitching(ctx, tenantID, "", projections.EventSwitchingWatchObserved,
			projections.SwitchingWatchObserved{ImportID: importID, Round: round, Rows: rows[i:end]}); err != nil {
			return err
		}
	}
	return nil
}
