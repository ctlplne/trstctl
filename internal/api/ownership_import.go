// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ownership"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Bulk ownership import, and the disagreements it refuses to resolve (epic I2).
//
// The response deliberately reports applied work and refused work SEPARATELY. A
// single "imported 412 owners" hides the eleven it overwrote, and those eleven
// are the only rows anybody needed to look at.

type ownershipImportResponse struct {
	// Applied is how many field values the import set.
	Applied int `json:"applied"`
	// Unchanged is how many already matched, so a re-run reads as "already in
	// sync" rather than "did nothing".
	Unchanged int `json:"unchanged"`
	// Conflicts are the disagreements. A refused one has current_attested true.
	Conflicts []ownershipConflict `json:"conflicts"`
	Detail    string              `json:"detail"`
	Guidance  string              `json:"guidance"`
}

type ownershipConflict struct {
	// ID is the stored conflict row, present when listing the queue and absent
	// on an import response — an import reports what it just decided, and those
	// rows have not been read back. A conflict an operator must eventually
	// resolve needs a handle; one that was just reported does not yet have one.
	ID              string `json:"id,omitempty"`
	OwnerID         string `json:"owner_id"`
	Field           string `json:"field"`
	CurrentValue    string `json:"current_value"`
	CurrentSource   string `json:"current_source"`
	IncomingValue   string `json:"incoming_value"`
	IncomingSource  string `json:"incoming_source"`
	IncomingRef     string `json:"incoming_ref"`
	CurrentAttested bool   `json:"current_attested"`
	Why             string `json:"why"`
}

const ownershipImportGuidance = "An import fills in ownership nobody recorded and NEVER overwrites " +
	"ownership a human attested — that becomes a conflict instead, with both sides and the source " +
	"row that caused it. Last-writer-wins is what makes CMDB integrations distrusted: one import " +
	"replaces a verified owner with a stale alias, the expiry notice goes to a team that no longer " +
	"exists, and nobody learns why until the certificate does. A blank cell is silence, not a " +
	"deletion. Changes to values nobody attested ARE applied, and are still listed, because a change " +
	"nobody was told about is how ownership data quietly stops matching reality."

// importOwnership ingests a CSV of ownership claims.
//
// AN-2/AN-5: the changes are emitted as ownership.reconciled events and
// projected, under the caller's Idempotency-Key. A retried import must not
// double-record the same disagreements — a conflict queue that grows every time
// somebody re-uploads the file is a queue nobody reads.
func (a *API) importOwnership(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		records, err := ownership.ParseCSV(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		owners, err := a.store.ListOwners(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		byName := map[string]store.Owner{}
		for _, o := range owners {
			byName[o.Name] = o
		}

		out := ownershipImportResponse{Conflicts: []ownershipConflict{}, Guidance: ownershipImportGuidance}
		now := time.Now().UTC()
		for _, rec := range records {
			existing, found := byName[rec.OwnerName]
			if !found {
				// An import that invented owners would let a typo create a parallel
				// estate nobody is looking at. Naming an unknown owner is a conflict
				// with the estate, not a licence to add one.
				out.Conflicts = append(out.Conflicts, ownershipConflict{
					Field: "owner", IncomingValue: rec.OwnerName, IncomingRef: rec.SourceRef,
					IncomingSource: string(ownership.SourceCSVImport),
					Why: "No owner of that name exists. The import does not create owners: a typo would " +
						"otherwise produce a parallel estate nobody is looking at.",
				})
				continue
			}
			plan := ownership.Reconcile(rec, ownership.Existing{
				OwnerID:       existing.ID,
				ApplicationID: existing.ApplicationID,
				Service:       existing.Service,
				BusinessUnit:  existing.BusinessUnit,
				Environment:   existing.Environment,
				Attested:      existing.OwnershipAttested(),
			}, ownership.SourceCSVImport, now)

			out.Unchanged += plan.Unchanged
			out.Applied += len(plan.Apply)
			if err := a.orch.ReconcileOwnership(ctx, tenantID,
				projections.OwnershipReconciledFrom(existing.ID, string(ownership.SourceCSVImport), rec.SourceRef, now, plan)); err != nil {
				return 0, nil, err
			}
			for _, c := range plan.Conflicts {
				out.Conflicts = append(out.Conflicts, ownershipConflict{
					OwnerID: c.OwnerID, Field: c.Field,
					CurrentValue: c.CurrentValue, CurrentSource: string(c.CurrentSource),
					IncomingValue: c.IncomingValue, IncomingSource: string(c.IncomingSource),
					IncomingRef: c.IncomingRef, CurrentAttested: c.CurrentAttested, Why: c.Why,
				})
			}
		}
		out.Detail = ownershipImportDetail(out)
		return http.StatusOK, out, nil
	})
}

// ownershipImportDetail says what happened, leading with what was refused.
func ownershipImportDetail(out ownershipImportResponse) string {
	refused := 0
	for _, c := range out.Conflicts {
		if c.CurrentAttested {
			refused++
		}
	}
	switch {
	case refused > 0:
		return "Some ownership was NOT changed: it was attested by a human and the import does not " +
			"overwrite an attestation. Those rows are listed below with both values and the source " +
			"row that disagreed."
	case len(out.Conflicts) > 0:
		return "Applied, with changes recorded. Nothing refused — none of the values the import " +
			"replaced had been attested by a human."
	case out.Applied > 0:
		return "Applied. Every change filled in ownership that was previously unrecorded."
	default:
		return "Nothing to do: every value the source spoke about already matched."
	}
}

type ownershipConflictList struct {
	Items []ownershipConflict `json:"items"`
	// Refused counts the ones an import declined to apply. Served separately
	// because a queue that mixes "we did not do this" with "we did this and are
	// telling you" is one an operator learns to ignore.
	Refused  int    `json:"refused"`
	Guidance string `json:"guidance"`
}

// listOwnershipConflicts serves the unresolved disagreements.
func (a *API) listOwnershipConflicts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeError(w, errStatus(http.StatusBadRequest, "tenant is required"))
		return
	}
	rows, err := a.store.ListOpenOwnershipConflicts(r.Context(), tenantID, 100)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := ownershipConflictList{Items: []ownershipConflict{}, Guidance: ownershipImportGuidance}
	for _, c := range rows {
		if c.CurrentAttested {
			out.Refused++
		}
		out.Items = append(out.Items, ownershipConflict{
			ID: c.ID, OwnerID: c.OwnerID, Field: c.Field,
			CurrentValue: c.CurrentValue, CurrentSource: c.CurrentSource,
			IncomingValue: c.IncomingValue, IncomingSource: c.IncomingSource,
			IncomingRef: c.IncomingRef, CurrentAttested: c.CurrentAttested,
		})
	}
	a.writeJSON(w, http.StatusOK, out)
}

type ownershipResolveBody struct {
	Resolution string `json:"resolution"`
}

// resolveOwnershipConflict closes a disagreement (I2).
//
// Until this existed the conflict queue was READ-ONLY: an operator could see
// that two sources disagreed and had no way to record which side won. A queue
// that only ever grows is one people stop reading, and the disagreements it
// holds are exactly the rows somebody needed to act on.
func (a *API) resolveOwnershipConflict(w http.ResponseWriter, r *http.Request) {
	idem := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idem, func(ctx context.Context, tenantID string) (int, any, error) {
		var body ownershipResolveBody
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if strings.TrimSpace(body.Resolution) == "" {
			return 0, nil, errStatus(http.StatusBadRequest,
				"resolution is required: closing a disagreement without saying which side was right leaves the next reader exactly where they started")
		}
		if err := a.orch.ResolveOwnershipConflict(ctx, tenantID, r.PathValue("id"),
			principalSubject(ctx), body.Resolution); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]string{"id": r.PathValue("id"), "resolution": body.Resolution}, nil
	})
}
