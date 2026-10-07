// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
)

var errExternalIssuerRebuild = errors.New("external issuer provenance needs rebuild")

// Older binaries projected the external issuer only as mutable inventory
// source. Scan retained, already-applied events once on upgrade (then only the
// unexamined tail) and rebuild atomically if a live row lost that issuer. The
// cursor is deliberately independent of the ordinary projection checkpoint.
func (p *Projector) externalIssuerProvenanceNeedsRebuild(ctx context.Context, log *events.Log) (bool, error) {
	var needsRebuild bool
	err := log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		applied, checked, err := p.store.ExternalIssuerRecoveryCursor(readCtx)
		if err != nil {
			return err
		}
		head, err := log.LastSequence(readCtx)
		if err != nil {
			return err
		}
		if applied > head {
			return fmt.Errorf("projections: external issuer recovery checkpoint %d beyond history head %d", applied, head)
		}
		from := checked + 1
		if checked > applied {
			from = 1
		}
		if from > applied {
			return nil
		}
		err = log.ReplayThrough(readCtx, from, applied, func(e events.Event) error {
			if e.Type != EventCertificateRecorded {
				return nil
			}
			if err := ValidateSchemaVersion(e); err != nil {
				return err
			}
			var fact CertificateRecorded
			if err := json.Unmarshal(e.Data, &fact); err != nil {
				return err
			}
			issuerID := AuthenticatedExternalIssuer(e, fact)
			if issuerID == "" {
				return nil
			}
			cert, err := p.store.GetCertificateByFingerprint(readCtx, e.TenantID, fact.Fingerprint)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // tenant offboarded or its certificate was erased
			}
			if err != nil {
				return err
			}
			if cert.IssuingExternalCAID != issuerID {
				needsRebuild = true
				return errExternalIssuerRebuild
			}
			return nil
		})
		if errors.Is(err, errExternalIssuerRebuild) {
			return nil
		}
		if err != nil {
			return err
		}
		return p.store.MarkExternalIssuerCheckedThrough(readCtx, applied)
	})
	return needsRebuild, err
}
