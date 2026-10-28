// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/lifecycle"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A216: with ca.rollover_draft_band_months set, an active authority whose
// remaining life enters that CA calendar band gets a re-key ceremony opened
// for it — the reviewed plan (same profile, same lifetime) and its approval
// request. The CA calendar opens it, so every custodian may approve it, and
// nothing changes until custodians approve and a person executes the re-key.

var caRolloverNamespace = uuid.MustParse("4d2b7e1c-9a63-5f08-b1c4-6e0a3f8d2c57")

// caCalendarActor opens drafted ceremonies.
const caCalendarActor = "trstctl:ca-calendar"

// RunCARolloverDraftsOnce drafts a re-key ceremony for each active authority
// inside the configured band that has no live draft, and returns how many
// drafts it recorded.
func (s *Server) RunCARolloverDraftsOnce(ctx context.Context) (int, error) {
	h := s.caHierarchy
	if h == nil || h.rolloverDraftBand <= 0 || s.store == nil || s.orch == nil {
		return 0, nil
	}
	tenants, err := s.store.TenantsWithCAHorizonCandidates(ctx)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	drafted := 0
	var errs []error
	for _, tenantID := range tenants {
		n, err := s.draftTenantCARollovers(ctx, h, tenantID, now)
		drafted += n
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", tenantID, err))
		}
	}
	return drafted, errors.Join(errs...)
}

func (s *Server) draftTenantCARollovers(ctx context.Context, h *caHierarchyService, tenantID string, now time.Time) (int, error) {
	authorities, err := s.store.ListCAAuthorities(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	drafts, err := s.store.CARolloverDrafts(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	drafted := 0
	for _, authority := range authorities {
		if authority.Status != "active" {
			continue
		}
		der, err := firstCertDER(authority.CertificatePEM)
		if err != nil {
			continue
		}
		info, err := certinfo.Inspect(der)
		if err != nil {
			continue
		}
		band, inBand := lifecycle.CAHorizonBand(now, info.NotAfter)
		if !inBand || band > h.rolloverDraftBand {
			continue
		}
		previous, hasPrevious := drafts[authority.ID]
		if hasPrevious {
			lapsed, err := s.rolloverDraftLapsed(ctx, tenantID, previous, band)
			if err != nil {
				return drafted, err
			}
			if !lapsed {
				continue
			}
		}
		draft := projections.CARolloverDrafted{AuthorityID: authority.ID, BandMonths: band, NotAfter: info.NotAfter.UTC()}
		if err := s.openRolloverCeremony(ctx, h, tenantID, authority, info, &draft); err != nil {
			return drafted, err
		}
		key := tenantID + "\x00" + authority.ID + "\x00" + strconv.Itoa(band) + "\x00" + draft.NotAfter.Format(time.RFC3339)
		if hasPrevious {
			key += "\x00" + strconv.FormatUint(previous.EventSequence, 10)
		}
		eventID := uuid.NewSHA1(caRolloverNamespace, []byte(key)).String()
		if err := s.orch.RecordCARolloverDraftedWithEventID(ctx, tenantID, eventID, draft); err != nil {
			return drafted, err
		}
		drafted++
	}
	return drafted, nil
}

// openRolloverCeremony opens (or finds, after an interrupted sweep) the
// authority's re-key ceremony and fills the draft with it, or records why
// none can be opened.
func (s *Server) openRolloverCeremony(ctx context.Context, h *caHierarchyService, tenantID string, authority store.CAAuthority,
	info certinfo.Info, draft *projections.CARolloverDrafted) error {
	if err := validateAuthorityRekey(authority); err != nil {
		draft.NotDraftedReason = "no re-key ceremony can be opened for this authority: " + plainCAError(err)
		return nil
	}
	// The successor keeps the authority's lifetime. Its certificate's window
	// includes the minutes it was backdated by, so whole hours are kept.
	lifetime := info.NotAfter.Sub(info.NotBefore)
	if lifetime > time.Hour {
		lifetime = lifetime.Truncate(time.Hour)
	}
	ttl := int64(lifetime / time.Second)
	threshold := h.minApprovals
	if threshold < 1 {
		threshold = 1
	}
	req := api.CACeremonyStartRequest{
		Operation: "rekey_ca", AuthorityID: authority.ID, Threshold: threshold,
		Spec: rekeyAuthoritySpec(authority, ttl),
		Reason: fmt.Sprintf("Scheduled rollover: %s entered the %d-month band of the CA calendar and expires %s.",
			authority.CommonName, draft.BandMonths, draft.NotAfter.Format("2006-01-02")),
	}
	actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: caCalendarActor})
	preview, err := h.PreviewCeremony(actorCtx, tenantID, req)
	if err != nil {
		draft.NotDraftedReason = "the re-key plan could not be prepared: " + plainCAError(err)
		return nil
	}
	purpose, _, err := h.ceremonyPurposeAndSpec(actorCtx, tenantID, req)
	if err != nil {
		return err
	}
	ceremonyID, found, err := s.store.PendingKeyCeremonyForPurpose(ctx, tenantID, purpose)
	if err != nil {
		return err
	}
	if !found {
		ceremony, err := h.StartCeremony(actorCtx, tenantID, req)
		if err != nil {
			return err
		}
		ceremonyID = ceremony.ID
	}
	draft.CeremonyID, draft.PreviewFingerprint = ceremonyID, preview.RequestFingerprint
	draft.Reason, draft.TTLSeconds = req.Reason, ttl
	return nil
}

// rolloverDraftLapsed reports whether a tighter band may draft again: only
// when the earlier draft opened no ceremony or its ceremony is no longer
// pending (cancelled), and the authority has moved into a tighter band.
func (s *Server) rolloverDraftLapsed(ctx context.Context, tenantID string, previous store.CARolloverDraft, band int) (bool, error) {
	if band >= previous.BandMonths {
		return false, nil
	}
	if previous.CeremonyID == "" {
		return true, nil
	}
	ceremony, err := s.store.GetKeyCeremony(ctx, tenantID, previous.CeremonyID)
	if err != nil {
		return false, err
	}
	return ceremony.Status != "pending", nil
}

// plainCAError is a CA hierarchy refusal without its package prefix.
func plainCAError(err error) string {
	msg := err.Error()
	for _, prefix := range []string{api.ErrCAHierarchyInvalid.Error() + ": ", api.ErrCAHierarchyConflict.Error() + ": "} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	return msg
}
