// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/projections"
)

// A216: a rollover draft names the opened ceremony with the plan it binds, or
// why none was opened — never both, never neither.
func TestCARolloverDraftNamesItsCeremonyOrWhyNone(t *testing.T) {
	opened := projections.CARolloverDrafted{
		AuthorityID: "0a215a21-6000-4000-8000-0000000a2160", BandMonths: 6, NotAfter: time.Now().Add(150 * 24 * time.Hour),
		CeremonyID: "0a215a21-6000-4000-8000-0000000a2161", PreviewFingerprint: strings.Repeat("ab", 32),
		Reason: "Scheduled rollover", TTLSeconds: 86400,
	}
	if err := projections.ValidateCARolloverDrafted(opened); err != nil {
		t.Fatalf("an opened ceremony was refused: %v", err)
	}
	blocked := projections.CARolloverDrafted{AuthorityID: opened.AuthorityID, BandMonths: 6, NotAfter: opened.NotAfter,
		NotDraftedReason: "offline root"}
	if err := projections.ValidateCARolloverDrafted(blocked); err != nil {
		t.Fatalf("a draft that says why no ceremony was opened was refused: %v", err)
	}
	for name, bad := range map[string]projections.CARolloverDrafted{
		"neither":      {AuthorityID: opened.AuthorityID, BandMonths: 6, NotAfter: opened.NotAfter},
		"both":         func() projections.CARolloverDrafted { d := opened; d.NotDraftedReason = "x"; return d }(),
		"no plan":      func() projections.CARolloverDrafted { d := opened; d.PreviewFingerprint = ""; return d }(),
		"no lifetime":  func() projections.CARolloverDrafted { d := opened; d.TTLSeconds = 0; return d }(),
		"no authority": func() projections.CARolloverDrafted { d := opened; d.AuthorityID = ""; return d }(),
	} {
		if err := projections.ValidateCARolloverDrafted(bad); err == nil {
			t.Fatalf("%s: an incomplete draft was accepted", name)
		}
	}
}
