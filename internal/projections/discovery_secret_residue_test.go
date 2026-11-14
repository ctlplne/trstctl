// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// P6-L5: a scan run's re-check of a moved secret's history residue replaces
// the residue the move recorded and names its run and time. A check of
// another move of the finding (another version), or one older than the last
// applied, changes nothing; moving the finding again starts over from the
// move's own residue, never re-checked.
func TestSecretResidueChecksReplaceTheMovesResidueP6L5(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)
	appendAUD96DiscoveryBase(t, log)
	const finding = "00000000-0000-4000-8000-0000000065a1"
	const run2, run3 = "00000000-0000-4000-8000-0000000065b2", "00000000-0000-4000-8000-0000000065b3"
	mustAppend(t, log, events.Event{
		Type: projections.EventDiscoveryFindingRecorded, TenantID: tenantA,
		Data: mustJSONAUD96(t, projections.DiscoveryFindingRecorded{
			ID: finding, RunID: aud96RunID, SourceID: aud96SourceID, Kind: "leaked_secret", Ref: "slack-bot-token@app.env",
			Provenance: "repository:github:acme/ledger:app.env", Fingerprint: "app.env:slack-bot-token:2", RiskScore: 95,
			Metadata: json.RawMessage(`{"rule_id":"slack-bot-token","file":"app.env","line":2}`),
		}),
	})
	loc := func(commit string) store.SecretResidueLocation {
		return store.SecretResidueLocation{RuleID: "slack-bot-token", File: "app.env", Line: 2, Commit: commit}
	}
	moved := func(version int, residue ...store.SecretResidueLocation) {
		mustAppend(t, log, events.Event{Type: projections.EventDiscoveryFindingSecretMoved, TenantID: tenantA,
			Data: mustJSONAUD96(t, projections.DiscoveryFindingSecretMoved{
				FindingID: finding, SecretName: "ledger/slack", SecretVersion: version, MovedBy: "operator", Residue: residue,
			})})
	}
	checked := func(version int, run string, at time.Time, residue ...store.SecretResidueLocation) {
		mustAppend(t, log, events.Event{Type: projections.EventDiscoveryFindingSecretResidueChecked, TenantID: tenantA,
			Data: mustJSONAUD96(t, projections.DiscoveryFindingSecretResidueChecked{
				FindingID: finding, SecretName: "ledger/slack", SecretVersion: version, RunID: run, CheckedAt: at, Residue: residue,
			})})
	}
	read := func(step string) store.DiscoveryFindingSecretMove {
		t.Helper()
		if err := p.ProjectCatchUp(ctx, log); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		moves, err := s.SecretMovesForSource(ctx, tenantA, aud96SourceID, 10)
		if err != nil || len(moves) != 1 {
			t.Fatalf("%s: moves %+v %v", step, moves, err)
		}
		return moves[0]
	}
	commits := func(m store.DiscoveryFindingSecretMove) []string {
		var out []string
		for _, r := range m.Residue {
			out = append(out, r.Commit)
		}
		return out
	}
	t1 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

	moved(1, loc("aaaaaaa1"))
	if m := read("move"); len(m.Residue) != 1 || m.ResidueCheckedAt != nil || m.ResidueRunID != "" {
		t.Fatalf("after the move: %+v", m)
	}
	checked(1, run2, t1, loc("aaaaaaa1"), loc("bbbbbbb2"))
	if m := read("check"); len(m.Residue) != 2 || m.ResidueCheckedAt == nil || !m.ResidueCheckedAt.Equal(t1) || m.ResidueRunID != run2 {
		t.Fatalf("after a check: %+v", m)
	}
	checked(2, run3, t1.Add(time.Hour))                   // another move's check
	checked(1, run3, t1.Add(-time.Hour), loc("ccccccc3")) // an older check
	if m := read("stale checks"); len(m.Residue) != 2 || m.ResidueRunID != run2 {
		t.Fatalf("a stale or foreign check applied: %+v (%v)", m, commits(m))
	}
	checked(1, run3, t1.Add(time.Hour))
	if m := read("cleared"); len(m.Residue) != 0 || m.ResidueRunID != run3 || !m.ResidueCheckedAt.Equal(t1.Add(time.Hour)) {
		t.Fatalf("after a check that found nothing: %+v", m)
	}
	moved(2, loc("ddddddd4"))
	if m := read("moved again"); m.SecretVersion != 2 || len(m.Residue) != 1 || m.Residue[0].Commit != "ddddddd4" ||
		m.ResidueCheckedAt != nil || m.ResidueRunID != "" {
		t.Fatalf("after moving again: %+v", m)
	}
}
