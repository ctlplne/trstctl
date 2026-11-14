// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// History residue as its own finding (P6-L6). While a moved finding is open,
// the history commits that still hold its value are listed on it. Once it
// closes as remediated (rotated, the new version read, a scan no longer sees
// the leak), those commits become their own open finding on the same source,
// secret_history_residue: a lower risk, since the value no longer works, but
// still the repository's to clean. Every later re-check (P6-L5) keeps it
// current: residue found records it again (a closed one shows as regressed),
// and none found closes it as remediated with the scan run as evidence.

const (
	secretHistoryResidueKind = "secret_history_residue"
	secretHistoryResidueRisk = 35
)

var secretHistoryResidueNamespace = uuid.MustParse("9f4c2d7a-81e3-4b56-a0d9-3c6e18b7f254")

// residueSubject is the moved finding a residue finding stands for.
type residueSubject struct {
	FindingID     string
	SourceID      string
	Ref           string
	Provenance    string
	SecretName    string
	SecretVersion int
}

// reconcileSecretHistoryResidueFinding records the residue a scan run found
// for a closed moved finding as its own finding, or closes that finding when
// the run found none.
func reconcileSecretHistoryResidueFinding(ctx context.Context, orch *orchestrator.Orchestrator, st *store.Store, tenantID string,
	subject residueSubject, runID string, residue []store.SecretResidueLocation) error {
	if orch == nil || st == nil || subject.SourceID == "" || runID == "" {
		return nil
	}
	fingerprint := "history:" + subject.FindingID
	if len(residue) == 0 {
		id := discovery.FindingIdentity(tenantID, subject.SourceID, secretHistoryResidueKind, subject.Ref, fingerprint)
		f, err := st.GetDiscoveryFinding(ctx, tenantID, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if f.TriageStatus == string(discovery.TriageRemediated) || f.TriageStatus == string(discovery.TriageDismissed) {
			return nil
		}
		return orch.CloseSecretHistoryResidueFinding(ctx, tenantID, f.ID, runID)
	}
	sorted := slices.Clone(residue)
	slices.SortFunc(sorted, func(a, b store.SecretResidueLocation) int {
		return cmp.Or(cmp.Compare(a.Commit, b.Commit), cmp.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line), cmp.Compare(a.RuleID, b.RuleID))
	})
	commits := map[string]bool{}
	for _, loc := range sorted {
		commits[loc.Commit] = true
	}
	meta, err := json.Marshal(map[string]any{
		"moved_finding_id": subject.FindingID, "secret_name": subject.SecretName, "secret_version": subject.SecretVersion,
		"history_residue": sorted, "commit_count": len(commits),
	})
	if err != nil {
		return err
	}
	eventID := uuid.NewSHA1(secretHistoryResidueNamespace, []byte(tenantID+"\x00"+subject.FindingID+"\x00"+runID)).String()
	_, err = orch.RecordDiscoveryFindingWithEventID(ctx, tenantID, eventID, store.DiscoveryFinding{
		RunID: runID, SourceID: subject.SourceID, Kind: secretHistoryResidueKind, Ref: subject.Ref,
		Provenance: subject.Provenance, Fingerprint: fingerprint, RiskScore: secretHistoryResidueRisk, Metadata: meta,
	})
	return err
}
