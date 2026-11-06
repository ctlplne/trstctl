// SPDX-License-Identifier: BUSL-1.1
package graph

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// addCloudMachineAssessments verifies native executor/run provenance and typed
// fact fingerprints. A tenant-authored manual finding cannot manufacture grants.
// Only the latest captured snapshot of a principal contributes modeled edges.
func addCloudMachineAssessments(ctx context.Context, st *store.Store, tenantID string, g *Graph, findings []store.DiscoveryFinding, now time.Time) (map[string]bool, error) {
	recognized := map[string]bool{}
	type candidate struct {
		finding store.DiscoveryFinding
		value   assessment.Assessment
	}
	latest := map[string]candidate{}
	sources := map[string]store.DiscoverySource{}
	runs := map[string]store.DiscoveryRun{}
	for _, finding := range findings {
		if finding.Kind != assessment.FindingKind {
			continue
		}
		source, ok := sources[finding.SourceID]
		if !ok {
			var err error
			source, err = st.GetDiscoverySource(ctx, tenantID, finding.SourceID)
			if store.IsNotFound(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			sources[finding.SourceID] = source
		}
		if source.Kind != assessment.SourceKind {
			continue
		}
		run, ok := runs[finding.RunID]
		if !ok {
			var err error
			run, err = st.GetDiscoveryRun(ctx, tenantID, finding.RunID)
			if store.IsNotFound(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			runs[finding.RunID] = run
		}
		if run.SourceID != source.ID || run.DryRun || (run.Status != "succeeded" && run.Status != "partial") {
			continue
		}
		value, err := assessment.DecodeAssessment(finding.Metadata)
		if err != nil {
			continue
		}
		digest, err := assessment.Fingerprint(value)
		if err != nil || digest != finding.Fingerprint || finding.Ref != "aws-iam:"+value.Identity.Principal.ARN || finding.Provenance != "aws-iam:"+value.Identity.Principal.AccountID {
			continue
		}
		recognized[finding.ID] = true
		previous, found := latest[value.Identity.Principal.ARN]
		if !found || finding.DiscoveredAt.After(previous.finding.DiscoveredAt) || (finding.DiscoveredAt.Equal(previous.finding.DiscoveredAt) && finding.ID > previous.finding.ID) {
			latest[value.Identity.Principal.ARN] = candidate{finding, value}
		}
	}
	names := make([]string, 0, len(latest))
	for name := range latest {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		current := latest[name]
		value, finding := current.value, current.finding
		principal := value.Identity.Principal
		principalID := "aws-principal:" + crypto.SHA256Hex([]byte(principal.ARN))
		g.AddNode(Node{ID: principalID, Kind: KindWorkload, Name: principal.ARN, Attrs: map[string]string{"principal": principal.ARN, "principal_kind": string(principal.Kind), "account_id": principal.AccountID, "finding_id": finding.ID, "evidence": "captured IAM metadata; permissions are policy models"}})
		var active []string
		for _, key := range value.Keys {
			id := "aws-key:" + crypto.SHA256Hex([]byte(principal.ARN+":"+key.Key.ID))
			g.AddNode(Node{ID: id, Kind: KindCredential, Name: key.Key.ID, Attrs: map[string]string{"credential_kind": "api_key", "provider": "aws-iam", "status": key.Key.Status, "stale": strconv.FormatBool(key.Stale), "long_lived": strconv.FormatBool(key.LongLived), "finding_id": finding.ID, "risk_score": strconv.Itoa(value.RiskScore)}})
			g.AddEdge(Edge{From: principalID, To: id, Type: EdgeHolds, Source: "native IAM key owner; finding " + finding.ID, Confidence: "observed"})
			if key.Key.Status == "Active" {
				active = append(active, id)
			}
		}
		if principal.Kind == awspolicy.IAMRole {
			id := "aws-role-policy:" + crypto.SHA256Hex([]byte(principal.ARN))
			g.AddNode(Node{ID: id, Kind: KindCredential, Name: principal.ARN, Attrs: map[string]string{"credential_kind": "iam_role", "provider": "aws-iam", "finding_id": finding.ID, "evidence": "role policy authority; no session credential observed"}})
			g.AddEdge(Edge{From: principalID, To: id, Type: EdgeHolds, Source: "native IAM role; finding " + finding.ID, Confidence: "observed"})
			active = append(active, id)
		}
		// Freshness constrains policy models, not visibility of historical key facts.
		if finding.DiscoveredAt.Before(now.Add(-24*time.Hour)) || finding.DiscoveredAt.After(now.Add(time.Minute)) {
			continue
		}
		for index, evaluation := range value.Evaluations {
			if evaluation.Check.PrincipalARN != principal.ARN {
				continue
			}
			target := resourceID("aws:" + evaluation.Check.Resource)
			g.AddNode(Node{ID: target, Kind: KindResource, Name: evaluation.Check.Resource, Attrs: map[string]string{"resource_kind": "aws_policy_resource", "account_id": evaluation.Check.ResourceAccountID, "evidence": "permission check in a captured context; native enforcement unproven"}})
			if evaluation.Result.Decision != awspolicy.Allowed {
				continue
			}
			for _, id := range active {
				g.AddEdge(Edge{From: id, To: target, Type: EdgeGrantsAccess, Source: fmt.Sprintf("cloud machine policy model finding %s check %d action %s; %s", finding.ID, index, evaluation.Check.Action, evaluation.PolicySource), Confidence: "policy_model"})
			}
		}
	}
	return recognized, nil
}
