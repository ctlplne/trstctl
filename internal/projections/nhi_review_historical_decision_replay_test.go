// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func appendNHIReviewDecisionAs(t *testing.T, log *events.Log, actor string, decision projections.NHIAccessReviewItemDecided) events.Event {
	t.Helper()
	data, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	event, err := log.Append(context.Background(), events.Event{
		Type: projections.EventNHIAccessReviewItemDecided, TenantID: tenantA,
		Actor: &eventspec.Actor{Subject: actor}, Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestNHIReviewHistoricalDuplicateKeepsFirstDecisionThroughColdReplay(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	p := projections.New(s)
	const campaignID = "df710ae8-1a10-46b9-ab20-bff712305ad2"
	const firstItemID = "9a51d168-7b37-4c73-a256-144ab6fd246b"
	const secondItemID = "78426080-ea9c-4237-8382-510432e68ca7"
	appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "nhi-history"})
	appendJSONEvent(t, log, projections.EventNHIAccessReviewCampaignStarted, tenantA, projections.NHIAccessReviewCampaignStarted{
		ID: campaignID, Name: "QA reviewer first writer", Scope: "quarterly_access",
		ReviewerSubject: "eval-custodian-2", RequestedBy: "eval-admin",
		Items: []projections.NHIAccessReviewItem{
			{ItemID: firstItemID, NHIID: "spiffe://qa.local/nhi-history/one", NHIKind: "spiffe", DisplayName: "QA one", Resource: "local", Entitlement: "read"},
			{ItemID: secondItemID, NHIID: "spiffe://qa.local/nhi-history/two", NHIKind: "spiffe", DisplayName: "QA two", Resource: "local", Entitlement: "read"},
		},
	})
	first := projections.NHIAccessReviewItemDecided{
		CampaignID: campaignID, ItemID: firstItemID, Decision: "certified", ReviewerSubject: "eval-custodian-2",
		Reason: "first accepted review", DecisionEvidenceRefs: []string{"qa:first-review"},
		DecidedAt: time.Date(2026, 10, 15, 8, 30, 0, 0, time.UTC),
	}
	appendNHIReviewDecisionAs(t, log, "eval-custodian-2", first)
	appendNHIReviewDecisionAs(t, log, "eval-custodian-2", projections.NHIAccessReviewItemDecided{
		CampaignID: campaignID, ItemID: firstItemID, Decision: "revoked", ReviewerSubject: "eval-custodian-2",
		Reason: "later duplicate must not replace first", DecisionEvidenceRefs: []string{"qa:later-review"},
		DecidedAt: first.DecidedAt.Add(time.Minute),
	})
	appendNHIReviewDecisionAs(t, log, "eval-custodian-2", projections.NHIAccessReviewItemDecided{
		CampaignID: campaignID, ItemID: secondItemID, Decision: "certified", ReviewerSubject: "eval-custodian-2",
		DecisionEvidenceRefs: []string{"qa:second-item"}, DecidedAt: first.DecidedAt.Add(2 * time.Minute),
	})
	check := func(stage string) {
		t.Helper()
		campaign, err := s.GetNHIReviewCampaign(ctx, tenantA, campaignID)
		if err != nil {
			t.Fatalf("%s read campaign: %v", stage, err)
		}
		if campaign.Status != "completed" || campaign.PendingCount != 0 || campaign.CertifiedCount != 2 || campaign.RevokedCount != 0 {
			t.Fatalf("%s campaign status=%s pending=%d certified=%d revoked=%d", stage,
				campaign.Status, campaign.PendingCount, campaign.CertifiedCount, campaign.RevokedCount)
		}
		for _, item := range campaign.Items {
			if item.ItemID == firstItemID {
				if item.Status != "certified" || item.DecisionBy != "eval-custodian-2" ||
					item.DecisionReason != first.Reason || len(item.DecisionEvidenceRefs) != 1 ||
					item.DecisionEvidenceRefs[0] != "qa:first-review" {
					t.Fatalf("%s first item changed: %+v", stage, item)
				}
				return
			}
		}
		t.Fatalf("%s first item missing: %+v", stage, campaign.Items)
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("cold catch-up refused retained NHI duplicate: %v", err)
	}
	check("catch-up")
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("full rebuild refused retained NHI duplicate: %v", err)
	}
	check("full rebuild")
	liveDuplicate := appendNHIReviewDecisionAs(t, log, "eval-custodian-2", first)
	if err := p.Apply(ctx, liveDuplicate); !errors.Is(err, store.ErrNHIReviewItemAlreadyDecided) {
		t.Fatalf("live duplicate was accepted: %v", err)
	}
	check("live refusal")
}

func TestNHIReviewHistoricalForgedActorDoesNotBecomeReviewer(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	p := projections.New(s)
	const campaignID = "7b81e160-4a4d-446d-bc32-fc7896056974"
	const itemID = "2e63e8c7-8199-43b6-9002-132219faaf8b"
	appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "nhi-forged-actor"})
	appendJSONEvent(t, log, projections.EventNHIAccessReviewCampaignStarted, tenantA, projections.NHIAccessReviewCampaignStarted{
		ID: campaignID, Name: "QA forged reviewer actor", Scope: "quarterly_access",
		ReviewerSubject: "eval-custodian-2", RequestedBy: "eval-admin",
		Items: []projections.NHIAccessReviewItem{{
			ItemID: itemID, NHIID: "spiffe://qa.local/nhi-forged-actor", NHIKind: "spiffe", DisplayName: "QA forged actor", Resource: "local", Entitlement: "read",
		}},
	})
	forged := projections.NHIAccessReviewItemDecided{
		CampaignID: campaignID, ItemID: itemID, Decision: "certified", ReviewerSubject: "eval-custodian-2",
		DecisionEvidenceRefs: []string{"qa:forged"},
	}
	appendNHIReviewDecisionAs(t, log, "eval-admin", forged)
	appendNHIReviewDecisionAs(t, log, "eval-custodian-1", projections.NHIAccessReviewItemDecided{
		CampaignID: campaignID, ItemID: itemID, Decision: "revoked", ReviewerSubject: "eval-custodian-1",
		Reason: "unassigned reviewer must not decide", DecisionEvidenceRefs: []string{"qa:unassigned"},
	})
	appendNHIReviewDecisionAs(t, log, "eval-custodian-2", projections.NHIAccessReviewItemDecided{
		CampaignID: campaignID, ItemID: itemID, Decision: "certified", ReviewerSubject: "eval-custodian-2",
		DecisionEvidenceRefs: []string{"qa:real-reviewer"},
	})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("cold catch-up refused valid reviewer after forged actor: %v", err)
	}
	read := func(stage string) {
		t.Helper()
		campaign, err := s.GetNHIReviewCampaign(ctx, tenantA, campaignID)
		if err != nil {
			t.Fatal(err)
		}
		if len(campaign.Items) != 1 || campaign.Items[0].DecisionBy != "eval-custodian-2" ||
			len(campaign.Items[0].DecisionEvidenceRefs) != 1 || campaign.Items[0].DecisionEvidenceRefs[0] != "qa:real-reviewer" {
			t.Fatalf("%s forged actor became reviewer: %+v", stage, campaign.Items)
		}
	}
	read("catch-up")
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("full rebuild refused valid reviewer after forged actor: %v", err)
	}
	read("full rebuild")
	liveForged := appendNHIReviewDecisionAs(t, log, "eval-admin", forged)
	if err := p.Apply(ctx, liveForged); !errors.Is(err, store.ErrNHIReviewReviewerUnauthorized) {
		t.Fatalf("live forged actor was accepted: %v", err)
	}
	read("live refusal")
}

func TestNHIReviewUnassignedQueueExcludesCreatorThroughColdReplay(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	p := projections.New(s)
	const campaignID = "81a0a541-adb8-4af8-830c-775c7f72b56b"
	const itemID = "41e9011c-8652-4492-a3f5-08eaf9bf7a0a"
	appendJSONEvent(t, log, projections.EventTenantRegistered, tenantA, map[string]string{"name": "nhi-review-queue"})
	appendJSONEvent(t, log, projections.EventNHIAccessReviewCampaignStarted, tenantA, projections.NHIAccessReviewCampaignStarted{
		ID: campaignID, Name: "QA distinct reviewer queue", Scope: "quarterly_access",
		ReviewerSubject: store.NHIReviewAnyDistinctReviewer, RequestedBy: "queue-creator",
		Items: []projections.NHIAccessReviewItem{{
			ItemID: itemID, NHIID: "spiffe://qa.local/review-queue", NHIKind: "workload", DisplayName: "QA review queue workload",
			Resource: "qa-local-postgres", Entitlement: "schema:qa/read",
		}},
	})
	appendNHIReviewDecisionAs(t, log, "queue-creator", projections.NHIAccessReviewItemDecided{
		CampaignID: campaignID, ItemID: itemID, Decision: "certified", ReviewerSubject: "queue-creator",
		DecisionEvidenceRefs: []string{"qa:self-review-must-not-project"},
	})
	appendNHIReviewDecisionAs(t, log, "queue-reviewer", projections.NHIAccessReviewItemDecided{
		CampaignID: campaignID, ItemID: itemID, Decision: "certified", ReviewerSubject: "queue-reviewer",
		DecisionEvidenceRefs: []string{"qa:independent-review"},
	})
	appendNHIReviewDecisionAs(t, log, "later-reviewer", projections.NHIAccessReviewItemDecided{
		CampaignID: campaignID, ItemID: itemID, Decision: "revoked", ReviewerSubject: "later-reviewer",
		Reason: "late duplicate must not replace first", DecisionEvidenceRefs: []string{"qa:late-review"},
	})
	check := func(stage string) {
		t.Helper()
		campaign, err := s.GetNHIReviewCampaign(ctx, tenantA, campaignID)
		if err != nil {
			t.Fatalf("%s read campaign: %v", stage, err)
		}
		if campaign.Status != "completed" || campaign.ReviewerSubject != store.NHIReviewAnyDistinctReviewer ||
			len(campaign.Items) != 1 || campaign.Items[0].Status != "certified" ||
			campaign.Items[0].DecisionBy != "queue-reviewer" ||
			len(campaign.Items[0].DecisionEvidenceRefs) != 1 ||
			campaign.Items[0].DecisionEvidenceRefs[0] != "qa:independent-review" {
			t.Fatalf("%s wrong queue decision: %+v", stage, campaign)
		}
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("cold catch-up: %v", err)
	}
	check("catch-up")
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("full rebuild: %v", err)
	}
	check("full rebuild")
}
