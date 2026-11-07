// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A276: periodic certification of brokered accounts, their access templates
// and the approver lists that decide privileged access, through the access
// reviews (Q1): every account (its owner, roles, template and any open
// flag), every template's approvers and quorum, the approvers of access
// without a template, and the emergency responders. A completed campaign's
// result is signed with the audit key.

const (
	// PAMCertificationScope names a campaign built from brokered accounts.
	PAMCertificationScope = "pam_accounts"
	// pamCertificationActor requests the periodic campaigns.
	pamCertificationActor = "trstctl:pam-certification"
	// CertificationResultArtifact is what a campaign result's signature
	// covers.
	CertificationResultArtifact = "access-certification-result"
	pamCertificationApproverMax = 25
)

// pamApprovers are the tenant's active members whose roles grant
// access:approve, sorted.
func (s *pamService) pamApprovers(ctx context.Context, tenantID string) ([]string, error) {
	members, err := s.store.ListTenantMembersPage(ctx, tenantID, "", false, 10000)
	if err != nil {
		return nil, err
	}
	custom, err := s.store.ListTenantCustomRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	roles := authz.BuiltinRoles()
	for _, c := range custom {
		perms := make([]authz.Permission, 0, len(c.Permissions))
		for _, p := range c.Permissions {
			perms = append(perms, authz.Permission(p))
		}
		roles[c.Name] = authz.Role{Name: c.Name, Permissions: perms}
	}
	var out []string
	for _, m := range members {
		if m.OffboardedAt != nil || m.Status == "offboarded" {
			continue
		}
		for _, name := range m.Roles {
			if role, ok := roles[name]; ok && role.Allows(authz.AccessApprove) {
				out = append(out, m.Subject)
				break
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func approverList(subjects []string) string {
	if len(subjects) == 0 {
		return "no member's role grants access:approve"
	}
	if len(subjects) > pamCertificationApproverMax {
		return strings.Join(subjects[:pamCertificationApproverMax], ", ") + " and " + strconv.Itoa(len(subjects)-pamCertificationApproverMax) + " more"
	}
	return strings.Join(subjects, ", ")
}

// PAMCertificationCampaign is a certification campaign's items: the
// tenant's brokered accounts and approver lists.
func (s *pamService) PAMCertificationCampaign(ctx context.Context, tenantID string) (orchestrator.NHIReviewCampaignStartRequest, error) {
	targets, err := s.ListPAMTargets(ctx, tenantID)
	if err != nil {
		return orchestrator.NHIReviewCampaignStartRequest{}, err
	}
	folders, err := s.store.ListPAMFolders(ctx, tenantID)
	if err != nil {
		return orchestrator.NHIReviewCampaignStartRequest{}, err
	}
	folderTemplate := map[string]string{}
	for _, f := range folders {
		folderTemplate[f.Name] = f.TemplateID
	}
	templates, err := s.store.ListPAMTemplates(ctx, tenantID)
	if err != nil {
		return orchestrator.NHIReviewCampaignStartRequest{}, err
	}
	templateByID := map[string]store.PAMAccessTemplate{}
	for _, t := range templates {
		templateByID[t.ID] = t
	}
	flags, err := s.store.ListPAMAccountFlags(ctx, tenantID, "open")
	if err != nil {
		return orchestrator.NHIReviewCampaignStartRequest{}, err
	}
	open := map[[2]string][]string{}
	for _, f := range flags {
		open[[2]string{f.TargetType, f.TargetID}] = f.Reasons
	}
	approvers, err := s.pamApprovers(ctx, tenantID)
	if err != nil {
		return orchestrator.NHIReviewCampaignStartRequest{}, err
	}
	var items []orchestrator.NHIReviewItemRequest
	for _, t := range targets {
		if !t.Enabled {
			continue
		}
		access := strings.Join(t.AllowedRoles, ", ")
		if t.TargetType == pamTargetSSH {
			access = strings.Join(t.Principals, ", ")
		}
		policy := "no template: " + strconv.Itoa(s.requiredApprovals) + " approvals"
		evidence := []string{"pam-target:" + t.TargetType + "/" + t.ID, "pam-owner:" + firstNonEmptyString(t.OwnerID, "none")}
		if id := folderTemplate[t.Folder]; id != "" {
			if tpl, ok := templateByID[id]; ok {
				policy = "template " + tpl.Name + " revision " + strconv.FormatInt(tpl.Revision, 10) + ": " + strconv.Itoa(max(tpl.RequiredApprovals, s.requiredApprovals)) + " approvals"
				evidence = append(evidence, "pam-template:"+tpl.ID+"@"+strconv.FormatInt(tpl.Revision, 10))
			}
		}
		risk := "medium"
		if reasons := open[[2]string{t.TargetType, t.ID}]; len(reasons) > 0 {
			risk = "high"
			evidence = append(evidence, "pam-flag:"+strings.Join(reasons, ","))
		}
		items = append(items, orchestrator.NHIReviewItemRequest{NHIID: "pam-account:" + t.TargetType + "/" + t.ID, NHIKind: "privileged_account",
			DisplayName: t.ID, OwnerRef: t.OwnerID, Resource: t.TargetType + "/" + t.ID,
			Entitlement: strings.TrimSpace(access + "; " + policy), Risk: risk, EvidenceRefs: evidence})
	}
	for _, tpl := range templates {
		items = append(items, orchestrator.NHIReviewItemRequest{NHIID: "pam-approvers:" + tpl.ID, NHIKind: "approver_list",
			DisplayName: "approvers of template " + tpl.Name, Resource: "template " + tpl.Name,
			Entitlement: strconv.Itoa(max(tpl.RequiredApprovals, s.requiredApprovals)) + " distinct approvals from: " + approverList(approvers),
			Risk:        "medium", EvidenceRefs: []string{"pam-template:" + tpl.ID + "@" + strconv.FormatInt(tpl.Revision, 10), "pam-approvers:" + strconv.Itoa(len(approvers))}})
	}
	items = append(items, orchestrator.NHIReviewItemRequest{NHIID: "pam-approvers:default", NHIKind: "approver_list",
		DisplayName: "approvers of access without a template", Resource: "privileged access without a template",
		Entitlement: strconv.Itoa(s.requiredApprovals) + " distinct approvals from: " + approverList(approvers), Risk: "medium",
		EvidenceRefs: []string{"pam-approvers:" + strconv.Itoa(len(approvers))}})
	responders, err := s.store.ListPAMEmergencyResponders(ctx, tenantID)
	if err != nil {
		return orchestrator.NHIReviewCampaignStartRequest{}, err
	}
	responderList := "no emergency responders"
	if len(responders) > 0 {
		responderList = "may open emergency access without review: " + approverList(responders)
	}
	items = append(items, orchestrator.NHIReviewItemRequest{NHIID: "pam-responders:emergency", NHIKind: "approver_list",
		DisplayName: "emergency responders", Resource: "emergency access", Entitlement: responderList, Risk: "high",
		EvidenceRefs: []string{"pam-responders:" + strconv.Itoa(len(responders))}})
	if len(items) > orchestrator.MaxNHIReviewCampaignItems {
		return orchestrator.NHIReviewCampaignStartRequest{}, fmt.Errorf("%w: %d accounts and approver lists exceed a campaign's %d items", api.ErrPAMInvalid,
			len(items), orchestrator.MaxNHIReviewCampaignItems)
	}
	return orchestrator.NHIReviewCampaignStartRequest{Scope: PAMCertificationScope, Items: items}, nil
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// certifyPeriodically starts a certification campaign for each tenant with
// brokered accounts whose last one began longer ago than the interval.
func (s *pamService) certifyPeriodically(ctx context.Context) {
	if s.certificationInterval <= 0 || s.orch == nil {
		return
	}
	now := s.clock()
	if !s.lastCertificationCheck.IsZero() && now.Sub(s.lastCertificationCheck) < pamFlagScanInterval {
		return
	}
	s.lastCertificationCheck = now
	tenants, err := s.store.ListTenantsWithPAMTargets(ctx, 0)
	if err != nil {
		return
	}
	for _, tenantID := range tenants {
		if ctx.Err() != nil {
			return
		}
		_, _ = s.certifyTenantIfDue(ctx, tenantID, now.UTC())
	}
}

// certifyTenantIfDue starts the tenant's next certification campaign when
// none began within the interval; it reports whether it started one.
func (s *pamService) certifyTenantIfDue(ctx context.Context, tenantID string, now time.Time) (bool, error) {
	var newest *time.Time
	for after := ""; ; {
		page, err := s.store.ListNHIReviewCampaignsPage(ctx, tenantID, after, 200)
		if err != nil {
			return false, err
		}
		for _, c := range page {
			if c.Scope == PAMCertificationScope && (newest == nil || c.CreatedAt.After(*newest)) {
				at := c.CreatedAt
				newest = &at
			}
		}
		if len(page) < 200 {
			break
		}
		after = page[len(page)-1].ID
	}
	if newest != nil && now.Sub(*newest) < s.certificationInterval {
		return false, nil
	}
	start, err := s.PAMCertificationCampaign(ctx, tenantID)
	if err != nil {
		return false, err
	}
	due := now.Add(14 * 24 * time.Hour)
	start.Name, start.DueAt, start.ReviewerSubject = "Privileged account certification "+now.Format("2006-01-02"), &due, s.certificationReviewer
	actorCtx := events.ContextWithActor(ctx, events.Actor{Subject: pamCertificationActor})
	_, err = s.orch.StartNHIReviewCampaign(actorCtx, tenantID, start)
	return err == nil, err
}

// CertificationResult is a completed campaign's canonical result and the
// audit key's signature over it.
type certificationResultItem struct {
	ItemID         string     `json:"item_id"`
	NHIID          string     `json:"nhi_id"`
	NHIKind        string     `json:"nhi_kind"`
	Resource       string     `json:"resource"`
	Entitlement    string     `json:"entitlement"`
	OwnerRef       string     `json:"owner_ref,omitempty"`
	Status         string     `json:"status"`
	DecisionBy     string     `json:"decision_by,omitempty"`
	DecisionReason string     `json:"decision_reason,omitempty"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
}

type certificationResult struct {
	CampaignID      string                    `json:"campaign_id"`
	TenantID        string                    `json:"tenant_id"`
	Name            string                    `json:"name"`
	Scope           string                    `json:"scope"`
	RequestedBy     string                    `json:"requested_by"`
	ReviewerSubject string                    `json:"reviewer_subject"`
	CreatedAt       time.Time                 `json:"created_at"`
	CompletedAt     time.Time                 `json:"completed_at"`
	Certified       int                       `json:"certified"`
	Revoked         int                       `json:"revoked"`
	Exceptions      int                       `json:"exceptions"`
	Items           []certificationResultItem `json:"items"`
}

// CertificationResult signs a completed campaign's result (A276).
func (s *pamService) CertificationResult(ctx context.Context, tenantID, campaignID string) (api.CertificationResult, error) {
	if s.auditSigner == nil {
		return api.CertificationResult{}, fmt.Errorf("%w: signed certification results need the audit signing key", api.ErrPAMUnavailable)
	}
	campaign, err := s.store.GetNHIReviewCampaign(ctx, tenantID, campaignID)
	if err != nil {
		return api.CertificationResult{}, err
	}
	if campaign.Status != "completed" || campaign.CompletedAt == nil {
		return api.CertificationResult{}, fmt.Errorf("%w: the campaign is %s; its result is signed once every item is decided", api.ErrPAMTargetConflict, campaign.Status)
	}
	result := certificationResult{CampaignID: campaign.ID, TenantID: tenantID, Name: campaign.Name, Scope: campaign.Scope,
		RequestedBy: campaign.RequestedBy, ReviewerSubject: campaign.ReviewerSubject, CreatedAt: campaign.CreatedAt.UTC(),
		CompletedAt: campaign.CompletedAt.UTC(), Certified: campaign.CertifiedCount, Revoked: campaign.RevokedCount, Exceptions: campaign.ExceptionCount}
	for _, it := range campaign.Items {
		var decided *time.Time
		if it.DecidedAt != nil {
			at := it.DecidedAt.UTC()
			decided = &at
		}
		result.Items = append(result.Items, certificationResultItem{ItemID: it.ItemID, NHIID: it.NHIID, NHIKind: it.NHIKind, Resource: it.Resource,
			Entitlement: it.Entitlement, OwnerRef: it.OwnerRef, Status: it.Status, DecisionBy: it.DecisionBy, DecisionReason: it.DecisionReason, DecidedAt: decided})
	}
	slices.SortFunc(result.Items, func(a, b certificationResultItem) int { return strings.Compare(a.ItemID, b.ItemID) })
	body, err := json.Marshal(result)
	if err != nil {
		return api.CertificationResult{}, err
	}
	signature, err := s.auditSigner.SignArtifact(CertificationResultArtifact, body)
	if err != nil {
		return api.CertificationResult{}, err
	}
	return api.CertificationResult{Artifact: CertificationResultArtifact, Result: body, Signature: signature}, nil
}

// The served broker's methods.

// GeneratePAMCertification starts a certification campaign now (A276).
func (s *Server) GeneratePAMCertification(ctx context.Context, tenantID string) (orchestrator.NHIReviewCampaignStartRequest, error) {
	if s.pam == nil {
		return orchestrator.NHIReviewCampaignStartRequest{}, api.ErrPAMUnavailable
	}
	return s.pam.PAMCertificationCampaign(ctx, tenantID)
}

// CertificationResult signs a completed campaign's result (A276).
func (s *Server) CertificationResult(ctx context.Context, tenantID, campaignID string) (api.CertificationResult, error) {
	if s.pam == nil {
		return api.CertificationResult{}, api.ErrPAMUnavailable
	}
	return s.pam.CertificationResult(ctx, tenantID, campaignID)
}
