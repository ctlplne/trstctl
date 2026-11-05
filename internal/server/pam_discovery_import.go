// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A260 part 2: importing discovered accounts. An import names staged
// accounts, the folder they go into, an optional access template and a
// reason. It is requested for independent review through the operation
// approval engine — reviewers see the folder and every account — and applied
// by its requester with the approval's exact ID and intent digest; the
// import's event consumes the approval in the same transaction. The review
// binds the accounts as they were: one that changed or was removed since
// is refused. Importing grants nothing: no target, role binding, session or
// credential changes.

const (
	pamImportMaxAccounts = 100
	pamImportReasonMax   = 512
)

var pamImportFolder = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// importAccounts loads the accounts an import names and checks each can be
// imported: staged, not removed.
func (s *pamService) importAccounts(ctx context.Context, tenantID string, ids []string) ([]projections.PAMDiscoveryImportedAccount, error) {
	if len(ids) == 0 || len(ids) > pamImportMaxAccounts {
		return nil, fmt.Errorf("%w: an import names 1-%d accounts", api.ErrPAMInvalid, pamImportMaxAccounts)
	}
	seen := map[string]bool{}
	out := make([]projections.PAMDiscoveryImportedAccount, 0, len(ids))
	for _, id := range ids {
		if _, err := uuid.Parse(id); err != nil || seen[id] {
			return nil, fmt.Errorf("%w: account_ids must be distinct account IDs", api.ErrPAMInvalid)
		}
		seen[id] = true
		a, err := s.store.GetPAMDiscoveredAccount(ctx, tenantID, id)
		if err != nil {
			return nil, err
		}
		if a.Status != "staged" || a.RemovedRun != "" {
			return nil, fmt.Errorf("%w: account %s is %s; only staged accounts the last scan found can be imported", api.ErrPAMRejected,
				a.Account.Name, map[bool]string{true: "no longer found", false: a.Status}[a.RemovedRun != ""])
		}
		out = append(out, projections.PAMDiscoveryImportedAccount{ID: a.ID, ProviderID: a.ProviderID, Key: a.Account.Key,
			Name: a.Account.Name, Kind: a.Account.Kind, Privileges: a.Account.Privileges})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// importDigest binds an import's command: its request, folder, template,
// reason and every account as it is now.
func importDigest(requestID, folder, templateID, reason string, accounts []projections.PAMDiscoveryImportedAccount) (string, error) {
	raw, err := json.Marshal(struct {
		Domain     string                                    `json:"domain"`
		RequestID  string                                    `json:"request_id"`
		Folder     string                                    `json:"folder"`
		TemplateID string                                    `json:"template_id"`
		Reason     string                                    `json:"reason"`
		Accounts   []projections.PAMDiscoveryImportedAccount `json:"accounts"`
	}{"trstctl.pam.discovery-import.v1", requestID, folder, templateID, reason, accounts})
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(raw), nil
}

func (s *pamService) checkImport(ctx context.Context, tenantID, requester string, req api.PAMDiscoveryImportRequest) ([]projections.PAMDiscoveryImportedAccount, int, error) {
	req.Reason = strings.TrimSpace(req.Reason)
	switch {
	case requester == "":
		return nil, 0, fmt.Errorf("%w: an authenticated requester is required", api.ErrPAMInvalid)
	case !validUUID(req.RequestID):
		return nil, 0, fmt.Errorf("%w: request_id must be a UUID", api.ErrPAMInvalid)
	case !pamImportFolder.MatchString(req.Folder):
		return nil, 0, fmt.Errorf("%w: folder must be 1-64 lowercase letters, digits, - or _", api.ErrPAMInvalid)
	case req.Reason == "" || utf8.RuneCountInString(req.Reason) > pamImportReasonMax || strings.ContainsAny(req.Reason, "\r\n"):
		return nil, 0, fmt.Errorf("%w: reason must be one line of 1-%d characters", api.ErrPAMInvalid, pamImportReasonMax)
	}
	required := s.requiredApprovals
	if req.TemplateID != "" {
		template, err := s.store.GetPAMTemplate(ctx, tenantID, req.TemplateID)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: template %s is not a live access template", api.ErrPAMInvalid, req.TemplateID)
		}
		required = max(required, template.RequiredApprovals)
	}
	accounts, err := s.importAccounts(ctx, tenantID, req.AccountIDs)
	if err != nil {
		return nil, 0, err
	}
	return accounts, required, nil
}

func validUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil && s != ""
}

func (s *pamService) RequestPAMDiscoveryImport(ctx context.Context, tenantID, requester string, req api.PAMDiscoveryImportRequest) (api.PAMDiscoveryImportReview, error) {
	accounts, required, err := s.checkImport(ctx, tenantID, requester, req)
	if err != nil {
		return api.PAMDiscoveryImportReview{}, err
	}
	reason := strings.TrimSpace(req.Reason)
	digest, err := importDigest(req.RequestID, req.Folder, req.TemplateID, reason, accounts)
	if err != nil {
		return api.PAMDiscoveryImportReview{}, err
	}
	evidence := []string{"pam-import-sha256:" + digest, "pam-import-folder:" + req.Folder,
		"pam-import-accounts:" + strconv.Itoa(len(accounts))}
	if req.TemplateID != "" {
		evidence = append(evidence, "pam-import-template:"+req.TemplateID)
	}
	for _, a := range accounts {
		evidence = append(evidence, "pam-import-account:"+a.ProviderID+"/"+a.Name+" ["+strings.Join(a.Privileges, " ")+"]")
	}
	approval, err := s.orch.EnsureOperationApprovalRequest(ctx, tenantID, orchestrator.OperationApprovalIntent{
		ResourceKind: "pam_import", ResourceID: "pam-import:" + req.RequestID, ResourceName: req.Folder,
		Action: "import", Requester: requester, FromState: "staged", ToState: "imported",
		Reason: reason, EvidenceRefs: evidence, RequiredApprovals: required, TTL: s.approvalTTL,
	})
	if err != nil {
		return api.PAMDiscoveryImportReview{}, err
	}
	return api.PAMDiscoveryImportReview{RequestID: req.RequestID, ApprovalRequestID: approval.ID, IntentDigest: approval.IntentDigest,
		Status: approval.Status, ApprovalCount: approval.ApprovalCount, RequiredApprovals: approval.RequiredApprovals,
		ExpiresAt: approval.ExpiresAt, Accounts: len(accounts)}, nil
}

func (s *pamService) ApplyPAMDiscoveryImport(ctx context.Context, tenantID, requester string, req api.PAMDiscoveryImportRequest) ([]api.PAMImportedAccount, error) {
	if !validUUID(req.RequestID) || !validUUID(req.ApprovalRequestID) || req.IntentDigest == "" {
		return nil, fmt.Errorf("%w: the import's request_id and the approval's exact approval_request_id and intent_digest are required", api.ErrPAMInvalid)
	}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-discovery-import\x00"+tenantID+"\x00"+req.RequestID)).String()
	canonical, found, err := s.log.EventByID(ctx, eventID)
	if err != nil {
		return nil, err
	}
	var payload projections.PAMDiscoveryImported
	if found {
		// An applied import answers a repeated apply with what it imported,
		// once its projection is in place.
		if canonical.Type != projections.EventPAMDiscoveryImported || canonical.TenantID != tenantID || json.Unmarshal(canonical.Data, &payload) != nil ||
			payload.Actor != requester || payload.Approval.RequestID != req.ApprovalRequestID {
			return nil, fmt.Errorf("%w: the import's request_id belongs to a different import or approval", orchestrator.ErrIdempotencyConflict)
		}
		if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error { return s.projector.ApplyTx(ctx, tx, canonical) }); err != nil {
			return nil, err
		}
		return importedViews(payload), nil
	}
	accounts, _, err := s.checkImport(ctx, tenantID, requester, req)
	if err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(req.Reason)
	digest, err := importDigest(req.RequestID, req.Folder, req.TemplateID, reason, accounts)
	if err != nil {
		return nil, err
	}
	approval, err := s.store.GetOperationApproval(ctx, tenantID, req.ApprovalRequestID)
	if err != nil {
		return nil, err
	}
	if approval.ResourceKind != "pam_import" || approval.ResourceID != "pam-import:"+req.RequestID || approval.Action != "import" ||
		approval.Requester != requester || approval.IntentDigest != req.IntentDigest {
		return nil, fmt.Errorf("%w: the approval does not belong to this requester and import", api.ErrPAMRejected)
	}
	if !containsExactString(approval.EvidenceRefs, "pam-import-sha256:"+digest) {
		return nil, fmt.Errorf("%w: the import or an account in it changed since its review; request a new review", api.ErrPAMRejected)
	}
	use, err := store.OperationApprovalUseFromRequest(approval)
	if err != nil {
		return nil, err
	}
	payload = projections.PAMDiscoveryImported{RequestID: req.RequestID, Folder: req.Folder, TemplateID: req.TemplateID, Reason: reason,
		Accounts: accounts, Approval: use, Actor: requester, At: s.clock().UTC()}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	err = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := s.store.ValidateOperationApprovalUseTx(ctx, tx, tenantID, use, s.clock().UTC()); err != nil {
			return err
		}
		candidate := events.Event{ID: eventID, Type: projections.EventPAMDiscoveryImported, TenantID: tenantID,
			Time: s.clock().UTC().Truncate(time.Microsecond), Data: data}
		if actor, ok := events.ActorFromContext(ctx); ok {
			candidate.Actor = &actor
		}
		canonical, err = s.log.Append(ctx, candidate)
		if err != nil {
			return err
		}
		if canonical.Type != candidate.Type || canonical.TenantID != tenantID || !bytes.Equal(canonical.Data, data) {
			return fmt.Errorf("%w: canonical import differs", orchestrator.ErrIdempotencyConflict)
		}
		return s.projector.ApplyTx(ctx, tx, canonical)
	})
	if err != nil {
		return nil, err
	}
	return importedViews(payload), nil
}

func importedViews(payload projections.PAMDiscoveryImported) []api.PAMImportedAccount {
	out := make([]api.PAMImportedAccount, 0, len(payload.Accounts))
	for _, a := range payload.Accounts {
		out = append(out, api.PAMImportedAccount{ID: a.ID, ProviderID: a.ProviderID, Key: a.Key, Name: a.Name, Kind: a.Kind,
			Privileges: a.Privileges, Folder: payload.Folder, TemplateID: payload.TemplateID, Reason: payload.Reason, RequestID: payload.RequestID,
			ApprovalRequestID: payload.Approval.RequestID, ImportedBy: payload.Actor, ImportedAt: payload.At})
	}
	return out
}

func (s *pamService) DismissPAMDiscoveredAccount(ctx context.Context, tenantID, actor, id, reason string) (api.PAMDiscoveredAccount, error) {
	reason = strings.TrimSpace(reason)
	if actor == "" || reason == "" || utf8.RuneCountInString(reason) > pamImportReasonMax || strings.ContainsAny(reason, "\r\n") {
		return api.PAMDiscoveredAccount{}, fmt.Errorf("%w: a reason of one line of 1-%d characters is required", api.ErrPAMInvalid, pamImportReasonMax)
	}
	if !validUUID(id) {
		return api.PAMDiscoveredAccount{}, store.ErrPAMDiscoveredAccountNotFound
	}
	a, err := s.store.GetPAMDiscoveredAccount(ctx, tenantID, id)
	if err != nil {
		return api.PAMDiscoveredAccount{}, err
	}
	if a.Status != "staged" {
		return api.PAMDiscoveredAccount{}, fmt.Errorf("%w: account %s is %s; only a staged account can be dismissed", api.ErrPAMTargetConflict,
			a.Account.Name, a.Status)
	}
	if err := s.appendProject(ctx, tenantID, projections.EventPAMDiscoveryDismissed, projections.PAMDiscoveryDismissed{AccountID: a.ID,
		ProviderID: a.ProviderID, Key: a.Account.Key, Reason: reason, Actor: actor, At: s.clock().UTC()}); err != nil {
		return api.PAMDiscoveredAccount{}, err
	}
	a, err = s.store.GetPAMDiscoveredAccount(ctx, tenantID, id)
	if err != nil {
		return api.PAMDiscoveredAccount{}, err
	}
	return api.PAMDiscoveredAccount{ID: a.ID, ProviderID: a.ProviderID, PAMDiscoveredAccountInfo: accountInfo(a.Account),
		FirstSeenAt: a.FirstSeenAt, LastSeenAt: a.LastSeenAt, RemovedAt: a.RemovedAt, Status: a.Status}, nil
}

func (s *pamService) ListPAMImportedAccounts(ctx context.Context, tenantID, folder, providerID string) ([]api.PAMImportedAccount, error) {
	items, err := s.store.ListPAMImportedAccounts(ctx, tenantID, folder, providerID)
	if err != nil {
		return nil, err
	}
	out := make([]api.PAMImportedAccount, 0, len(items))
	for _, a := range items {
		privileges := a.Privileges
		if privileges == nil {
			privileges = []string{}
		}
		out = append(out, api.PAMImportedAccount{ID: a.ID, ProviderID: a.ProviderID, Key: a.Key, Name: a.Name, Kind: a.Kind,
			Privileges: privileges, Folder: a.Folder, TemplateID: a.TemplateID, Reason: a.Reason, RequestID: a.RequestID,
			ApprovalRequestID: a.ApprovalRequestID, ImportedBy: a.ImportedBy, ImportedAt: a.ImportedAt})
	}
	return out, nil
}

func (s *Server) RequestPAMDiscoveryImport(ctx context.Context, tenantID, requester string, req api.PAMDiscoveryImportRequest) (api.PAMDiscoveryImportReview, error) {
	if s.pam == nil {
		return api.PAMDiscoveryImportReview{}, api.ErrPAMUnavailable
	}
	return s.pam.RequestPAMDiscoveryImport(ctx, tenantID, requester, req)
}

func (s *Server) ApplyPAMDiscoveryImport(ctx context.Context, tenantID, requester string, req api.PAMDiscoveryImportRequest) ([]api.PAMImportedAccount, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ApplyPAMDiscoveryImport(ctx, tenantID, requester, req)
}

func (s *Server) DismissPAMDiscoveredAccount(ctx context.Context, tenantID, actor, id, reason string) (api.PAMDiscoveredAccount, error) {
	if s.pam == nil {
		return api.PAMDiscoveredAccount{}, api.ErrPAMUnavailable
	}
	return s.pam.DismissPAMDiscoveredAccount(ctx, tenantID, actor, id, reason)
}

func (s *Server) ListPAMImportedAccounts(ctx context.Context, tenantID, folder, providerID string) ([]api.PAMImportedAccount, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMImportedAccounts(ctx, tenantID, folder, providerID)
}
