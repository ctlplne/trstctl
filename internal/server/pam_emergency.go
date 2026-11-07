// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/accessrules"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A258: reusable access templates, and audited emergency access by named
// responders. A template sets what a session request records as its reason,
// raises its review quorum (never below the deployment's) and bounds its
// length. Emergency access opens a session at once, without the quorum: only
// a named responder (a person, never a bundle run or a token minted for
// someone else) may open it, every approver is notified through the approval
// channels, it ends at a short deadline, and it carries a post-incident
// review that only someone else holding access:approve can close.

const (
	pamTemplateMaxApprovals = 10
	pamTemplateReasonMax    = 500
	// pamEmergencyMaxTTL bounds an emergency session.
	pamEmergencyMaxTTL       = time.Hour
	pamEmergencyMaxResponder = 50
	pamEmergencyNotesMax     = 2000
	// pamReauthenticateMaxSeconds bounds a high-risk template's fresh
	// sign-in window (A277).
	pamReauthenticateMaxSeconds = 3600
)

var pamTemplateName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func templateView(t store.PAMAccessTemplate) api.PAMAccessTemplate {
	return api.PAMAccessTemplate{ID: t.ID, Name: t.Name, Reason: t.Reason, RequiredApprovals: t.RequiredApprovals,
		MaxTTLSeconds: t.MaxTTLSeconds, RequireRecording: t.RequireRecording, DesktopClipboard: pamDesktopClipboard(t.DesktopClipboard), CommandRules: t.CommandRules,
		WebSignIn: t.WebSignIn, ReauthenticateWithinSeconds: t.ReauthenticateWithinSeconds, Revision: t.Revision, SavedBy: t.SavedBy, SavedAt: t.SavedAt.UTC()}
}

func emergencyView(g store.PAMEmergencyGrant) api.PAMEmergencyGrant {
	return api.PAMEmergencyGrant{SessionID: g.SessionID, Responder: g.Responder, Reason: g.Reason, TargetType: g.TargetType,
		TargetID: g.TargetID, Role: g.Role, OpenedAt: g.OpenedAt.UTC(), ExpiresAt: g.ExpiresAt.UTC(),
		Review: api.PAMEmergencyReview{Status: g.ReviewStatus, Reviewer: g.Reviewer, Outcome: g.Outcome, Notes: g.Notes, ReviewedAt: g.ReviewedAt}}
}

// SavePAMTemplate creates a template (no ID) or replaces one at the revision
// the caller read.
func (s *pamService) SavePAMTemplate(ctx context.Context, tenantID, actor string, t api.PAMAccessTemplate) (api.PAMAccessTemplate, error) {
	var saved api.PAMAccessTemplate
	err := s.store.WithPAMCatalogLock(ctx, tenantID, func() error { var err error; saved, err = s.savePAMTemplate(ctx, tenantID, actor, t); return err })
	return saved, err
}
func (s *pamService) savePAMTemplate(ctx context.Context, tenantID, actor string, t api.PAMAccessTemplate) (api.PAMAccessTemplate, error) {
	t.Name, t.Reason = strings.TrimSpace(t.Name), strings.TrimSpace(t.Reason)
	switch {
	case actor == "":
		return api.PAMAccessTemplate{}, fmt.Errorf("%w: an authenticated author is required", api.ErrPAMInvalid)
	case !pamTemplateName.MatchString(t.Name):
		return api.PAMAccessTemplate{}, fmt.Errorf("%w: name must be 1-64 lowercase letters, digits, - or _", api.ErrPAMInvalid)
	case t.Reason == "" || utf8.RuneCountInString(t.Reason) > pamTemplateReasonMax || strings.ContainsAny(t.Reason, "\r\n"):
		return api.PAMAccessTemplate{}, fmt.Errorf("%w: reason must be one line of 1-%d characters", api.ErrPAMInvalid, pamTemplateReasonMax)
	case t.RequiredApprovals < s.requiredApprovals || t.RequiredApprovals > pamTemplateMaxApprovals:
		return api.PAMAccessTemplate{}, fmt.Errorf("%w: required_approvals must be %d-%d (never below the deployment's)", api.ErrPAMInvalid,
			s.requiredApprovals, pamTemplateMaxApprovals)
	case t.DesktopClipboard != "" && t.DesktopClipboard != "deny" && t.DesktopClipboard != "to_target" && t.DesktopClipboard != "from_target" && t.DesktopClipboard != "both":
		return api.PAMAccessTemplate{}, fmt.Errorf("%w: desktop_clipboard must be deny, to_target, from_target or both", api.ErrPAMInvalid)
	case t.MaxTTLSeconds < 60 || time.Duration(t.MaxTTLSeconds)*time.Second > s.maxTTL:
		return api.PAMAccessTemplate{}, fmt.Errorf("%w: max_ttl_seconds must be 60-%d", api.ErrPAMInvalid, int(s.maxTTL/time.Second))
	case t.ReauthenticateWithinSeconds != 0 && (t.ReauthenticateWithinSeconds < 60 || t.ReauthenticateWithinSeconds > pamReauthenticateMaxSeconds):
		return api.PAMAccessTemplate{}, fmt.Errorf("%w: reauthenticate_within_seconds must be 0 (no fresh sign-in) or 60-%d", api.ErrPAMInvalid, pamReauthenticateMaxSeconds)
	}
	if t.WebSignIn != nil {
		// A273: how the gateway signs in to a web console; field and header
		// names only, never a credential.
		if err := t.WebSignIn.Validate(); err != nil {
			return api.PAMAccessTemplate{}, fmt.Errorf("%w: web_sign_in: %v", api.ErrPAMInvalid, err)
		}
	}
	rules, err := accessrules.CanonicalRules(t.CommandRules)
	if err != nil {
		return api.PAMAccessTemplate{}, fmt.Errorf("%w: %v", api.ErrPAMInvalid, err)
	}
	t.CommandRules = rules
	revision := int64(1)
	if t.ID == "" {
		t.ID = uuid.NewString()
	} else {
		current, err := s.store.GetPAMTemplate(ctx, tenantID, t.ID)
		if err != nil {
			return api.PAMAccessTemplate{}, err
		}
		if t.Revision != current.Revision {
			return api.PAMAccessTemplate{}, fmt.Errorf("%w: the template is at revision %d; read it again", orchestrator.ErrIdempotencyConflict, current.Revision)
		}
		revision = current.Revision + 1
	}
	live, err := s.store.ListPAMTemplates(ctx, tenantID)
	if err != nil {
		return api.PAMAccessTemplate{}, err
	}
	for _, other := range live {
		if other.ID != t.ID && strings.EqualFold(other.Name, t.Name) {
			return api.PAMAccessTemplate{}, fmt.Errorf("%w: a template named %s exists", api.ErrPAMTargetConflict, t.Name)
		}
	}
	if err := s.appendProject(ctx, tenantID, projections.EventPAMTemplateSaved, projections.PAMTemplateSaved{ID: t.ID, Name: t.Name,
		Reason: t.Reason, RequiredApprovals: t.RequiredApprovals, MaxTTLSeconds: t.MaxTTLSeconds, RequireRecording: t.RequireRecording, CommandRules: t.CommandRules, Revision: revision,
		DesktopClipboard: pamDesktopClipboard(t.DesktopClipboard), WebSignIn: t.WebSignIn, ReauthenticateWithinSeconds: t.ReauthenticateWithinSeconds,
		Actor: actor, At: s.clock().UTC()}); err != nil {
		return api.PAMAccessTemplate{}, err
	}
	saved, err := s.store.GetPAMTemplate(ctx, tenantID, t.ID)
	if err != nil {
		return api.PAMAccessTemplate{}, err
	}
	return templateView(saved), nil
}

func (s *pamService) ListPAMTemplates(ctx context.Context, tenantID string) ([]api.PAMAccessTemplate, error) {
	items, err := s.store.ListPAMTemplates(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]api.PAMAccessTemplate, 0, len(items))
	for _, t := range items {
		out = append(out, templateView(t))
	}
	return out, nil
}

func (s *pamService) GetPAMTemplate(ctx context.Context, tenantID, id string) (api.PAMAccessTemplate, error) {
	t, err := s.store.GetPAMTemplate(ctx, tenantID, id)
	if err != nil {
		return api.PAMAccessTemplate{}, err
	}
	return templateView(t), nil
}

func (s *pamService) DeletePAMTemplate(ctx context.Context, tenantID, id, actor string) error {
	return s.store.WithPAMCatalogLock(ctx, tenantID, func() error { return s.deletePAMTemplate(ctx, tenantID, id, actor) })
}
func (s *pamService) deletePAMTemplate(ctx context.Context, tenantID, id, actor string) error {
	if _, err := s.store.GetPAMTemplate(ctx, tenantID, id); err != nil {
		return err
	}
	return s.appendProject(ctx, tenantID, projections.EventPAMTemplateDeleted, projections.PAMTemplateDeleted{ID: id, Actor: actor, At: s.clock().UTC()})
}

// requireFreshSignIn refuses a session or credential release through a
// high-risk template (A277) unless the caller's sign-in is no older than the
// template's window. An API token, or a sign-in that cannot say when the
// person authenticated, never counts as fresh.
func (s *pamService) requireFreshSignIn(within time.Duration, signedInAt time.Time) error {
	if within <= 0 {
		return nil
	}
	now := s.clock()
	if signedInAt.IsZero() || now.Sub(signedInAt) > within || signedInAt.After(now.Add(time.Minute)) {
		return &api.PAMReauthenticationRequired{MaxAge: within}
	}
	return nil
}

func pamTemplateReauthWindow(t *store.PAMAccessTemplate) time.Duration {
	if t == nil {
		return 0
	}
	return time.Duration(t.ReauthenticateWithinSeconds) * time.Second
}

// withTemplate applies a request's template, identically at the request and
// the open so both bind the same reviewed command: the template's reason
// (with the requester's note after it), its maximum length, and the quorum it
// asks for. A template changed or deleted after the review no longer opens.
func (s *pamService) withTemplate(ctx context.Context, tenantID string, req api.PAMSessionRequest) (api.PAMSessionRequest, int, []string, error) {
	if req.TemplateResolved {
		req.Reason = req.OriginalTemplateReason
	}
	req.OriginalTemplateReason = req.Reason
	req.ResolvedCommandPolicy = nil
	req.ResolvedWebSignIn = nil
	req.ResolvedTemplateRefs = nil
	req.ResolvedReauthenticateWithin = 0
	req.TemplateResolved = false
	t, refs, recorded, err := s.pamRequestTemplate(ctx, tenantID, req.TargetType, req.TargetID, req.TemplateID)
	if err != nil {
		return req, 0, nil, err
	}
	req.ResolvedTemplateRefs = append([]string{}, refs...)
	req.TemplateResolved = true
	if req.TargetType == pamTargetWebConsole {
		// A273: the gateway signs in to a web console only as a template
		// says; the request binds that sign-in for its reviewers.
		if t == nil || t.WebSignIn == nil {
			return req, 0, nil, fmt.Errorf("%w: a webconsole session is requested through an access template that sets web_sign_in (its folder's, or template_id)", api.ErrPAMInvalid)
		}
		signIn := *t.WebSignIn
		signIn.BrowserCookies = append([]string(nil), t.WebSignIn.BrowserCookies...)
		req.ResolvedWebSignIn = &signIn
	}
	if t == nil {
		return req, s.requiredApprovals, refs, nil
	}
	req.ResolvedReauthenticateWithin = time.Duration(t.ReauthenticateWithinSeconds) * time.Second
	req.ResolvedCommandPolicy = accessrules.ForTarget(t.ID, t.Revision, t.CommandRules, req.TargetType)
	if req.ResolvedCommandPolicy != nil {
		if err := s.requireCommandRuleGateway(ctx, tenantID, req); err != nil {
			return req, 0, nil, err
		}
	}
	if t.RequireRecording && !recorded {
		return req, 0, nil, fmt.Errorf("%w: this template requires a recorded gateway session and configured recording storage", api.ErrPAMInvalid)
	}
	req.TemplateID = t.ID
	reason := t.Reason
	if note := strings.TrimSpace(req.Reason); note != "" {
		reason += ": " + note
	}
	req.Reason = reason
	maxTTL := int64(t.MaxTTLSeconds)
	if req.TTLSeconds <= 0 || req.TTLSeconds > maxTTL {
		req.TTLSeconds = min(maxTTL, int64(s.ttl(req.TTLSeconds)/time.Second))
	}
	return req, max(s.requiredApprovals, t.RequiredApprovals),
		refs, nil
}

func (s *pamService) SetPAMEmergencyResponders(ctx context.Context, tenantID, actor string, subjects []string) ([]string, error) {
	clean := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		subject = strings.TrimSpace(subject)
		if subject == "" || len(subject) > 320 || strings.ContainsAny(subject, "\r\n") || strings.HasPrefix(subject, orchestrator.BundleRunSubjectPrefix) {
			return nil, fmt.Errorf("%w: a responder is a named principal (not a bundle run), 1-320 characters", api.ErrPAMInvalid)
		}
		if !slices.Contains(clean, subject) {
			clean = append(clean, subject)
		}
	}
	if len(clean) > pamEmergencyMaxResponder {
		return nil, fmt.Errorf("%w: at most %d responders", api.ErrPAMInvalid, pamEmergencyMaxResponder)
	}
	slices.Sort(clean)
	if err := s.appendProject(ctx, tenantID, projections.EventPAMEmergencyRespondersSet, projections.PAMEmergencyRespondersSet{
		Subjects: clean, Actor: actor, At: s.clock().UTC()}); err != nil {
		return nil, err
	}
	return s.store.ListPAMEmergencyResponders(ctx, tenantID)
}

func (s *pamService) ListPAMEmergencyResponders(ctx context.Context, tenantID string) ([]string, error) {
	return s.store.ListPAMEmergencyResponders(ctx, tenantID)
}

// OpenPAMEmergencySession opens a session at once for a named responder. The
// reason is required, the session lasts at most an hour, and the grant is
// recorded with its notice to the approval channels before anything is
// granted at the target.
func (s *pamService) OpenPAMEmergencySession(ctx context.Context, tenantID, idempotencyKey, responder string, req api.PAMSessionRequest) (api.PAMSession, error) {
	if req.TemplateID != "" {
		return api.PAMSession{}, fmt.Errorf("%w: emergency access takes no template", api.ErrPAMInvalid)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return api.PAMSession{}, fmt.Errorf("%w: emergency access needs a reason", api.ErrPAMInvalid)
	}
	responders, err := s.store.ListPAMEmergencyResponders(ctx, tenantID)
	if err != nil {
		return api.PAMSession{}, err
	}
	if !slices.Contains(responders, responder) {
		return api.PAMSession{}, fmt.Errorf("%w: %s is not a named emergency responder", api.ErrPAMRejected, responder)
	}
	// Emergency authority skips the ordinary quorum, never the account's
	// required recording, lifetime policy or fresh sign-in (A277).
	req, _, _, err = s.withTemplate(ctx, tenantID, req)
	if err != nil {
		return api.PAMSession{}, err
	}
	if err := s.requireFreshSignIn(req.ResolvedReauthenticateWithin, req.SignedInAt); err != nil {
		return api.PAMSession{}, err
	}
	if err := s.validate(ctx, tenantID, idempotencyKey, responder, req); err != nil {
		return api.PAMSession{}, err
	}
	if req.TTLSeconds <= 0 || time.Duration(req.TTLSeconds)*time.Second > pamEmergencyMaxTTL {
		req.TTLSeconds = int64(min(s.ttl(req.TTLSeconds), pamEmergencyMaxTTL) / time.Second)
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-emergency\x00"+tenantID+"\x00"+idempotencyKey)).String()
	if _, err := s.store.GetPAMSession(ctx, tenantID, id); err == nil {
		return api.PAMSession{}, fmt.Errorf("%w: an emergency session already exists for this key", orchestrator.ErrIdempotencyConflict)
	} else if !store.IsNotFound(err) {
		return api.PAMSession{}, err
	}
	verifier, att, err := s.verifyAttestation(ctx, tenantID, req)
	if err != nil {
		return api.PAMSession{}, err
	}
	if err := s.validateAttestedTarget(ctx, tenantID, req, att); err != nil {
		return api.PAMSession{}, err
	}
	now := s.clock().UTC()
	expiresAt := now.Add(s.ttl(req.TTLSeconds))
	if err := s.recordEmergency(ctx, tenantID, projections.PAMEmergencyOpened{SessionID: id, Responder: responder,
		Reason: strings.TrimSpace(req.Reason), TargetType: req.TargetType, TargetID: req.TargetID, Role: req.Role,
		OpenedAt: now, ExpiresAt: expiresAt}); err != nil {
		return api.PAMSession{}, err
	}
	if err := verifier.Bind(ctx, att, "pam:"+id); err != nil {
		return api.PAMSession{}, fmt.Errorf("server: bind PAM attestation: %w", err)
	}
	var session api.PAMSession
	switch {
	case isPAMDatabaseType(req.TargetType):
		session, err = s.openDatabase(ctx, tenantID, idempotencyKey, responder, id, now, expiresAt, att, req)
	case req.TargetType == pamTargetSSH:
		session, err = s.openSSH(ctx, tenantID, idempotencyKey, responder, id, now, expiresAt, att, req)
	default:
		err = fmt.Errorf("%w: unsupported target_type %q", api.ErrPAMInvalid, req.TargetType)
	}
	if err != nil {
		return api.PAMSession{}, err
	}
	grant, err := s.store.GetPAMEmergencyGrant(ctx, tenantID, id)
	if err != nil {
		return api.PAMSession{}, err
	}
	view := emergencyView(grant)
	session.Emergency = &view
	return session, nil
}

// recordEmergency appends the grant, then projects it and queues its notice
// in one transaction; reconcileEmergencyNotices queues a notice a crash
// between the two left out.
func (s *pamService) recordEmergency(ctx context.Context, tenantID string, opened projections.PAMEmergencyOpened) error {
	data, err := json.Marshal(opened)
	if err != nil {
		return err
	}
	e, err := s.log.Append(ctx, events.Event{Type: projections.EventPAMEmergencyOpened, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	entry, err := emergencyNotice(tenantID, opened.SessionID, opened.Responder, opened.TargetType, opened.TargetID, opened.Role, opened.Reason)
	if err != nil {
		return err
	}
	return s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := s.projector.ApplyTx(ctx, tx, e); err != nil {
			return err
		}
		if s.outbox == nil {
			return nil
		}
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, entry)
		return err
	})
}

// emergencyNotice is the alert every approver gets: on the approval channels,
// critical, naming who opened what and why, never a credential.
func emergencyNotice(tenantID, sessionID, responder, targetType, targetID, role, reason string) (orchestrator.Entry, error) {
	alert, err := json.Marshal(notify.Alert{
		Kind: notify.KindEmergencyAccess, TenantID: tenantID, OperationID: "emergency-" + sessionID,
		Subject: targetType + "/" + targetID,
		Detail: fmt.Sprintf("%s opened emergency access to %s/%s as %s without approval: %s. Its post-incident review is pending.",
			responder, targetType, targetID, role, reason),
		Severity: notify.AlertSeverityCritical,
	})
	if err != nil {
		return orchestrator.Entry{}, err
	}
	return orchestrator.Entry{TenantID: tenantID, Destination: notify.DestinationApproval,
		IdempotencyKey: "emergency-access:" + sessionID, EffectLane: notify.DestinationApproval + ":emergency:" + sessionID,
		Payload: alert}, nil
}

// reconcileEmergencyNotices queues the notice of every grant of the last day
// whose notice is missing (a crash between the grant's event and its
// transaction); a queued or delivered notice is left alone.
func (s *pamService) reconcileEmergencyNotices(ctx context.Context) {
	if s.outbox == nil {
		return
	}
	grants, err := s.store.ListRecentPAMEmergencyGrants(ctx, s.clock().Add(-24*time.Hour), 100)
	if err != nil {
		return
	}
	for _, g := range grants {
		entry, err := emergencyNotice(g.TenantID, g.SessionID, g.Responder, g.TargetType, g.TargetID, g.Role, g.Reason)
		if err != nil {
			continue
		}
		_ = s.store.WithTenant(ctx, g.TenantID, func(tx pgx.Tx) error {
			_, err := s.outbox.EnqueueIfAbsent(ctx, tx, entry)
			return err
		})
	}
}

func (s *pamService) ListPAMEmergencyGrants(ctx context.Context, tenantID string) ([]api.PAMEmergencyGrant, error) {
	grants, err := s.store.ListPAMEmergencyGrants(ctx, tenantID, 200)
	if err != nil {
		return nil, err
	}
	out := make([]api.PAMEmergencyGrant, 0, len(grants))
	for _, g := range grants {
		out = append(out, emergencyView(g))
	}
	return out, nil
}

// ReviewPAMEmergencyGrant records a grant's post-incident review. Its
// responder cannot review it, and a grant is reviewed once.
func (s *pamService) ReviewPAMEmergencyGrant(ctx context.Context, tenantID, sessionID, reviewer, outcome, notes string) (api.PAMEmergencyGrant, error) {
	notes = strings.TrimSpace(notes)
	if outcome != "justified" && outcome != "unjustified" {
		return api.PAMEmergencyGrant{}, fmt.Errorf("%w: outcome is justified or unjustified", api.ErrPAMInvalid)
	}
	if notes == "" || utf8.RuneCountInString(notes) > pamEmergencyNotesMax {
		return api.PAMEmergencyGrant{}, fmt.Errorf("%w: notes of 1-%d characters are required", api.ErrPAMInvalid, pamEmergencyNotesMax)
	}
	grant, err := s.store.GetPAMEmergencyGrant(ctx, tenantID, sessionID)
	if err != nil {
		return api.PAMEmergencyGrant{}, err
	}
	switch {
	case reviewer == "" || reviewer == grant.Responder:
		return api.PAMEmergencyGrant{}, fmt.Errorf("%w: the responder cannot review their own emergency access", api.ErrPAMRejected)
	case grant.ReviewStatus != "pending":
		return api.PAMEmergencyGrant{}, fmt.Errorf("%w: the grant was already reviewed", api.ErrPAMTerminal)
	}
	if err := s.appendProject(ctx, tenantID, projections.EventPAMEmergencyReviewed, projections.PAMEmergencyReviewed{
		SessionID: sessionID, Reviewer: reviewer, Outcome: outcome, Notes: notes, At: s.clock().UTC()}); err != nil {
		return api.PAMEmergencyGrant{}, err
	}
	grant, err = s.store.GetPAMEmergencyGrant(ctx, tenantID, sessionID)
	if err != nil {
		return api.PAMEmergencyGrant{}, err
	}
	return emergencyView(grant), nil
}

// The served broker's templates and emergency access.

func (s *Server) SavePAMTemplate(ctx context.Context, tenantID, actor string, t api.PAMAccessTemplate) (api.PAMAccessTemplate, error) {
	if s.pam == nil {
		return api.PAMAccessTemplate{}, api.ErrPAMUnavailable
	}
	return s.pam.SavePAMTemplate(ctx, tenantID, actor, t)
}

func (s *Server) ListPAMTemplates(ctx context.Context, tenantID string) ([]api.PAMAccessTemplate, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMTemplates(ctx, tenantID)
}

func (s *Server) GetPAMTemplate(ctx context.Context, tenantID, id string) (api.PAMAccessTemplate, error) {
	if s.pam == nil {
		return api.PAMAccessTemplate{}, api.ErrPAMUnavailable
	}
	return s.pam.GetPAMTemplate(ctx, tenantID, id)
}

func (s *Server) DeletePAMTemplate(ctx context.Context, tenantID, id, actor string) error {
	if s.pam == nil {
		return api.ErrPAMUnavailable
	}
	return s.pam.DeletePAMTemplate(ctx, tenantID, id, actor)
}

func (s *Server) SetPAMEmergencyResponders(ctx context.Context, tenantID, actor string, subjects []string) ([]string, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.SetPAMEmergencyResponders(ctx, tenantID, actor, subjects)
}

func (s *Server) ListPAMEmergencyResponders(ctx context.Context, tenantID string) ([]string, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMEmergencyResponders(ctx, tenantID)
}

func (s *Server) OpenPAMEmergencySession(ctx context.Context, tenantID, idempotencyKey, responder string, req api.PAMSessionRequest) (api.PAMSession, error) {
	if s.pam == nil {
		return api.PAMSession{}, api.ErrPAMUnavailable
	}
	return s.pam.OpenPAMEmergencySession(ctx, tenantID, idempotencyKey, responder, req)
}

func (s *Server) ListPAMEmergencyGrants(ctx context.Context, tenantID string) ([]api.PAMEmergencyGrant, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMEmergencyGrants(ctx, tenantID)
}

func (s *Server) ReviewPAMEmergencyGrant(ctx context.Context, tenantID, sessionID, reviewer, outcome, notes string) (api.PAMEmergencyGrant, error) {
	if s.pam == nil {
		return api.PAMEmergencyGrant{}, api.ErrPAMUnavailable
	}
	return s.pam.ReviewPAMEmergencyGrant(ctx, tenantID, sessionID, reviewer, outcome, notes)
}

// pamDesktopClipboard is a template's clipboard policy, deny when unset (A269).
func pamDesktopClipboard(policy string) string {
	if policy == "" {
		return "deny"
	}
	return policy
}
