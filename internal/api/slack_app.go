// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/slackapp"
)

// trstctl's Slack app (N8): installing it in a workspace, picking the channel
// approval requests are posted to, linking a member's Slack user, and the
// decisions taken from its Approve and Deny buttons.

// SlackAppStatus is a tenant's install as the API shows it; never the token.
type SlackAppStatus struct {
	Configured          bool       `json:"configured"`
	Installed           bool       `json:"installed"`
	TeamID              string     `json:"team_id,omitempty"`
	TeamName            string     `json:"team_name,omitempty"`
	ApprovalChannelID   string     `json:"approval_channel_id,omitempty"`
	ApprovalChannelName string     `json:"approval_channel_name,omitempty"`
	InstalledBy         string     `json:"installed_by,omitempty"`
	InstalledAt         *time.Time `json:"installed_at,omitempty"`
}

// SlackAppService is the server side of the Slack app.
type SlackAppService interface {
	SlackStatus(ctx context.Context, tenantID string) (SlackAppStatus, error)
	SlackInstallURL(ctx context.Context, tenantID, subject string) (string, time.Time, error)
	SlackChannels(ctx context.Context, tenantID string) ([]slackapp.Channel, error)
	SetSlackApprovalChannel(ctx context.Context, tenantID, subject, channelID string) (SlackAppStatus, error)
	NewSlackLinkCode(ctx context.Context, tenantID, subject string) (string, time.Time, error)
	UninstallSlack(ctx context.Context, tenantID, subject string) error
}

// ErrSlackNotConfigured is a deployment without the Slack app configured.
var ErrSlackNotConfigured = errors.New("the Slack app is not configured: set slack_app in the server configuration")

// ErrSlackNotInstalled is a tenant that has not installed the app.
var ErrSlackNotInstalled = errors.New("this tenant has not installed the Slack app")

// WithSlackApp serves the Slack app's routes.
func WithSlackApp(service SlackAppService) Option {
	return func(c *config) { c.slackApp = service }
}

type delegatedPrincipalKey struct{}

// delegatedPrincipal is a principal the server itself vouches for on a request
// it builds (N8: a Slack user a member linked); an HTTP client cannot set it.
func delegatedPrincipal(r *http.Request) (authz.Principal, bool) {
	p, ok := r.Context().Value(delegatedPrincipalKey{}).(authz.Principal)
	return p, ok && p.Subject != "" && p.TenantID != ""
}

type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header { return b.header }
func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}
func (b *bufferedResponse) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}

// DecideApprovalAs takes an approval decision for a member outside the API
// (N8: a Slack button). The request runs through the same route, guard and
// handler as an API call, as the member with the roles their membership holds
// now: an offboarded or pending member holds none, self-approval is refused,
// and the intent digest must match.
func (a *API) DecideApprovalAs(ctx context.Context, tenantID, subject, requestID, intentDigest string, approve bool, reason, idempotencyKey string) (int, []byte) {
	principal, err := a.sessionPrincipal(ctx, auth.Session{TenantID: tenantID, Subject: subject})
	if err != nil {
		return http.StatusServiceUnavailable, []byte(`{"detail":"the member's roles could not be read"}`)
	}
	path := "/api/v1/approval-requests/" + url.PathEscape(requestID) + "/approvals"
	body := map[string]string{"intent_digest": intentDigest}
	if !approve {
		path = "/api/v1/approval-requests/" + url.PathEscape(requestID) + "/denials"
		body["reason"] = reason
	}
	raw, _ := json.Marshal(body)
	r, err := http.NewRequestWithContext(context.WithValue(ctx, delegatedPrincipalKey{}, principal), http.MethodPost, path, bytes.NewReader(raw))
	if err != nil {
		return http.StatusInternalServerError, nil
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", idempotencyKey)
	r.Header.Set("X-Tenant-ID", tenantID)
	out := &bufferedResponse{header: http.Header{}}
	a.ServeHTTP(out, r)
	return out.status, out.body.Bytes()
}

func (a *API) slackAppRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/integrations/slack", opID: "getSlackApp", summary: "Show this tenant's Slack app install: the workspace and the channel approval requests are posted to; never the token", handler: a.getSlackApp, resSchema: "SlackApp", successCode: "200", perm: authz.ConnectorsRead},
		{method: "POST", path: "/api/v1/integrations/slack/install", opID: "startSlackInstall", summary: "Start installing the Slack app: returns Slack's consent URL, valid for ten minutes and once", handler: a.startSlackInstall, resSchema: "SlackInstallStart", successCode: "200", mutation: true, perm: authz.ConnectorsWrite},
		{method: "GET", path: "/api/v1/integrations/slack/channels", opID: "listSlackChannels", summary: "List the workspace's channels the app can see, for picking the approval channel", handler: a.listSlackChannels, resSchema: "SlackChannelList", successCode: "200", perm: authz.ConnectorsRead},
		{method: "PUT", path: "/api/v1/integrations/slack/approval-channel", opID: "setSlackApprovalChannel", summary: "Pick the channel approval requests are posted to with Approve and Deny buttons", handler: a.setSlackApprovalChannel, reqSchema: "SlackApprovalChannel", resSchema: "SlackApp", successCode: "200", mutation: true, perm: authz.ConnectorsWrite},
		{method: "POST", path: "/api/v1/integrations/slack/link-codes", opID: "createSlackLinkCode", summary: "Get a one-time code that links your Slack user to you: type /trstctl link <code> in Slack within ten minutes", handler: a.createSlackLinkCode, resSchema: "SlackLinkCode", successCode: "201", mutation: true, perm: authz.ApprovalsReview},
		{method: "DELETE", path: "/api/v1/integrations/slack", opID: "uninstallSlackApp", summary: "Remove this tenant's Slack app install, its user links and its approval messages", handler: a.uninstallSlackApp, successCode: "204", mutation: true, perm: authz.ConnectorsWrite},
	}
}

func slackAppSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	ts := func() *Schema { return &Schema{Type: "string", Format: "date-time"} }
	return map[string]*Schema{
		"SlackApp": {Type: "object", Properties: map[string]*Schema{
			"configured": {Type: "boolean"}, "installed": {Type: "boolean"}, "team_id": str(), "team_name": str(),
			"approval_channel_id": str(), "approval_channel_name": str(), "installed_by": str(), "installed_at": ts(),
		}, Required: []string{"configured", "installed"}},
		"SlackInstallStart": {Type: "object", Properties: map[string]*Schema{
			"authorize_url": {Type: "string", Description: "Slack's consent screen; open it in a browser signed in to the workspace"}, "expires_at": ts(),
		}, Required: []string{"authorize_url", "expires_at"}},
		"SlackChannelList": {Type: "object", Properties: map[string]*Schema{"items": {Type: "array", Items: &Schema{Type: "object", Properties: map[string]*Schema{
			"id": str(), "name": str(), "is_private": {Type: "boolean"}, "is_member": {Type: "boolean"},
		}}}}, Required: []string{"items"}},
		"SlackApprovalChannel": {Type: "object", Properties: map[string]*Schema{"channel_id": str()}, Required: []string{"channel_id"}},
		"SlackLinkCode": {Type: "object", Properties: map[string]*Schema{
			"code": {Type: "string", Description: "type /trstctl link <code> in Slack; shown once"}, "expires_at": ts(),
		}, Required: []string{"code", "expires_at"}},
	}
}

func (a *API) slackService(w http.ResponseWriter) bool {
	if a.slackApp == nil {
		a.writeError(w, errStatusFrom(http.StatusNotFound, ErrSlackNotConfigured))
		return false
	}
	return true
}

func slackAPIError(err error) error {
	switch {
	case errors.Is(err, ErrSlackNotConfigured), errors.Is(err, ErrSlackNotInstalled):
		return errStatusFrom(http.StatusConflict, err)
	case errors.Is(err, slackapp.ErrRefused):
		return errStatusFrom(http.StatusBadGateway, err)
	}
	return err
}

func (a *API) getSlackApp(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.slackApp == nil {
		a.writeJSON(w, http.StatusOK, SlackAppStatus{})
		return
	}
	status, err := a.slackApp.SlackStatus(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, slackAPIError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, status)
}

//trstctl:mutation
func (a *API) startSlackInstall(w http.ResponseWriter, r *http.Request) {
	if !a.slackService(w) {
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		u, expires, err := a.slackApp.SlackInstallURL(ctx, tenantID, subject)
		if err != nil {
			return 0, nil, slackAPIError(err)
		}
		return http.StatusOK, map[string]any{"authorize_url": u, "expires_at": expires}, nil
	})
}

func (a *API) listSlackChannels(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if !a.slackService(w) {
		return
	}
	channels, err := a.slackApp.SlackChannels(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, slackAPIError(err))
		return
	}
	if channels == nil {
		channels = []slackapp.Channel{}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": channels})
}

//trstctl:mutation
func (a *API) setSlackApprovalChannel(w http.ResponseWriter, r *http.Request) {
	if !a.slackService(w) {
		return
	}
	var req struct {
		ChannelID string `json:"channel_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req.ChannelID = strings.TrimSpace(req.ChannelID)
	if !slackapp.ValidChannelID(req.ChannelID) {
		a.writeError(w, errStatus(http.StatusBadRequest, "channel_id must be a Slack channel ID from the channel list"))
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		status, err := a.slackApp.SetSlackApprovalChannel(ctx, tenantID, subject, req.ChannelID)
		if err != nil {
			return 0, nil, slackAPIError(err)
		}
		return http.StatusOK, status, nil
	})
}

//trstctl:mutation
func (a *API) createSlackLinkCode(w http.ResponseWriter, r *http.Request) {
	if !a.slackService(w) {
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		code, expires, err := a.slackApp.NewSlackLinkCode(ctx, tenantID, subject)
		if err != nil {
			return 0, nil, slackAPIError(err)
		}
		return http.StatusCreated, map[string]any{"code": code, "expires_at": expires}, nil
	})
}

//trstctl:mutation
func (a *API) uninstallSlackApp(w http.ResponseWriter, r *http.Request) {
	if !a.slackService(w) {
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		if err := a.slackApp.UninstallSlack(ctx, tenantID, subject); err != nil {
			return 0, nil, slackAPIError(err)
		}
		return http.StatusNoContent, nil, nil
	})
}
