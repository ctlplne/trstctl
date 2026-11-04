// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/slackapp"
	"trstctl.com/trstctl/internal/store"
)

// trstctl's Slack app (N8). An operator installs it in a workspace through
// Slack's consent screen; the bot token is sealed under the tenant's key. The
// operator picks the channel approval requests are posted to, each with
// Approve and Deny buttons. A member links their Slack user to themselves by
// typing a one-time code into Slack (/trstctl link <code>); a button pressed by
// a linked member takes the decision through the API's own approval route as
// that member — never by display name, and never for a Slack user nobody
// linked. Every request Slack sends is checked against the app's signing
// secret.

const (
	slackCodeLifetime   = 10 * time.Minute
	slackMaxBody        = 64 << 10
	slackCallbackPath   = "/integrations/slack/oauth/callback"
	slackInteractPath   = "/integrations/slack/interactions"
	slackCommandsPath   = "/integrations/slack/commands"
	slackChannelLimit   = 1000
	slackApprovalPrefix = "approval-"
)

type slackAppServer struct {
	s      *Server
	cfg    config.SlackAppConfig
	client slackapp.Client
	now    func() time.Time
}

func newSlackAppServer(s *Server, cfg config.SlackAppConfig) (*slackAppServer, error) {
	if !cfg.Enabled() {
		return nil, nil
	}
	base := cfg.APIBase
	if base == "" {
		base = "https://slack.com"
	}
	doer, err := cloudHTTPClient(base, cfg.AllowPrivateAPI, cfg.PrivateEgressCIDRs)
	if err != nil {
		return nil, fmt.Errorf("server: slack_app.api_base: %w", err)
	}
	return &slackAppServer{s: s, cfg: cfg, client: slackapp.Client{BaseURL: base, Doer: doer}, now: time.Now}, nil
}

func (a *slackAppServer) redirectURL() string { return a.cfg.PublicURL + slackCallbackPath }

func slackCodeDigest(code string) string {
	return crypto.SHA256Hex([]byte("slack-one-time-code\x00" + code))
}

func slackBotTokenAAD(tenantID, teamID string) []byte {
	return []byte("trstctl/slack-bot-token/v1\x00" + tenantID + "\x00" + teamID)
}

func (a *slackAppServer) botToken(ctx context.Context, in store.SlackInstall) ([]byte, error) {
	return openTenantValue(ctx, a.s.tenantCrypto, a.s.kek, in.TenantID, in.SealedBotToken, slackBotTokenAAD(in.TenantID, in.TeamID))
}

func (a *slackAppServer) install(ctx context.Context, tenantID string) (store.SlackInstall, error) {
	in, err := a.s.store.GetSlackInstall(ctx, tenantID)
	if store.IsNotFound(err) {
		return store.SlackInstall{}, api.ErrSlackNotInstalled
	}
	return in, err
}

func slackStatusFor(in store.SlackInstall) api.SlackAppStatus {
	at := in.InstalledAt
	return api.SlackAppStatus{Configured: true, Installed: true, TeamID: in.TeamID, TeamName: in.TeamName,
		ApprovalChannelID: in.ApprovalChannelID, ApprovalChannelName: in.ApprovalChannelName, InstalledBy: in.InstalledBy, InstalledAt: &at}
}

// SlackStatus implements api.SlackAppService.
func (a *slackAppServer) SlackStatus(ctx context.Context, tenantID string) (api.SlackAppStatus, error) {
	in, err := a.install(ctx, tenantID)
	if errors.Is(err, api.ErrSlackNotInstalled) {
		return api.SlackAppStatus{Configured: true}, nil
	}
	if err != nil {
		return api.SlackAppStatus{}, err
	}
	return slackStatusFor(in), nil
}

// SlackInstallURL implements api.SlackAppService: a single-use state names
// the tenant and the installing member for ten minutes.
func (a *slackAppServer) SlackInstallURL(ctx context.Context, tenantID, subject string) (string, time.Time, error) {
	random, err := crypto.RandomBytes(24)
	if err != nil {
		return "", time.Time{}, err
	}
	state := tenantID + "." + hex.EncodeToString(random)
	expires := a.now().UTC().Add(slackCodeLifetime)
	if err := a.s.store.IssueSlackCode(ctx, tenantID, slackCodeDigest(state), "install", subject, expires); err != nil {
		return "", time.Time{}, err
	}
	return a.client.AuthorizeURL(a.cfg.ClientID, a.redirectURL(), state), expires, nil
}

// SlackChannels implements api.SlackAppService.
func (a *slackAppServer) SlackChannels(ctx context.Context, tenantID string) ([]slackapp.Channel, error) {
	in, err := a.install(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	token, err := a.botToken(ctx, in)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(token)
	return a.client.Channels(ctx, token, slackChannelLimit)
}

// SetSlackApprovalChannel implements api.SlackAppService: only a channel the
// app can see is accepted.
func (a *slackAppServer) SetSlackApprovalChannel(ctx context.Context, tenantID, subject, channelID string) (api.SlackAppStatus, error) {
	channels, err := a.SlackChannels(ctx, tenantID)
	if err != nil {
		return api.SlackAppStatus{}, err
	}
	for _, ch := range channels {
		if ch.ID == channelID {
			if err := a.s.orch.RecordSlackEvent(ctx, tenantID, projections.EventSlackApprovalChannelSet,
				projections.SlackApprovalChannelSet{ChannelID: ch.ID, ChannelName: ch.Name, SetBy: subject}); err != nil {
				return api.SlackAppStatus{}, err
			}
			return a.SlackStatus(ctx, tenantID)
		}
	}
	return api.SlackAppStatus{}, fmt.Errorf("%w: the app cannot see channel %s; invite it to the channel first", slackapp.ErrRefused, channelID)
}

// NewSlackLinkCode implements api.SlackAppService.
func (a *slackAppServer) NewSlackLinkCode(ctx context.Context, tenantID, subject string) (string, time.Time, error) {
	if _, err := a.install(ctx, tenantID); err != nil {
		return "", time.Time{}, err
	}
	random, err := crypto.RandomBytes(10)
	if err != nil {
		return "", time.Time{}, err
	}
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random)
	expires := a.now().UTC().Add(slackCodeLifetime)
	if err := a.s.store.IssueSlackCode(ctx, tenantID, slackCodeDigest(code), "link", subject, expires); err != nil {
		return "", time.Time{}, err
	}
	return code, expires, nil
}

// UninstallSlack implements api.SlackAppService.
func (a *slackAppServer) UninstallSlack(ctx context.Context, tenantID, subject string) error {
	in, err := a.install(ctx, tenantID)
	if err != nil {
		return err
	}
	return a.s.orch.RecordSlackEvent(ctx, tenantID, projections.EventSlackUninstalled, projections.SlackUninstalled{TeamID: in.TeamID, By: subject})
}

func slackPage(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!doctype html><title>trstctl</title><p>%s</p>", html.EscapeString(message))
}

// oauthCallback serves GET /integrations/slack/oauth/callback: it spends the
// state once, exchanges the code for the bot token, seals it under the
// tenant's key and records the install.
func (a *slackAppServer) oauthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state, code := q.Get("state"), q.Get("code")
	tenantID, _, ok := strings.Cut(state, ".")
	if q.Get("error") != "" || !ok || code == "" {
		slackPage(w, http.StatusBadRequest, "The Slack install was cancelled or is incomplete.")
		return
	}
	ctx := r.Context()
	subject, err := a.s.store.UseSlackCode(ctx, tenantID, slackCodeDigest(state), "install", a.now().UTC())
	if err != nil {
		slackPage(w, http.StatusBadRequest, "This install link is unknown, expired or already used; start the install again from trstctl.")
		return
	}
	clientSecret, err := resolveDiscoveryCredentialBytesRef(ctx, a.cfg.ClientSecretRef)
	if err != nil {
		slackPage(w, http.StatusServiceUnavailable, "The Slack app's client secret is not available on this control plane.")
		return
	}
	defer secret.Wipe(clientSecret)
	install, err := a.client.Exchange(ctx, a.cfg.ClientID, clientSecret, code, a.redirectURL())
	if err != nil {
		slackPage(w, http.StatusBadGateway, "Slack did not complete the install: "+err.Error())
		return
	}
	defer secret.Wipe(install.BotToken)
	if other, err := a.s.store.TenantForSlackTeam(ctx, install.TeamID); err == nil && other != tenantID {
		slackPage(w, http.StatusConflict, "This Slack workspace is already installed for another trstctl tenant.")
		return
	}
	sealed, err := sealTenantValue(ctx, a.s.tenantCrypto, a.s.kek, tenantID, install.BotToken, slackBotTokenAAD(tenantID, install.TeamID))
	if err != nil {
		slackPage(w, http.StatusServiceUnavailable, "The bot token could not be sealed.")
		return
	}
	if err := a.s.orch.RecordSlackEvent(ctx, tenantID, projections.EventSlackInstalled, projections.SlackInstalled{
		TeamID: install.TeamID, TeamName: install.TeamName, BotUserID: install.BotUserID, AppID: install.AppID,
		SealedBotToken: sealed, InstalledBy: subject}); err != nil {
		slackPage(w, http.StatusServiceUnavailable, "The install could not be recorded.")
		return
	}
	slackPage(w, http.StatusOK, "trstctl is installed in "+install.TeamName+". Pick the approval channel in trstctl.")
}

// verified reads a request Slack sent and checks its signature.
func (a *slackAppServer) verified(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, slackMaxBody+1))
	if err != nil || len(body) > slackMaxBody {
		return nil, errors.New("slack request body is too large")
	}
	signing, err := resolveDiscoveryCredentialBytesRef(r.Context(), a.cfg.SigningSecretRef)
	if err != nil {
		return nil, errors.New("the Slack signing secret is not available")
	}
	defer secret.Wipe(signing)
	if err := slackapp.VerifyRequest(signing, r.Header, body, a.now()); err != nil {
		return nil, err
	}
	return body, nil
}

func slackEphemeral(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"response_type": "ephemeral", "text": text})
}

// commands serves POST /integrations/slack/commands: /trstctl link <code>
// links the Slack user who typed it to the member who asked for the code.
func (a *slackAppServer) commands(w http.ResponseWriter, r *http.Request) {
	body, err := a.verified(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	fields := strings.Fields(form.Get("text"))
	if form.Get("command") != "/trstctl" || len(fields) != 2 || fields[0] != "link" {
		slackEphemeral(w, "Use /trstctl link <code>, with a code from trstctl (integrations slack link-code).")
		return
	}
	ctx := r.Context()
	tenantID, err := a.s.store.TenantForSlackTeam(ctx, form.Get("team_id"))
	if err != nil {
		slackEphemeral(w, "This workspace has no trstctl install.")
		return
	}
	subject, err := a.s.store.UseSlackCode(ctx, tenantID, slackCodeDigest(strings.ToUpper(fields[1])), "link", a.now().UTC())
	if err != nil {
		slackEphemeral(w, "That code is unknown, expired or already used; get a new one from trstctl.")
		return
	}
	if err := a.s.orch.RecordSlackEvent(ctx, tenantID, projections.EventSlackUserLinked,
		projections.SlackUserLinked{SlackUserID: form.Get("user_id"), Subject: subject}); err != nil {
		slackEphemeral(w, "The link could not be recorded; try again.")
		return
	}
	slackEphemeral(w, "Your Slack user is linked to "+subject+" in trstctl.")
}

type slackInteraction struct {
	Type string `json:"type"`
	Team struct {
		ID string `json:"id"`
	} `json:"team"`
	User struct {
		ID string `json:"id"`
	} `json:"user"`
	Container struct {
		ChannelID string `json:"channel_id"`
		MessageTS string `json:"message_ts"`
	} `json:"container"`
	Actions []struct {
		ActionID string `json:"action_id"`
		Value    string `json:"value"`
		ActionTS string `json:"action_ts"`
	} `json:"actions"`
}

// interactions serves POST /integrations/slack/interactions: an Approve or
// Deny button pressed by a linked member decides the request as that member.
func (a *slackAppServer) interactions(w http.ResponseWriter, r *http.Request) {
	body, err := a.verified(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	form, err := url.ParseQuery(string(body))
	var in slackInteraction
	if err != nil || json.Unmarshal([]byte(form.Get("payload")), &in) != nil || in.Type != "block_actions" || len(in.Actions) != 1 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	action := in.Actions[0]
	approve := action.ActionID == "approve"
	requestID, digest, ok := strings.Cut(action.Value, "|")
	if (!approve && action.ActionID != "deny") || !ok || requestID == "" || digest == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	tenantID, err := a.s.store.TenantForSlackTeam(ctx, in.Team.ID)
	if err != nil {
		slackEphemeral(w, "This workspace has no trstctl install.")
		return
	}
	subject, err := a.s.store.SlackLinkedSubject(ctx, tenantID, in.User.ID)
	if err != nil {
		slackEphemeral(w, "Your Slack user is not linked to a trstctl member: get a code from trstctl (integrations slack link-code) and type /trstctl link <code>.")
		return
	}
	if a.s.api == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	status, answer := a.s.api.DecideApprovalAs(ctx, tenantID, subject, requestID, digest, approve, "denied in Slack by "+subject,
		"slack:"+in.User.ID+":"+requestID+":"+action.ActionID)
	if status/100 != 2 {
		var problem struct {
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(answer, &problem)
		slackEphemeral(w, "trstctl refused the decision: "+problem.Detail)
		return
	}
	decision := "deny"
	if approve {
		decision = "approve"
	}
	if err := a.s.orch.RecordSlackEvent(ctx, tenantID, projections.EventSlackApprovalDecided, projections.SlackApprovalDecided{
		ApprovalRequestID: requestID, Decision: decision, Subject: subject, SlackUserID: in.User.ID}); err != nil {
		slackEphemeral(w, "trstctl recorded the decision; the message could not be updated.")
		return
	}
	if inst, err := a.install(ctx, tenantID); err == nil {
		if token, err := a.botToken(ctx, inst); err == nil {
			verb := map[bool]string{true: "approved", false: "denied"}[approve]
			text := fmt.Sprintf("Approval request %s was %s by %s.", requestID, verb, subject)
			_ = a.client.Update(ctx, token, slackapp.Message{Channel: in.Container.ChannelID, TS: in.Container.MessageTS}, text,
				[]any{map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": text}}})
			secret.Wipe(token)
		}
	}
	w.WriteHeader(http.StatusOK)
}

// postApproval posts an approval request to the tenant's approval channel
// with Approve and Deny buttons, once per request. It reports false when the
// tenant has no install or no channel.
func (a *slackAppServer) postApproval(ctx context.Context, tenantID string, alert notify.Alert) (bool, error) {
	in, err := a.install(ctx, tenantID)
	if errors.Is(err, api.ErrSlackNotInstalled) || (err == nil && in.ApprovalChannelID == "") {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	requestID, ok := strings.CutPrefix(alert.OperationID, slackApprovalPrefix)
	if !ok || requestID == "" || alert.RequestBinding == "" {
		return false, nil
	}
	if _, err := a.s.store.GetSlackApprovalMessage(ctx, tenantID, requestID); err == nil {
		return true, nil
	} else if !store.IsNotFound(err) {
		return false, err
	}
	token, err := a.botToken(ctx, in)
	if err != nil {
		return false, err
	}
	defer secret.Wipe(token)
	value := requestID + "|" + alert.RequestBinding
	blocks := []any{
		map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": "*Approval requested*\n" + alert.Detail}},
		map[string]any{"type": "actions", "elements": []any{
			map[string]any{"type": "button", "action_id": "approve", "style": "primary", "value": value, "text": map[string]any{"type": "plain_text", "text": "Approve"}},
			map[string]any{"type": "button", "action_id": "deny", "style": "danger", "value": value, "text": map[string]any{"type": "plain_text", "text": "Deny"}},
		}},
	}
	msg, err := a.client.Post(ctx, token, in.ApprovalChannelID, "Approval requested: "+alert.Detail, blocks)
	if err != nil {
		return false, err
	}
	return true, a.s.orch.RecordSlackEvent(ctx, tenantID, projections.EventSlackApprovalPosted,
		projections.SlackApprovalPosted{ApprovalRequestID: requestID, ChannelID: msg.Channel, MessageTS: msg.TS})
}

func (a *slackAppServer) routes(mux *http.ServeMux, wrap func(http.Handler) http.Handler) {
	mux.Handle("GET "+slackCallbackPath, wrap(http.HandlerFunc(a.oauthCallback)))
	mux.Handle("POST "+slackInteractPath, wrap(http.HandlerFunc(a.interactions)))
	mux.Handle("POST "+slackCommandsPath, wrap(http.HandlerFunc(a.commands)))
}

// slackApprovalPoster is the outbox hook that posts approval requests, or nil.
func (s *Server) slackApprovalPoster() func(context.Context, string, notify.Alert) (bool, error) {
	if s.slack == nil {
		return nil
	}
	return s.slack.postApproval
}

// slackAPIOption serves the Slack app's API routes when it is configured.
func (s *Server) slackAPIOption() api.Option {
	if s.slack == nil {
		return api.WithSlackApp(nil)
	}
	return api.WithSlackApp(s.slack)
}
