// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base32"
	"encoding/base64"
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
	// socket is the Socket Mode client (A277): the guarded transport with no
	// overall timeout, since the connection stays open.
	socket slackapp.Client
	// mac keys a posted button's decision (A277): the deployment KEK's keyed
	// digest, so a decision survives a restart and cannot be forged.
	mac func(domain, material []byte) ([]byte, error)
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
	a := &slackAppServer{s: s, cfg: cfg, client: slackapp.Client{BaseURL: base, Doer: doer}, now: time.Now}
	if mac, ok := s.kek.(secretCommandMAC); ok {
		a.mac = mac.KeyedDigest
	}
	if cfg.SocketMode() {
		socketDoer, err := slackSocketHTTPClient(base, cfg.AllowPrivateAPI, cfg.PrivateEgressCIDRs)
		if err != nil {
			return nil, fmt.Errorf("server: slack_app socket mode: %w", err)
		}
		a.socket = slackapp.Client{BaseURL: base, Doer: socketDoer}
	}
	return a, nil
}

// slackSocketHTTPClient is cloudHTTPClient's guarded transport without an
// overall timeout: a Socket Mode connection stays open.
func slackSocketHTTPClient(endpoint string, allowPrivate bool, privateCIDRs []string) (*http.Client, error) {
	c, err := cloudHTTPClient(endpoint, allowPrivate, privateCIDRs)
	if err != nil {
		return nil, err
	}
	out := *c
	out.Timeout = 0
	return &out, nil
}

// A277: each posted button carries its decision signed by trstctl — the
// tenant, the approval request, the intent digest it binds to, the action, a
// nonce and an expiry — so a decision that comes back altered is refused, and
// each approver's use of a nonce is recorded once, so a replay is refused.
const (
	slackDecisionDomain   = "trstctl-slack-decision-v1"
	slackDecisionLifetime = 24 * time.Hour
	// slackApprovalEventType tags an approval request's message in Slack's
	// message metadata (N8-L1), and slackHistoryPages bounds how many pages
	// of 200 recent messages a post reads looking for an earlier one.
	slackApprovalEventType = "trstctl_approval_request"
	slackHistoryPages      = 5
)

type slackDecision struct {
	Tenant  string `json:"t"`
	Request string `json:"r"`
	Digest  string `json:"d"`
	Action  string `json:"a"`
	Nonce   string `json:"n"`
	Expires int64  `json:"x"`
}

var (
	errSlackDecisionAltered = errors.New("the decision was altered or was not signed by trstctl")
	errSlackDecisionExpired = errors.New("the decision's button has expired; decide in trstctl")
)

func (a *slackAppServer) signDecision(d slackDecision) (string, error) {
	if a.mac == nil {
		return "", errors.New("server: Slack decisions need the deployment key's keyed digest")
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	sum, err := a.mac([]byte(slackDecisionDomain), raw)
	if err != nil {
		return "", err
	}
	return "v1." + base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sum), nil
}

// openDecision checks a pressed button's value: trstctl's signature over
// exactly what it posted, for this action, not expired.
func (a *slackAppServer) openDecision(value, action string) (slackDecision, error) {
	parts := strings.Split(value, ".")
	if a.mac == nil || len(parts) != 3 || parts[0] != "v1" {
		return slackDecision{}, errSlackDecisionAltered
	}
	raw, err1 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err2 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil {
		return slackDecision{}, errSlackDecisionAltered
	}
	want, err := a.mac([]byte(slackDecisionDomain), raw)
	if err != nil || !crypto.ConstantTimeEqual(want, sig) {
		return slackDecision{}, errSlackDecisionAltered
	}
	var d slackDecision
	if json.Unmarshal(raw, &d) != nil || d.Action != action || d.Request == "" || d.Digest == "" || d.Nonce == "" {
		return slackDecision{}, errSlackDecisionAltered
	}
	if a.now().Unix() > d.Expires {
		return slackDecision{}, errSlackDecisionExpired
	}
	return d, nil
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
		ApprovalChannelID: in.ApprovalChannelID, ApprovalChannelName: in.ApprovalChannelName, InstalledBy: in.InstalledBy, InstalledAt: &at,
		DuplicatePostCheck: slackapp.CanFindTagged(in.Scopes)}
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
		SealedBotToken: sealed, InstalledBy: subject, Scopes: install.Scopes}); err != nil {
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
	slackEphemeral(w, a.handleCommand(r.Context(), form.Get("team_id"), form.Get("user_id"), form.Get("command"), form.Get("text")))
}

// handleCommand runs /trstctl link <code> from either transport and returns
// the reply.
func (a *slackAppServer) handleCommand(ctx context.Context, teamID, userID, command, text string) string {
	fields := strings.Fields(text)
	if command != "/trstctl" || len(fields) != 2 || fields[0] != "link" {
		return "Use /trstctl link <code>, with a code from trstctl (integrations slack link-code)."
	}
	tenantID, err := a.s.store.TenantForSlackTeam(ctx, teamID)
	if err != nil {
		return "This workspace has no trstctl install."
	}
	subject, err := a.s.store.UseSlackCode(ctx, tenantID, slackCodeDigest(strings.ToUpper(fields[1])), "link", a.now().UTC())
	if err != nil {
		return "That code is unknown, expired or already used; get a new one from trstctl."
	}
	if err := a.s.orch.RecordSlackEvent(ctx, tenantID, projections.EventSlackUserLinked,
		projections.SlackUserLinked{SlackUserID: userID, Subject: subject}); err != nil {
		return "The link could not be recorded; try again."
	}
	return "Your Slack user is linked to " + subject + " in trstctl."
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
	ResponseURL string `json:"response_url"`
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
	if a.s.api == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if reply := a.handleInteraction(r.Context(), in); reply != "" {
		slackEphemeral(w, reply)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleInteraction decides an approval from a pressed button, from either
// transport, as the linked member; it returns a reply for the presser, or
// nothing when the decision was taken and the message updated.
func (a *slackAppServer) handleInteraction(ctx context.Context, in slackInteraction) string {
	if in.Type != "block_actions" || len(in.Actions) != 1 || a.s.api == nil {
		return "trstctl could not read that action."
	}
	action := in.Actions[0]
	approve := action.ActionID == "approve"
	if !approve && action.ActionID != "deny" {
		return "trstctl could not read that action."
	}
	d, err := a.openDecision(action.Value, action.ActionID)
	if err != nil {
		return "trstctl refused the decision: " + err.Error()
	}
	tenantID, err := a.s.store.TenantForSlackTeam(ctx, in.Team.ID)
	if err != nil || tenantID != d.Tenant {
		return "This workspace has no trstctl install."
	}
	subject, err := a.s.store.SlackLinkedSubject(ctx, tenantID, in.User.ID)
	if err != nil {
		return "Your Slack user is not linked to a trstctl member: get a code from trstctl (integrations slack link-code) and type /trstctl link <code>."
	}
	// Single use: each linked member's use of this message's nonce is
	// recorded once; a second press, or a replayed delivery, is refused.
	use := crypto.SHA256Hex([]byte("slack-decision\x00" + d.Nonce + "\x00" + in.User.ID))
	if err := a.s.store.UseSlackDecision(ctx, tenantID, use, subject, time.Unix(d.Expires, 0).UTC()); err != nil {
		if errors.Is(err, store.ErrSlackDecisionUsed) {
			return "trstctl refused the decision: it was already used"
		}
		return "trstctl could not record the decision; try again."
	}
	status, answer := a.s.api.DecideApprovalAs(ctx, tenantID, subject, d.Request, d.Digest, approve, "denied in Slack by "+subject,
		"slack:"+in.User.ID+":"+d.Request+":"+action.ActionID)
	if status/100 != 2 {
		var problem struct {
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(answer, &problem)
		return "trstctl refused the decision: " + problem.Detail
	}
	decision := "deny"
	if approve {
		decision = "approve"
	}
	if err := a.s.orch.RecordSlackEvent(ctx, tenantID, projections.EventSlackApprovalDecided, projections.SlackApprovalDecided{
		ApprovalRequestID: d.Request, Decision: decision, Subject: subject, SlackUserID: in.User.ID}); err != nil {
		return "trstctl recorded the decision; the message could not be updated."
	}
	if inst, err := a.install(ctx, tenantID); err == nil {
		if token, err := a.botToken(ctx, inst); err == nil {
			verb := map[bool]string{true: "approved", false: "denied"}[approve]
			text := fmt.Sprintf("Approval request %s was %s by %s.", d.Request, verb, subject)
			_ = a.client.Update(ctx, token, slackapp.Message{Channel: in.Container.ChannelID, TS: in.Container.MessageTS}, text,
				[]any{map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": text}}})
			secret.Wipe(token)
		}
	}
	return ""
}

// slackApprovalTag is the metadata an approval request's message carries.
func slackApprovalTag(requestID string) slackapp.Tag {
	return slackapp.Tag{EventType: slackApprovalEventType, Fields: map[string]string{"approval_request": requestID}}
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
	// N8-L1: a post whose answer was lost (the connection dropped, or trstctl
	// stopped before recording it) is already in the channel, and the outbox
	// delivers this again. Find that message by its metadata and record it
	// instead of posting a second one. An install made before trstctl asked
	// for the channel's history cannot look, and posts as before.
	tag := slackApprovalTag(requestID)
	if slackapp.CanFindTagged(in.Scopes) {
		msg, found, err := a.client.FindTagged(ctx, token, in.ApprovalChannelID, in.AppID, tag, a.now().Add(-slackDecisionLifetime), slackHistoryPages)
		if err != nil {
			// A refused read must not stop the approval reaching reviewers.
			a.s.logger.Warn("slack approval post could not check the channel for an earlier post", "error_class", fmt.Sprintf("%T", err))
		} else if found {
			return true, a.s.orch.RecordSlackEvent(ctx, tenantID, projections.EventSlackApprovalPosted,
				projections.SlackApprovalPosted{ApprovalRequestID: requestID, ChannelID: msg.Channel, MessageTS: msg.TS})
		}
	}
	nonce, err := crypto.RandomBytes(16)
	if err != nil {
		return false, err
	}
	expires := a.now().Add(slackDecisionLifetime).Unix()
	values := map[string]string{}
	for _, action := range []string{"approve", "deny"} {
		values[action], err = a.signDecision(slackDecision{Tenant: tenantID, Request: requestID, Digest: alert.RequestBinding, Action: action,
			Nonce: base64.RawURLEncoding.EncodeToString(nonce), Expires: expires})
		if err != nil {
			return false, err
		}
	}
	blocks := []any{
		map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": "*Approval requested*\n" + alert.Detail}},
		map[string]any{"type": "actions", "elements": []any{
			map[string]any{"type": "button", "action_id": "approve", "style": "primary", "value": values["approve"], "text": map[string]any{"type": "plain_text", "text": "Approve"}},
			map[string]any{"type": "button", "action_id": "deny", "style": "danger", "value": values["deny"], "text": map[string]any{"type": "plain_text", "text": "Deny"}},
		}},
	}
	msg, err := a.client.PostTagged(ctx, token, in.ApprovalChannelID, "Approval requested: "+alert.Detail, blocks, tag)
	if err != nil {
		return false, err
	}
	return true, a.s.orch.RecordSlackEvent(ctx, tenantID, projections.EventSlackApprovalPosted,
		projections.SlackApprovalPosted{ApprovalRequestID: requestID, ChannelID: msg.Channel, MessageTS: msg.TS})
}

func (a *slackAppServer) routes(mux *http.ServeMux, wrap func(http.Handler) http.Handler) {
	// The install's redirect comes from the installing member's browser.
	mux.Handle("GET "+slackCallbackPath, wrap(http.HandlerFunc(a.oauthCallback)))
	if a.cfg.SocketMode() {
		// A277: Slack's deliveries arrive over trstctl's own connection; no
		// inbound endpoint for them is served.
		return
	}
	mux.Handle("POST "+slackInteractPath, wrap(http.HandlerFunc(a.interactions)))
	mux.Handle("POST "+slackCommandsPath, wrap(http.HandlerFunc(a.commands)))
}

// runSocketMode keeps a Socket Mode connection open (A277): it asks Slack for
// a connection with the app-level token, answers each delivery — a slash
// command's reply in its acknowledgement, a button press's reply through its
// response_url — and reconnects with backoff when the connection ends.
func (a *slackAppServer) runSocketMode(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := a.socketSession(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			a.s.logger.Warn("slack socket mode connection ended", "error_class", fmt.Sprintf("%T", err))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if err != nil && backoff < 30*time.Second {
			backoff *= 2
		} else if err == nil {
			backoff = time.Second
		}
	}
}

func (a *slackAppServer) socketSession(ctx context.Context) error {
	token, err := resolveDiscoveryCredentialBytesRef(ctx, a.cfg.AppTokenRef)
	if err != nil {
		return err
	}
	wsURL, err := a.socket.OpenSocket(ctx, token)
	secret.Wipe(token)
	if err != nil {
		return err
	}
	conn, err := a.socket.DialSocket(ctx, wsURL)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer func() { _ = conn.Close() }()
	for {
		env, err := conn.Next()
		if err != nil {
			return err
		}
		switch env.Type {
		case "hello":
		case "disconnect":
			return nil
		case "slash_commands":
			var cmd struct {
				TeamID  string `json:"team_id"`
				UserID  string `json:"user_id"`
				Command string `json:"command"`
				Text    string `json:"text"`
			}
			reply := "trstctl could not read that command."
			if json.Unmarshal(env.Payload, &cmd) == nil {
				reply = a.handleCommand(ctx, cmd.TeamID, cmd.UserID, cmd.Command, cmd.Text)
			}
			if err := conn.Ack(env.EnvelopeID, map[string]string{"response_type": "ephemeral", "text": reply}); err != nil {
				return err
			}
		case "interactive":
			if err := conn.Ack(env.EnvelopeID, nil); err != nil {
				return err
			}
			var in slackInteraction
			if json.Unmarshal(env.Payload, &in) != nil {
				continue
			}
			if reply := a.handleInteraction(ctx, in); reply != "" && in.ResponseURL != "" {
				_ = a.socket.PostResponse(ctx, in.ResponseURL, reply)
			}
		default:
			if env.EnvelopeID != "" {
				if err := conn.Ack(env.EnvelopeID, nil); err != nil {
					return err
				}
			}
		}
	}
}

// RunSlackSocketMode keeps the Slack app's Socket Mode connection open when
// it is configured (A277).
func (s *Server) RunSlackSocketMode(ctx context.Context) {
	if s.slack == nil || !s.slack.cfg.SocketMode() {
		<-ctx.Done()
		return
	}
	s.slack.runSocketMode(ctx)
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
