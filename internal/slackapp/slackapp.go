// SPDX-License-Identifier: BUSL-1.1

// Package slackapp is trstctl's Slack app (N8): the OAuth v2 install that
// yields a bot token, the channel list an operator picks the approval channel
// from, approval messages with Approve and Deny buttons, and the request
// signature every interaction from Slack carries. The bot token and the
// signing secret are the caller's locked bytes; this package never logs or
// returns them.
package slackapp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	maxResponseBytes = 4 << 20
	// SignatureWindow is how old a signed request may be (Slack's own rule).
	SignatureWindow = 5 * time.Minute
	// BotScopes are what the app asks for at install: posting and updating its
	// messages and listing the channels the picker shows.
	BotScopes = "chat:write,channels:read,groups:read"
)

var (
	ErrRefused   = errors.New("slackapp: Slack refused the call")
	channelID    = regexp.MustCompile(`^[CGD][A-Z0-9]{2,20}$`)
	teamIDFormat = regexp.MustCompile(`^T[A-Z0-9]{2,20}$`)
)

// Doer sends one HTTP request.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client calls Slack's Web API.
type Client struct {
	BaseURL string
	Doer    Doer
}

// AuthorizeURL is where the installing operator is sent: Slack's consent
// screen for this app's bot scopes, returning to redirect with state.
func (c Client) AuthorizeURL(clientID, redirect, state string) string {
	q := url.Values{"client_id": {clientID}, "scope": {BotScopes}, "redirect_uri": {redirect}, "state": {state}}
	return strings.TrimRight(c.BaseURL, "/") + "/oauth/v2/authorize?" + q.Encode()
}

// Install is what oauth.v2.access answers for a bot install.
type Install struct {
	TeamID    string
	TeamName  string
	BotUserID string
	AppID     string
	// BotToken is the caller's to seal and wipe.
	BotToken []byte
}

// Exchange trades an authorization code for the workspace's bot token.
func (c Client) Exchange(ctx context.Context, clientID string, clientSecret []byte, code, redirect string) (Install, error) {
	form := url.Values{"code": {code}, "redirect_uri": {redirect}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/api/oauth.v2.access", strings.NewReader(form.Encode()))
	if err != nil {
		return Install{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secrettext.String(clientSecret))
	body, err := c.do(req)
	if err != nil {
		return Install{}, err
	}
	defer secret.Wipe(body)
	var answer struct {
		OK          bool             `json:"ok"`
		Error       string           `json:"error"`
		TokenType   string           `json:"token_type"`
		AccessToken secret.JSONBytes `json:"access_token"`
		BotUserID   string           `json:"bot_user_id"`
		AppID       string           `json:"app_id"`
		Team        struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"team"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return Install{}, fmt.Errorf("slackapp: oauth.v2.access: %w", err)
	}
	if !answer.OK {
		secret.Wipe(answer.AccessToken)
		return Install{}, fmt.Errorf("%w: oauth.v2.access answered %q", ErrRefused, answer.Error)
	}
	if answer.TokenType != "bot" || len(answer.AccessToken) == 0 || !teamIDFormat.MatchString(answer.Team.ID) || answer.BotUserID == "" {
		secret.Wipe(answer.AccessToken)
		return Install{}, fmt.Errorf("%w: oauth.v2.access answered no bot token for a workspace", ErrRefused)
	}
	return Install{TeamID: answer.Team.ID, TeamName: answer.Team.Name, BotUserID: answer.BotUserID, AppID: answer.AppID, BotToken: answer.AccessToken}, nil
}

// Channel is one channel the picker offers.
type Channel struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	IsPrivate bool   `json:"is_private"`
	IsMember  bool   `json:"is_member"`
}

// Channels lists the workspace's channels the bot can see, up to limit.
func (c Client) Channels(ctx context.Context, token []byte, limit int) ([]Channel, error) {
	var out []Channel
	cursor := ""
	for len(out) < limit {
		q := url.Values{"types": {"public_channel,private_channel"}, "exclude_archived": {"true"}, "limit": {"200"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var page struct {
			OK       bool      `json:"ok"`
			Error    string    `json:"error"`
			Channels []Channel `json:"channels"`
			Meta     struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if err := c.call(ctx, token, http.MethodGet, "conversations.list?"+q.Encode(), nil, &page); err != nil {
			return nil, err
		}
		if !page.OK {
			return nil, fmt.Errorf("%w: conversations.list answered %q", ErrRefused, page.Error)
		}
		for _, ch := range page.Channels {
			if channelID.MatchString(ch.ID) && len(out) < limit {
				out = append(out, ch)
			}
		}
		if page.Meta.NextCursor == "" {
			break
		}
		cursor = page.Meta.NextCursor
	}
	return out, nil
}

// Message is a posted message's place.
type Message struct {
	Channel string
	TS      string
}

// Post sends blocks (with text as the notification fallback) to a channel.
func (c Client) Post(ctx context.Context, token []byte, channel, text string, blocks []any) (Message, error) {
	if !channelID.MatchString(channel) {
		return Message{}, fmt.Errorf("%w: %q is not a channel ID", ErrRefused, channel)
	}
	var answer struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Channel string `json:"channel"`
		TS      string `json:"ts"`
	}
	if err := c.call(ctx, token, http.MethodPost, "chat.postMessage", map[string]any{"channel": channel, "text": text, "blocks": blocks}, &answer); err != nil {
		return Message{}, err
	}
	if !answer.OK || answer.TS == "" {
		return Message{}, fmt.Errorf("%w: chat.postMessage answered %q", ErrRefused, answer.Error)
	}
	return Message{Channel: answer.Channel, TS: answer.TS}, nil
}

// Update replaces a posted message's text and blocks.
func (c Client) Update(ctx context.Context, token []byte, msg Message, text string, blocks []any) error {
	var answer struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := c.call(ctx, token, http.MethodPost, "chat.update", map[string]any{"channel": msg.Channel, "ts": msg.TS, "text": text, "blocks": blocks}, &answer); err != nil {
		return err
	}
	if !answer.OK {
		return fmt.Errorf("%w: chat.update answered %q", ErrRefused, answer.Error)
	}
	return nil
}

func (c Client) call(ctx context.Context, token []byte, method, endpoint string, body any, into any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+"/api/"+endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	raw, err := c.do(req)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func (c Client) do(req *http.Request) ([]byte, error) {
	if c.Doer == nil {
		return nil, errors.New("slackapp: no HTTP client")
	}
	resp, err := c.Doer.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
		return nil, fmt.Errorf("%w: HTTP %d", ErrRefused, resp.StatusCode)
	}
	return secret.ReadBounded(resp.Body, maxResponseBytes)
}

// VerifyRequest checks a request Slack sent: X-Slack-Signature is v0= and
// the hex HMAC-SHA256, under the app's signing secret, of
// "v0:<X-Slack-Request-Timestamp>:<body>", and the timestamp is within the
// window of now.
func VerifyRequest(signingSecret []byte, header http.Header, body []byte, now time.Time) error {
	ts := header.Get("X-Slack-Request-Timestamp")
	seconds, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("slackapp: the request has no timestamp")
	}
	if age := now.Sub(time.Unix(seconds, 0)); age > SignatureWindow || age < -SignatureWindow {
		return errors.New("slackapp: the request is outside the signature window")
	}
	given, ok := strings.CutPrefix(header.Get("X-Slack-Signature"), "v0=")
	if !ok {
		return errors.New("slackapp: the request is not signed")
	}
	sum, err := hex.DecodeString(given)
	if err != nil {
		return errors.New("slackapp: the signature is not hex")
	}
	base := make([]byte, 0, len(ts)+len(body)+4)
	base = append(base, "v0:"...)
	base = append(base, ts...)
	base = append(base, ':')
	base = append(base, body...)
	if !crypto.ConstantTimeEqual(sum, crypto.HMACSHA256(signingSecret, base)) {
		return errors.New("slackapp: the signature does not verify")
	}
	return nil
}

// Sign is VerifyRequest's counterpart, for a stand-in that plays Slack.
func Sign(signingSecret []byte, ts time.Time, body []byte) http.Header {
	stamp := strconv.FormatInt(ts.Unix(), 10)
	mac := crypto.HMACSHA256(signingSecret, []byte("v0:"+stamp+":"+string(body)))
	return http.Header{"X-Slack-Request-Timestamp": {stamp}, "X-Slack-Signature": {"v0=" + hex.EncodeToString(mac)}}
}

// ValidChannelID reports whether id is shaped like a Slack channel ID.
func ValidChannelID(id string) bool { return channelID.MatchString(id) }

// ValidTeamID reports whether id is shaped like a Slack workspace ID.
func ValidTeamID(id string) bool { return teamIDFormat.MatchString(id) }
