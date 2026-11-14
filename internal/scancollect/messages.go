// SPDX-License-Identifier: BUSL-1.1

package scancollect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	slackChannelID = regexp.MustCompile(`^[CGD][A-Z0-9]{2,20}$`)
	slackUserID    = regexp.MustCompile(`^[UW][A-Z0-9]{2,20}$`)
	slackTS        = regexp.MustCompile(`^[0-9]{1,12}\.[0-9]{1,9}$`)
	jiraKey        = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}-[0-9]{1,12}$`)
)

// collectSlack reads each channel's history (conversations.history, newest
// first, cursor pages, from Since) and writes it as Slack's export does: a
// folder per channel holding one JSON array of messages per UTC day, and
// channels.json naming each channel's ID.
func collectSlack(ctx context.Context, w *writer, req Request) (Result, error) {
	if len(req.Channels) == 0 {
		return Result{}, fmt.Errorf("%w: name at least one Slack channel ID", ErrRefused)
	}
	type channelEntry struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var channels []channelEntry
	res := Result{}
	posters := map[string]bool{}
	for _, channel := range req.Channels {
		if !slackChannelID.MatchString(channel) {
			return res, fmt.Errorf("%w: %q is not a Slack channel ID", ErrRefused, channel)
		}
		days := map[string][]json.RawMessage{}
		seen := map[string]bool{} // a broadcast reply is in the history and its thread
		cursor := ""
		for {
			if res.Items >= req.MaxItems {
				res.Truncated = true
				break
			}
			q := url.Values{"channel": {channel}, "limit": {"200"}}
			if !req.Since.IsZero() {
				q.Set("oldest", strconv.FormatInt(req.Since.Unix(), 10))
			}
			if cursor != "" {
				q.Set("cursor", cursor)
			}
			body, _, err := get(ctx, req, req.BaseURL+"/api/conversations.history?"+q.Encode(), authorization(req))
			if err != nil {
				return res, err
			}
			var page struct {
				OK       bool              `json:"ok"`
				Error    string            `json:"error"`
				Messages []json.RawMessage `json:"messages"`
				HasMore  bool              `json:"has_more"`
				Meta     struct {
					NextCursor string `json:"next_cursor"`
				} `json:"response_metadata"`
			}
			if err := json.Unmarshal(body, &page); err != nil {
				return res, fmt.Errorf("scancollect: Slack history for %s: %w", channel, err)
			}
			if !page.OK {
				return res, fmt.Errorf("%w: Slack answered %q for %s", ErrRefused, page.Error, channel)
			}
			for _, raw := range page.Messages {
				if res.Items >= req.MaxItems {
					res.Truncated = true
					break
				}
				m, err := addSlackMessage(raw, channel, days, posters, seen, &res)
				if err != nil {
					return res, err
				}
				// N6-L1: a thread's replies are not in the channel history; read
				// them from the thread, as Slack's export files them, by day.
				if m.ReplyCount > 0 && m.ThreadTS == m.TS && !res.Truncated {
					if err := collectSlackReplies(ctx, req, channel, m.TS, days, posters, seen, &res); err != nil {
						return res, err
					}
				}
			}
			if !page.HasMore || page.Meta.NextCursor == "" || res.Truncated {
				break
			}
			cursor = page.Meta.NextCursor
		}
		names := make([]string, 0, len(days))
		for day := range days {
			names = append(names, day)
		}
		sort.Strings(names)
		for _, day := range names {
			ok, err := w.writeJSON(channel+"/"+day+".json", days[day])
			if err != nil {
				return res, err
			}
			if !ok {
				res.Truncated = true
			}
		}
		channels = append(channels, channelEntry{ID: channel, Name: channel})
		if res.Truncated {
			break
		}
	}
	if _, err := w.writeJSON("channels.json", channels); err != nil {
		return res, err
	}
	// P14: users.json, as Slack's export holds it, so a finding can name the
	// poster's owner. A token without users:read.email gets no addresses and
	// the collection carries on without them.
	if users := slackPosters(ctx, req, posters); len(users) > 0 {
		if _, err := w.writeJSON("users.json", users); err != nil {
			return res, err
		}
	}
	return res, nil
}

// maxSlackPosters bounds the users.info calls one collection makes.
const maxSlackPosters = 200

type slackUser struct {
	ID      string `json:"id"`
	Profile struct {
		Email string `json:"email,omitempty"`
	} `json:"profile"`
}

// slackPosters reads each poster's profile (users.info), at most
// maxSlackPosters, skipping any Slack will not show.
func slackPosters(ctx context.Context, req Request, posters map[string]bool) []slackUser {
	ids := make([]string, 0, len(posters))
	for id := range posters {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > maxSlackPosters {
		ids = ids[:maxSlackPosters]
	}
	var users []slackUser
	for _, id := range ids {
		body, _, err := get(ctx, req, req.BaseURL+"/api/users.info?"+url.Values{"user": {id}}.Encode(), authorization(req))
		if err != nil {
			continue
		}
		var answer struct {
			OK   bool      `json:"ok"`
			User slackUser `json:"user"`
		}
		if json.Unmarshal(body, &answer) != nil || !answer.OK || answer.User.ID != id {
			continue
		}
		users = append(users, answer.User)
	}
	return users
}

// collectJira reads the issues JQL selects (search, startAt pages; summary,
// description and comments) and writes them as a Jira export does:
// issues.json with an issues array.
func collectJira(ctx context.Context, w *writer, req Request) (Result, error) {
	jql := strings.TrimSpace(req.JQL)
	if jql == "" {
		return Result{}, fmt.Errorf("%w: name the issues with a JQL query", ErrRefused)
	}
	if !req.Since.IsZero() {
		jql = "(" + jql + ") AND updated >= \"" + req.Since.UTC().Format("2006-01-02 15:04") + "\""
	}
	var issues []json.RawMessage
	res := Result{}
	for start := 0; ; {
		if res.Items >= req.MaxItems {
			res.Truncated = true
			break
		}
		q := url.Values{"jql": {jql}, "fields": {"summary,description,comment"}, "maxResults": {"50"}, "startAt": {strconv.Itoa(start)}}
		body, _, err := get(ctx, req, req.BaseURL+"/rest/api/2/search?"+q.Encode(), authorization(req))
		if err != nil {
			return res, err
		}
		var page struct {
			Issues []json.RawMessage `json:"issues"`
			Total  int               `json:"total"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return res, fmt.Errorf("scancollect: Jira search: %w", err)
		}
		for _, raw := range page.Issues {
			if res.Items >= req.MaxItems {
				res.Truncated = true
				break
			}
			var probe struct {
				Key string `json:"key"`
			}
			if json.Unmarshal(raw, &probe) != nil || !jiraKey.MatchString(probe.Key) {
				continue
			}
			issues = append(issues, raw)
			res.Items++
		}
		start += len(page.Issues)
		if len(page.Issues) == 0 || start >= page.Total || res.Truncated {
			break
		}
	}
	ok, err := w.writeJSON("issues.json", map[string]any{"issues": issues})
	if err != nil {
		return res, err
	}
	if !ok {
		res.Truncated = true
	}
	return res, nil
}

// slackMessage is what the collector reads of one message.
type slackMessage struct {
	TS         string `json:"ts"`
	User       string `json:"user"`
	ThreadTS   string `json:"thread_ts"`
	ReplyCount int    `json:"reply_count"`
}

// addSlackMessage files one message under its UTC day with the channel it
// was posted in, once per timestamp; a message without a valid timestamp is
// skipped.
func addSlackMessage(raw json.RawMessage, channel string, days map[string][]json.RawMessage, posters, seen map[string]bool, res *Result) (slackMessage, error) {
	var m slackMessage
	if json.Unmarshal(raw, &m) != nil || !slackTS.MatchString(m.TS) || seen[m.TS] {
		return m, nil
	}
	if slackUserID.MatchString(m.User) {
		posters[m.User] = true
	}
	// Each message names its channel, as a per-message export line does.
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return m, nil
	}
	fields["channel_id"], _ = json.Marshal(channel)
	withChannel, err := json.Marshal(fields)
	if err != nil {
		return m, err
	}
	seconds, _ := strconv.ParseInt(strings.SplitN(m.TS, ".", 2)[0], 10, 64)
	day := time.Unix(seconds, 0).UTC().Format("2006-01-02")
	days[day] = append(days[day], withChannel)
	seen[m.TS] = true
	res.Items++
	return m, nil
}

// collectSlackReplies reads one thread's replies (conversations.replies,
// cursor pages) into the channel's days, within the item limit (N6-L1).
func collectSlackReplies(ctx context.Context, req Request, channel, threadTS string, days map[string][]json.RawMessage, posters, seen map[string]bool, res *Result) error {
	cursor := ""
	for {
		q := url.Values{"channel": {channel}, "ts": {threadTS}, "limit": {"200"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		body, _, err := get(ctx, req, req.BaseURL+"/api/conversations.replies?"+q.Encode(), authorization(req))
		if err != nil {
			return err
		}
		var page struct {
			OK       bool              `json:"ok"`
			Error    string            `json:"error"`
			Messages []json.RawMessage `json:"messages"`
			HasMore  bool              `json:"has_more"`
			Meta     struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("scancollect: Slack thread %s in %s: %w", threadTS, channel, err)
		}
		if !page.OK {
			return fmt.Errorf("%w: Slack answered %q for thread %s in %s", ErrRefused, page.Error, threadTS, channel)
		}
		for _, raw := range page.Messages {
			if res.Items >= req.MaxItems {
				res.Truncated = true
				return nil
			}
			if _, err := addSlackMessage(raw, channel, days, posters, seen, res); err != nil {
				return err
			}
		}
		if !page.HasMore || page.Meta.NextCursor == "" {
			return nil
		}
		cursor = page.Meta.NextCursor
	}
}
