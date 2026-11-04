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
				var m struct {
					TS   string `json:"ts"`
					User string `json:"user"`
				}
				if json.Unmarshal(raw, &m) != nil || !slackTS.MatchString(m.TS) {
					continue
				}
				if slackUserID.MatchString(m.User) {
					posters[m.User] = true
				}
				// Each message names its channel, as a per-message export line does.
				var fields map[string]json.RawMessage
				if json.Unmarshal(raw, &fields) != nil {
					continue
				}
				fields["channel_id"], _ = json.Marshal(channel)
				withChannel, err := json.Marshal(fields)
				if err != nil {
					return res, err
				}
				seconds, _ := strconv.ParseInt(strings.SplitN(m.TS, ".", 2)[0], 10, 64)
				day := time.Unix(seconds, 0).UTC().Format("2006-01-02")
				days[day] = append(days[day], withChannel)
				res.Items++
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
