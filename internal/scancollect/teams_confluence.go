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
	teamsGUID      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	teamsChannelID = regexp.MustCompile(`^19:[A-Za-z0-9_-]{1,200}@thread\.(?:tacv2|skype)$`)
	teamsMessageID = regexp.MustCompile(`^[0-9]{1,20}$`)
	confluenceID   = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// maxPages bounds the pages one listing follows, beside MaxItems, so a
// provider that keeps answering with a next page cannot keep a worker busy.
const maxPages = 1000

// collectTeams reads each channel's messages and their replies from
// Microsoft Graph (GET /v1.0/teams/{team}/channels/{channel}/messages with
// replies expanded, @odata.nextLink pages on the same origin only) and writes
// them in the export layout: a folder per channel holding messages.json, one
// chatMessage per element (replies beside the message they answer, each
// naming its team and channel), channels.json naming each folder's team and
// channel, and users.json with the posters' addresses when Graph shows them.
// A deleted message has no content and is skipped; Since keeps the messages
// changed since then.
func collectTeams(ctx context.Context, w *writer, req Request) (Result, error) {
	if !teamsGUID.MatchString(req.Team) {
		return Result{}, fmt.Errorf("%w: %q is not a Teams team ID", ErrRefused, req.Team)
	}
	if len(req.Channels) == 0 {
		return Result{}, fmt.Errorf("%w: name at least one Teams channel ID", ErrRefused)
	}
	type channelEntry struct {
		TeamID    string `json:"team_id"`
		ChannelID string `json:"channel_id"`
		Dir       string `json:"dir"`
	}
	var channels []channelEntry
	res := Result{}
	posters := map[string]bool{}
	for i, channel := range req.Channels {
		if !teamsChannelID.MatchString(channel) {
			return res, fmt.Errorf("%w: %q is not a Teams channel ID", ErrRefused, channel)
		}
		var messages []json.RawMessage
		keep := func(raw json.RawMessage) error {
			if res.Items >= req.MaxItems {
				res.Truncated = true
				return nil
			}
			message, poster, ok, err := teamsMessage(raw, req.Team, channel, req.Since)
			if err != nil || !ok {
				return err
			}
			if poster != "" {
				posters[poster] = true
			}
			messages = append(messages, message)
			res.Items++
			return nil
		}
		next := req.BaseURL + "/v1.0/teams/" + url.PathEscape(req.Team) + "/channels/" + url.PathEscape(channel) + "/messages?$top=50&$expand=replies"
		for pages := 0; next != "" && !res.Truncated; pages++ {
			if pages == maxPages {
				res.Truncated = true
				break
			}
			body, _, err := get(ctx, req, next, authorization(req))
			if err != nil {
				return res, err
			}
			var page struct {
				Value    []json.RawMessage `json:"value"`
				NextLink string            `json:"@odata.nextLink"`
			}
			if err := json.Unmarshal(body, &page); err != nil {
				return res, fmt.Errorf("scancollect: Teams messages for %s: %w", channel, err)
			}
			for _, raw := range page.Value {
				if err := keep(raw); err != nil {
					return res, err
				}
				var thread struct {
					Replies  []json.RawMessage `json:"replies"`
					NextLink string            `json:"replies@odata.nextLink"`
				}
				if json.Unmarshal(raw, &thread) != nil {
					continue
				}
				for _, reply := range thread.Replies {
					if err := keep(reply); err != nil {
						return res, err
					}
				}
				// Replies past those Graph expanded inline.
				for more, morePages := thread.NextLink, 0; more != "" && !res.Truncated; morePages++ {
					if morePages == maxPages {
						res.Truncated = true
						break
					}
					if !sameOrigin(req.BaseURL, more) {
						return res, fmt.Errorf("%w: Microsoft Graph's next page of replies leaves %s", ErrRefused, redactQuery(req.BaseURL))
					}
					body, _, err := get(ctx, req, more, authorization(req))
					if err != nil {
						return res, err
					}
					var replies struct {
						Value    []json.RawMessage `json:"value"`
						NextLink string            `json:"@odata.nextLink"`
					}
					if err := json.Unmarshal(body, &replies); err != nil {
						return res, fmt.Errorf("scancollect: Teams replies for %s: %w", channel, err)
					}
					for _, reply := range replies.Value {
						if err := keep(reply); err != nil {
							return res, err
						}
					}
					more = replies.NextLink
				}
			}
			next = page.NextLink
			if next != "" && !sameOrigin(req.BaseURL, next) {
				return res, fmt.Errorf("%w: Microsoft Graph's next page leaves %s", ErrRefused, redactQuery(req.BaseURL))
			}
		}
		dir := "channel-" + strconv.Itoa(i+1)
		ok, err := w.writeJSON(dir+"/messages.json", messages)
		if err != nil {
			return res, err
		}
		if !ok {
			res.Truncated = true
		}
		channels = append(channels, channelEntry{TeamID: req.Team, ChannelID: channel, Dir: dir})
		if res.Truncated {
			break
		}
	}
	if _, err := w.writeJSON("channels.json", channels); err != nil {
		return res, err
	}
	// P14: the posters' addresses, so a finding can name its owner. A token
	// without User.Read.All gets none and the collection carries on.
	if users := teamsPosters(ctx, req, posters); len(users) > 0 {
		if _, err := w.writeJSON("users.json", users); err != nil {
			return res, err
		}
	}
	return res, nil
}

// teamsMessage readies one Graph chatMessage for the export: its replies
// removed (they are written beside it) and its team and channel named; it
// reports false for a message without an ID, a deleted one, or one older
// than since, and returns its poster's user ID.
func teamsMessage(raw json.RawMessage, team, channel string, since time.Time) (json.RawMessage, string, bool, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, "", false, nil
	}
	var m struct {
		ID                   string  `json:"id"`
		DeletedDateTime      *string `json:"deletedDateTime"`
		CreatedDateTime      string  `json:"createdDateTime"`
		LastModifiedDateTime string  `json:"lastModifiedDateTime"`
		From                 struct {
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"from"`
	}
	if json.Unmarshal(raw, &m) != nil || !teamsMessageID.MatchString(m.ID) || m.DeletedDateTime != nil {
		return nil, "", false, nil
	}
	if !since.IsZero() {
		changed := m.LastModifiedDateTime
		if changed == "" {
			changed = m.CreatedDateTime
		}
		if at, err := time.Parse(time.RFC3339, changed); err == nil && at.Before(since) {
			return nil, "", false, nil
		}
	}
	delete(fields, "replies")
	delete(fields, "replies@odata.context")
	delete(fields, "replies@odata.nextLink")
	identity, err := json.Marshal(map[string]string{"teamId": team, "channelId": channel})
	if err != nil {
		return nil, "", false, err
	}
	fields["channelIdentity"] = identity
	out, err := json.Marshal(fields)
	if err != nil {
		return nil, "", false, err
	}
	poster := ""
	if teamsGUID.MatchString(m.From.User.ID) {
		poster = m.From.User.ID
	}
	return out, poster, true, nil
}

// maxTeamsPosters bounds the user lookups one collection makes.
const maxTeamsPosters = 200

type teamsUser struct {
	ID   string `json:"id"`
	Mail string `json:"mail,omitempty"`
}

// teamsPosters reads each poster's address (GET /v1.0/users/{id}), at most
// maxTeamsPosters, skipping any Graph will not show.
func teamsPosters(ctx context.Context, req Request, posters map[string]bool) []teamsUser {
	ids := make([]string, 0, len(posters))
	for id := range posters {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > maxTeamsPosters {
		ids = ids[:maxTeamsPosters]
	}
	var users []teamsUser
	for _, id := range ids {
		body, _, err := get(ctx, req, req.BaseURL+"/v1.0/users/"+url.PathEscape(id)+"?$select=id,mail", authorization(req))
		if err != nil {
			continue
		}
		var user teamsUser
		if json.Unmarshal(body, &user) != nil || !strings.EqualFold(user.ID, id) || user.Mail == "" {
			continue
		}
		users = append(users, user)
	}
	return users
}

// collectConfluence reads the content a CQL query selects (pages, blog
// posts, comments: GET {base}/rest/api/content/search with the storage body,
// version and space expanded; Confluence's own next link, which is relative
// to the site, followed) and writes it as content.json with a results array,
// as the search answers. base_url is the site including its context path
// (https://example.atlassian.net/wiki for Confluence Cloud).
func collectConfluence(ctx context.Context, w *writer, req Request) (Result, error) {
	cql := strings.TrimSpace(req.CQL)
	if cql == "" {
		return Result{}, fmt.Errorf("%w: name the content with a CQL query", ErrRefused)
	}
	if !req.Since.IsZero() {
		cql = "(" + cql + ") AND lastmodified >= \"" + req.Since.UTC().Format("2006-01-02 15:04") + "\""
	}
	q := url.Values{"cql": {cql}, "expand": {"body.storage,version,space"}, "limit": {"50"}}
	next := req.BaseURL + "/rest/api/content/search?" + q.Encode()
	var results []json.RawMessage
	res := Result{}
	seen := map[string]bool{}
	for pages := 0; next != ""; pages++ {
		if res.Items >= req.MaxItems || pages == maxPages {
			res.Truncated = true
			break
		}
		seen[next] = true
		body, _, err := get(ctx, req, next, authorization(req))
		if err != nil {
			return res, err
		}
		var page struct {
			Results []json.RawMessage `json:"results"`
			Links   struct {
				Next string `json:"next"`
			} `json:"_links"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return res, fmt.Errorf("scancollect: Confluence search: %w", err)
		}
		for _, raw := range page.Results {
			if res.Items >= req.MaxItems {
				res.Truncated = true
				break
			}
			var probe struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(raw, &probe) != nil || !confluenceID.MatchString(probe.ID) {
				continue
			}
			results = append(results, raw)
			res.Items++
		}
		next = ""
		if link := page.Links.Next; link != "" && len(page.Results) > 0 && !res.Truncated {
			// Confluence names the next page relative to its own site, never
			// another host.
			if !strings.HasPrefix(link, "/") || strings.HasPrefix(link, "//") || strings.Contains(link, `\`) {
				return res, fmt.Errorf("%w: Confluence's next page is not on the site", ErrRefused)
			}
			if candidate := req.BaseURL + link; !seen[candidate] {
				next = candidate
			}
		}
	}
	ok, err := w.writeJSON("content.json", map[string]any{"results": results})
	if err != nil {
		return res, err
	}
	if !ok {
		res.Truncated = true
	}
	return res, nil
}

// sameOrigin reports whether link is on base's scheme and host, so a next
// page a provider names cannot send the request's credential elsewhere.
func sameOrigin(base, link string) bool {
	b, err := url.Parse(base)
	if err != nil {
		return false
	}
	l, err := url.Parse(link)
	if err != nil || l.User != nil {
		return false
	}
	return strings.EqualFold(b.Scheme, l.Scheme) && strings.EqualFold(b.Host, l.Host)
}
