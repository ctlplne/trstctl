// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"encoding/json"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// maxLocateBytes bounds the one export file a locator reads.
const maxLocateBytes = 64 << 20

// LocateThirdPartyObject maps a finding's file and line in a provider export
// to the provider object it sat in (A174): for a Slack export, the channel
// (and its ID from channels.json) and the message's ts and thread_ts; for a
// Jira export, the issue key; for a Teams export (OD-4), the team, channel
// and message (and the message it replies to), with the poster's address
// from users.json; for a Confluence export, the content's ID, type and
// space. It reads only that one export file, inside the
// artifact, and returns false when the object cannot be told. Nothing it
// returns is content: identifiers only.
func LocateThirdPartyObject(provider, artifactPath, file string, line int) (map[string]string, bool) {
	full, ok := exportFile(artifactPath, file)
	if !ok || line < 1 {
		return nil, false
	}
	data, err := readBounded(full)
	if err != nil {
		return nil, false
	}
	switch NormalizeThirdPartyProvider(provider) {
	case ThirdPartyProviderSlack:
		msg, ok := elementAtLine(data, line, "")
		if !ok {
			// A JSON Lines export holds one message per line.
			msg = lineAt(data, line)
		}
		var m struct {
			TS        string `json:"ts"`
			ThreadTS  string `json:"thread_ts"`
			Channel   string `json:"channel"`
			ChannelID string `json:"channel_id"`
			User      string `json:"user"`
		}
		if json.Unmarshal(msg, &m) != nil || m.TS == "" {
			return nil, false
		}
		channel := m.Channel
		if channel == "" {
			channel = filepath.Base(filepath.Dir(full))
		}
		out := map[string]string{"kind": "slack_message", "channel": channel, "message_ts": m.TS}
		if m.ThreadTS != "" && m.ThreadTS != m.TS {
			out["thread_ts"] = m.ThreadTS
		}
		if m.ChannelID != "" {
			out["channel_id"] = m.ChannelID
		} else if id := slackChannelID(filepath.Dir(filepath.Dir(full)), channel); id != "" {
			out["channel_id"] = id
		}
		// P14: the poster, and their address from the export's users.json,
		// so the finding can name its owner.
		if slackUserPattern.MatchString(m.User) {
			out["user"] = m.User
			if email := slackUserEmail(filepath.Dir(filepath.Dir(full)), m.User); email != "" {
				out["user_email"] = email
			}
		}
		return out, true
	case ThirdPartyProviderJira:
		issue, ok := elementAtLine(data, line, "issues")
		if !ok {
			issue = lineAt(data, line)
			var probe struct {
				Key string `json:"key"`
			}
			if json.Unmarshal(issue, &probe) != nil || probe.Key == "" {
				issue = data
			}
		}
		var i struct {
			Key string `json:"key"`
		}
		if json.Unmarshal(issue, &i) != nil || i.Key == "" {
			return nil, false
		}
		return map[string]string{"kind": "jira_issue", "issue_key": i.Key}, true
	case ThirdPartyProviderTeams:
		return locateTeamsMessage(full, data, line)
	case ThirdPartyProviderConfluence:
		return locateConfluenceContent(data, line)
	default:
		return nil, false
	}
}

var (
	teamsGUIDPattern      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	teamsChannelPattern   = regexp.MustCompile(`^19:[A-Za-z0-9_-]{1,200}@thread\.(?:tacv2|skype)$`)
	teamsMessagePattern   = regexp.MustCompile(`^[0-9]{1,20}$`)
	confluenceIDPattern   = regexp.MustCompile(`^[0-9]{1,20}$`)
	confluenceTypePattern = regexp.MustCompile(`^[a-z_]{1,32}$`)
	confluenceKeyPattern  = regexp.MustCompile(`^~?[A-Za-z0-9_-]{1,255}$`)
)

// locateTeamsMessage names the Microsoft Graph chatMessage at a line: its
// team, channel and message IDs, the message it replies to, and the poster
// with their address from the export's users.json.
func locateTeamsMessage(full string, data []byte, line int) (map[string]string, bool) {
	msg, ok := elementAtLine(data, line, "")
	if !ok {
		msg = lineAt(data, line)
	}
	var m struct {
		ID              string `json:"id"`
		ReplyToID       string `json:"replyToId"`
		ChannelIdentity struct {
			TeamID    string `json:"teamId"`
			ChannelID string `json:"channelId"`
		} `json:"channelIdentity"`
		From struct {
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"from"`
	}
	if json.Unmarshal(msg, &m) != nil || !teamsMessagePattern.MatchString(m.ID) ||
		!teamsGUIDPattern.MatchString(m.ChannelIdentity.TeamID) || !teamsChannelPattern.MatchString(m.ChannelIdentity.ChannelID) {
		return nil, false
	}
	out := map[string]string{"kind": "teams_message", "team_id": m.ChannelIdentity.TeamID,
		"channel_id": m.ChannelIdentity.ChannelID, "message_id": m.ID}
	if teamsMessagePattern.MatchString(m.ReplyToID) && m.ReplyToID != m.ID {
		out["reply_to_id"] = m.ReplyToID
	}
	if teamsGUIDPattern.MatchString(m.From.User.ID) {
		out["user"] = m.From.User.ID
		if email := teamsUserEmail(filepath.Dir(filepath.Dir(full)), m.From.User.ID); email != "" {
			out["user_email"] = email
		}
	}
	return out, true
}

// teamsUserEmail reads a member's address from the export's users.json
// ([{"id", "mail"}], as Microsoft Graph's user resource names it).
func teamsUserEmail(exportRoot, userID string) string {
	data, err := readBounded(filepath.Join(exportRoot, "users.json"))
	if err != nil {
		return ""
	}
	var users []struct {
		ID   string `json:"id"`
		Mail string `json:"mail"`
	}
	if json.Unmarshal(data, &users) != nil {
		return ""
	}
	for _, u := range users {
		if strings.EqualFold(u.ID, userID) {
			if addr, err := mail.ParseAddress(u.Mail); err == nil && addr.Address == u.Mail {
				return u.Mail
			}
		}
	}
	return ""
}

// locateConfluenceContent names the Confluence content at a line of a
// search export ({"results": [...]}, or JSON Lines): its ID, its type (page,
// blogpost, comment) and its space's key. Never its title or body.
func locateConfluenceContent(data []byte, line int) (map[string]string, bool) {
	item, ok := elementAtLine(data, line, "results")
	if !ok {
		item = lineAt(data, line)
	}
	var c struct {
		ID    string `json:"id"`
		Type  string `json:"type"`
		Space struct {
			Key string `json:"key"`
		} `json:"space"`
	}
	if json.Unmarshal(item, &c) != nil || !confluenceIDPattern.MatchString(c.ID) || !confluenceTypePattern.MatchString(c.Type) {
		return nil, false
	}
	out := map[string]string{"kind": "confluence_content", "content_id": c.ID, "content_type": c.Type}
	if confluenceKeyPattern.MatchString(c.Space.Key) {
		out["space_key"] = c.Space.Key
	}
	return out, true
}

// exportFile resolves a finding's file against the artifact and refuses any
// path that leaves it.
func exportFile(artifactPath, file string) (string, bool) {
	artifactPath = filepath.Clean(strings.TrimSpace(artifactPath))
	info, err := os.Stat(artifactPath)
	if err != nil {
		return "", false
	}
	root := artifactPath
	if !info.IsDir() {
		root = filepath.Dir(artifactPath)
	}
	full := filepath.Clean(file)
	if !filepath.IsAbs(full) {
		full = filepath.Join(root, filepath.FromSlash(file))
	}
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	if !info.IsDir() && full != artifactPath {
		return "", false
	}
	return full, true
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- a file inside the operator's reviewed artifact path, checked by exportFile (CWE-22)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, maxLocateBytes))
}

// elementAtLine finds the element of a JSON array that spans a line: the
// top-level array, or the array under key in a top-level object.
func elementAtLine(data []byte, line int, key string) (json.RawMessage, bool) {
	starts := lineStarts(data)
	if line > len(starts) {
		return nil, false
	}
	lineStart := starts[line-1]
	lineEnd := int64(len(data))
	if line < len(starts) {
		lineEnd = starts[line]
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if key != "" {
		if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
			return nil, false
		}
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, false
			}
			name, ok := tok.(string)
			if !ok {
				return nil, false
			}
			if name == key {
				break
			}
			var skip json.RawMessage
			if dec.Decode(&skip) != nil {
				return nil, false
			}
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil, false
	}
	var found json.RawMessage
	matches := 0
	for dec.More() {
		start := dec.InputOffset()
		var raw json.RawMessage
		if dec.Decode(&raw) != nil {
			return nil, false
		}
		end := dec.InputOffset()
		// The decoder's offset sits before the separator; the element itself
		// starts at its first byte.
		for start < end && strings.ContainsRune(" \t\r\n,", rune(data[start])) {
			start++
		}
		if start < lineEnd && end > lineStart {
			found = raw
			matches++
		}
	}
	// A line shared by several elements (a minified export) cannot be
	// attributed to one of them.
	return found, matches == 1
}

// lineAt returns one line of the file, for JSON Lines exports.
func lineAt(data []byte, line int) []byte {
	starts := lineStarts(data)
	if line < 1 || line > len(starts) {
		return nil
	}
	end := int64(len(data))
	if line < len(starts) {
		end = starts[line]
	}
	return bytes.TrimSpace(data[starts[line-1]:end])
}

func lineStarts(data []byte) []int64 {
	starts := []int64{0}
	for i, b := range data {
		if b == '\n' && i+1 < len(data) {
			starts = append(starts, int64(i+1))
		}
	}
	return starts
}

// slackChannelID reads the export's channels.json (and the private-channel
// lists beside it) for the channel's ID.
func slackChannelID(exportRoot, channel string) string {
	for _, name := range []string{"channels.json", "groups.json", "mpims.json"} {
		data, err := readBounded(filepath.Join(exportRoot, name))
		if err != nil {
			continue
		}
		var channels []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if json.Unmarshal(data, &channels) != nil {
			continue
		}
		sort.SliceStable(channels, func(i, j int) bool { return channels[i].Name < channels[j].Name })
		for _, c := range channels {
			if c.Name == channel {
				return c.ID
			}
		}
	}
	return ""
}

var slackUserPattern = regexp.MustCompile(`^[UW][A-Z0-9]{2,20}$`)

// slackUserEmail reads a member's email from the export's users.json, as
// Slack's own export writes it (profile.email).
func slackUserEmail(exportRoot, userID string) string {
	data, err := readBounded(filepath.Join(exportRoot, "users.json"))
	if err != nil {
		return ""
	}
	var users []struct {
		ID      string `json:"id"`
		Profile struct {
			Email string `json:"email"`
		} `json:"profile"`
	}
	if json.Unmarshal(data, &users) != nil {
		return ""
	}
	for _, u := range users {
		if u.ID == userID {
			if addr, err := mail.ParseAddress(u.Profile.Email); err == nil && addr.Address == u.Profile.Email {
				return u.Profile.Email
			}
		}
	}
	return ""
}
