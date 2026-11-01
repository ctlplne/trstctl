// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxLocateBytes bounds the one export file a locator reads.
const maxLocateBytes = 64 << 20

// LocateThirdPartyObject maps a finding's file and line in a provider export
// to the provider object it sat in (A174): for a Slack export, the channel
// (and its ID from channels.json) and the message's ts and thread_ts; for a
// Jira export, the issue key. It reads only that one export file, inside the
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
	default:
		return nil, false
	}
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
