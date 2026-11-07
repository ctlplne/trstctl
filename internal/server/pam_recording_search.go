// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/projections"
)

// A275: search across a tenant's session recordings. Recordings stay sealed
// per tenant in the object store — there is no plaintext index at rest — so
// a search opens the newest sessions' recordings within its bounds and reads
// the lines an operator would: SSH commands and terminal output, SQL
// statements and results, remote desktop index entries and other recorded
// requests. It never reads the typed-input stream, where a password typed at
// an echo-off prompt can stand. It matches case-insensitively, masks what it
// returns, and records the search before answering.

const (
	// recordingSearchBytes bounds the recording bytes one search reads.
	recordingSearchBytes = 64 << 20
	// recordingSearchSnippet bounds a returned line, around its match.
	recordingSearchSnippet = 240
	// recordingSearchLineBytes bounds a terminal line held while it is
	// still being written.
	recordingSearchLineBytes = 16 << 10
	// recordingSearchMatchedSessions bounds the sessions a search's record
	// names.
	recordingSearchMatchedSessions = 100
	// recordingSearchQueryBytes bounds the query a search's record keeps.
	recordingSearchQueryBytes = 256
)

// recordingSearchLine is one line a search reads from a recording.
type recordingSearchLine struct {
	atMillis           int64
	conn               int
	source, kind, text string
}

// recordingPartialLine is terminal output not yet ended by a newline.
type recordingPartialLine struct {
	atMillis int64
	conn     int
	buf      []byte
}

// recordingSearchFrame is the part of a recording frame a search reads.
type recordingSearchFrame struct {
	T      int64  `json:"t"`
	Conn   int    `json:"c"`
	Ch     int    `json:"ch"`
	Stream string `json:"s"`
	Data   string `json:"d"`
	Event  string `json:"e"`
	Kind   string `json:"kind"`
	Text   string `json:"v"`
}

// recordingSearchLines turns frames into the lines a search reads, calling
// emit for each until it returns false (then it returns false). Terminal
// output is split into lines per connection, channel and stream, its escape
// sequences removed; a line still open is kept in partial for the next page.
func recordingSearchLines(frames []json.RawMessage, partial map[string]*recordingPartialLine, emit func(recordingSearchLine) bool) bool {
	for _, raw := range frames {
		var f recordingSearchFrame
		if json.Unmarshal(raw, &f) != nil {
			continue
		}
		if f.Stream == "out" || f.Stream == "err" {
			data, err := base64.StdEncoding.DecodeString(f.Data)
			if err != nil {
				continue
			}
			key := fmt.Sprintf("%d/%d/%s", f.Conn, f.Ch, f.Stream)
			p := partial[key]
			if p == nil {
				p = &recordingPartialLine{atMillis: f.T, conn: f.Conn}
				partial[key] = p
			}
			for _, c := range data {
				if c != '\n' && c != '\r' {
					if len(p.buf) == 0 {
						p.atMillis = f.T
					}
					if len(p.buf) < recordingSearchLineBytes {
						p.buf = append(p.buf, c)
					}
					continue
				}
				if len(p.buf) > 0 {
					line := recordingSearchLine{atMillis: p.atMillis, conn: p.conn, source: "output", kind: f.Stream, text: terminalText(p.buf)}
					p.buf = p.buf[:0]
					if line.text != "" && !emit(line) {
						return false
					}
				}
			}
			continue
		}
		if f.Text == "" {
			continue
		}
		line := recordingSearchLine{atMillis: f.T, conn: f.Conn, kind: f.Kind, text: f.Text}
		switch f.Event {
		case "", "policy", "connect", "close", "sftp":
			continue
		case "request":
			line.source = "request"
			if f.Kind == "exec" {
				line.source = "command"
			}
		case "sql":
			line.source = "sql"
		case "result":
			line.source = "result"
		case "index":
			line.source = "index"
		default:
			line.source, line.kind = "request", strings.TrimSpace(f.Event+" "+f.Kind)
		}
		if !emit(line) {
			return false
		}
	}
	return true
}

// flushRecordingLines emits the terminal lines still open at a recording's
// end.
func flushRecordingLines(partial map[string]*recordingPartialLine, emit func(recordingSearchLine) bool) bool {
	for key, p := range partial {
		if len(p.buf) > 0 {
			stream := key[strings.LastIndexByte(key, '/')+1:]
			if text := terminalText(p.buf); text != "" && !emit(recordingSearchLine{atMillis: p.atMillis, conn: p.conn, source: "output", kind: stream, text: text}) {
				return false
			}
		}
	}
	return true
}

// terminalText is a terminal line's text: escape sequences and control
// characters removed, a backspace erasing what it echoes over.
func terminalText(b []byte) string {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c == 0x1b && i+1 < len(b) && b[i+1] == '[':
			i += 2
			for i < len(b) && (b[i] < 0x40 || b[i] > 0x7e) {
				i++
			}
		case c == 0x1b && i+1 < len(b) && b[i+1] == ']':
			i += 2
			for i < len(b) && b[i] != 0x07 && (b[i] != 0x1b || i+1 >= len(b) || b[i+1] != '\\') {
				i++
			}
			if i < len(b) && b[i] == 0x1b {
				i++
			}
		case c == 0x1b:
			i++
		case c == 0x08:
			if len(out) > 0 {
				_, size := utf8.DecodeLastRune(out)
				out = out[:len(out)-size]
			}
		case c == '\t' || c >= 0x20 && c != 0x7f:
			out = append(out, c)
		}
	}
	return strings.TrimSpace(strings.ToValidUTF8(string(out), ""))
}

// recordingSnippet is at most recordingSearchSnippet characters of a line
// around the match at index i (a byte offset), masked.
func recordingSnippet(line string, i, n int) string {
	runes := []rune(line)
	if len(runes) > recordingSearchSnippet {
		at := utf8.RuneCountInString(line[:i])
		start := at - (recordingSearchSnippet-utf8.RuneCountInString(line[i:i+n]))/2
		start = max(0, min(start, len(runes)-recordingSearchSnippet))
		line = string(runes[start : start+recordingSearchSnippet])
	}
	return accessgateway.MaskText(line)
}

// SearchPAMRecordings searches the tenant's session recordings (A275).
func (s *Server) SearchPAMRecordings(ctx context.Context, tenantID, actor string, q api.PAMRecordingSearchQuery) (api.PAMRecordingSearchResult, error) {
	if s.pam == nil || s.pam.recordings == nil {
		return api.PAMRecordingSearchResult{}, api.ErrPAMUnavailable
	}
	if strings.TrimSpace(actor) == "" {
		return api.PAMRecordingSearchResult{}, fmt.Errorf("%w: an authenticated searcher is required", api.ErrPAMInvalid)
	}
	candidates, err := s.store.ListPAMRecordingsForSearch(ctx, tenantID, q.Since, q.Until, q.TargetType, q.TargetID, q.Sessions)
	if err != nil {
		return api.PAMRecordingSearchResult{}, err
	}
	needle := strings.ToLower(q.Text)
	out := api.PAMRecordingSearchResult{Items: []api.PAMRecordingSearchHit{}}
	var matched []string
	budget := recordingSearchBytes
	for _, c := range candidates {
		if len(out.Items) >= q.Limit || budget <= 0 {
			out.Truncated = true
			break
		}
		before := len(out.Items)
		emit := func(line recordingSearchLine) bool {
			lower := strings.ToLower(line.text)
			if i := strings.Index(lower, needle); i >= 0 && len(lower) == len(line.text) {
				out.Items = append(out.Items, api.PAMRecordingSearchHit{SessionID: c.SessionID, TargetType: c.TargetType, TargetID: c.TargetID,
					Subject: c.Subject, SessionStartedAt: c.StartedAt.UTC(), AtMillis: line.atMillis, Conn: line.conn, Source: line.source,
					Kind: line.kind, Text: recordingSnippet(line.text, i, len(needle))})
			} else if i >= 0 {
				out.Items = append(out.Items, api.PAMRecordingSearchHit{SessionID: c.SessionID, TargetType: c.TargetType, TargetID: c.TargetID,
					Subject: c.Subject, SessionStartedAt: c.StartedAt.UTC(), AtMillis: line.atMillis, Conn: line.conn, Source: line.source,
					Kind: line.kind, Text: recordingSnippet(line.text, 0, 0)})
			}
			return len(out.Items) < q.Limit
		}
		partial := map[string]*recordingPartialLine{}
		complete := true
		for from := 0; ; {
			frames, next, err := s.pam.recordingFrames(ctx, tenantID, c.SessionID, from, 50, recordingReadLimit)
			if err != nil {
				return api.PAMRecordingSearchResult{}, err
			}
			for _, f := range frames {
				budget -= len(f)
			}
			if !recordingSearchLines(frames, partial, emit) {
				complete = false
				break
			}
			if next == from || budget <= 0 {
				complete = next == from
				break
			}
			from = next
		}
		if complete {
			complete = flushRecordingLines(partial, emit)
		}
		out.SessionsSearched++
		if len(out.Items) > before && len(matched) < recordingSearchMatchedSessions {
			matched = append(matched, c.SessionID)
		}
		if !complete {
			out.Truncated = true
			break
		}
	}
	query := q.Text
	if len(query) > recordingSearchQueryBytes {
		query = strings.ToValidUTF8(query[:recordingSearchQueryBytes], "")
	}
	if err := s.pam.appendDeterministic(ctx, tenantID, uuid.NewString(), projections.EventPAMRecordingSearched, projections.PAMRecordingSearched{
		ID: uuid.NewString(), Actor: actor, Query: accessgateway.MaskText(query), Since: q.Since.UTC(), Until: q.Until.UTC(),
		TargetType: q.TargetType, TargetID: q.TargetID, SessionsSearched: out.SessionsSearched, Matches: len(out.Items),
		MatchedSessions: matched, Truncated: out.Truncated, At: time.Now().UTC().Truncate(time.Millisecond),
	}); err != nil {
		return api.PAMRecordingSearchResult{}, err
	}
	return out, nil
}
