// SPDX-License-Identifier: BUSL-1.1

package ticketintake

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// P13-L1: every trstctl decision on a request that ServiceNow intake opened
// is written back to its ticket as a work note — approved, denied, canceled,
// expired, issued. A relay adds the note with the intake schedule's token
// redeemed for that one attempt; the note carries a marker so that reading
// the ticket first makes a replayed job add nothing.

// NoteJobKind is the relay job kind that adds one work note.
const NoteJobKind = "ticket.note"

// MaxNoteText bounds a note's text.
const MaxNoteText = 2000

// NoteIntent is one work note on one ServiceNow ticket.
type NoteIntent struct {
	Schedule    string `json:"schedule,omitempty"`
	NoteID      string `json:"note_id"`
	InstanceURL string `json:"instance_url"`
	TokenRef    string `json:"token_ref"`
	SNTable     string `json:"sn_table"`
	SourceRef   string `json:"source_ref"`
	Text        string `json:"text"`
}

// NoteReport is what the relay returns: whether it added the note or found it
// already there.
type NoteReport struct {
	Schedule   string    `json:"schedule,omitempty"`
	NoteID     string    `json:"note_id"`
	Outcome    string    `json:"outcome"`
	ObservedAt time.Time `json:"observed_at"`
}

// Note outcomes.
const (
	NoteAdded   = "added"
	NotePresent = "present"
)

// NoteID names one decision's note: the same request and decision always
// give the same note.
func NoteID(tenantID, requestID, decision string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("ticket-note\x00"+tenantID+"\x00"+requestID+"\x00"+decision)).String()
}

// NoteMarker is what the note ends with, and what the relay looks for.
func NoteMarker(noteID string) string {
	return "[trstctl note " + noteID + "]"
}

// ValidateNoteIntent checks a work note's durable intent.
func ValidateNoteIntent(intent NoteIntent) error {
	if !ValidScheduleName(intent.Schedule) {
		return errors.New("ticket note: schedule must contain 1-40 lowercase letters, digits, underscores or hyphens")
	}
	if parsed, err := uuid.Parse(intent.NoteID); err != nil || parsed == uuid.Nil {
		return errors.New("ticket note: note_id must be a non-zero UUID")
	}
	if !allowedTables[strings.TrimSpace(intent.SNTable)] {
		return errors.New("ticket note: table is not request-shaped")
	}
	if !ValidSourceRef(intent.SourceRef) || strings.ContainsAny(intent.SourceRef, ":.") {
		return errors.New("ticket note: source_ref must be a ServiceNow sys_id")
	}
	if !strings.HasPrefix(strings.TrimSpace(intent.TokenRef), "secret://") {
		return errors.New("ticket note: token_ref must be a secret:// reference")
	}
	text := strings.TrimSpace(intent.Text)
	if text == "" || len(text) > MaxNoteText || strings.IndexFunc(text, func(r rune) bool { return unicode.IsControl(r) && r != '\n' }) >= 0 {
		return fmt.Errorf("ticket note: text must be 1-%d printable characters", MaxNoteText)
	}
	return nil
}

// NoteEndpoints are the one GET (the ticket's work notes, to find the marker)
// and the one PATCH (the note) a work note makes.
func NoteEndpoints(intent NoteIntent) (read, write string, err error) {
	if err := ValidateNoteIntent(intent); err != nil {
		return "", "", err
	}
	base, err := url.Parse(strings.TrimSpace(intent.InstanceURL))
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil {
		return "", "", errors.New("ticket note: instance URL must be absolute")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/now/table/" + strings.TrimSpace(intent.SNTable) + "/" + url.PathEscape(intent.SourceRef)
	base.RawQuery, base.Fragment = "", ""
	write = base.String()
	q := url.Values{}
	q.Set("sysparm_fields", "work_notes")
	q.Set("sysparm_display_value", "true")
	q.Set("sysparm_exclude_reference_link", "true")
	base.RawQuery = q.Encode()
	return base.String(), write, nil
}

// NoteBody is the PATCH body: the note's text and its marker as a work note.
func NoteBody(intent NoteIntent) ([]byte, error) {
	if err := ValidateNoteIntent(intent); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"work_notes": strings.TrimSpace(intent.Text) + "\n" + NoteMarker(intent.NoteID)})
}

// NoteAlreadyPresent reports whether a ticket's work notes, as the read returned
// them, already hold this note.
func NoteAlreadyPresent(readBody []byte, noteID string) (bool, error) {
	var payload struct {
		Result struct {
			WorkNotes string `json:"work_notes"`
		} `json:"result"`
	}
	if err := json.Unmarshal(readBody, &payload); err != nil {
		return false, fmt.Errorf("ticket note: parse ServiceNow response: %w", err)
	}
	return strings.Contains(payload.Result.WorkNotes, NoteMarker(noteID)), nil
}

// ValidateNoteReport checks a relay's report against its durable intent.
func ValidateNoteReport(intent NoteIntent, report NoteReport) error {
	if err := ValidateNoteIntent(intent); err != nil {
		return err
	}
	if report.NoteID != intent.NoteID || ScheduleName(report.Schedule) != ScheduleName(intent.Schedule) || report.ObservedAt.IsZero() {
		return errors.New("ticket note: the report is for another note")
	}
	if report.Outcome != NoteAdded && report.Outcome != NotePresent {
		return errors.New("ticket note: the report's outcome is neither added nor present")
	}
	return nil
}
