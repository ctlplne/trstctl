// SPDX-License-Identifier: BUSL-1.1

// Package ticketintake defines reference-only ServiceNow and Jira read intents
// and their bounded parsers. The network relay executes the read; the control
// plane consumes only typed observations and decides which requests to open.
package ticketintake

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const MaxTickets = 100

const (
	SystemServiceNow = "servicenow"
	SystemJira       = "jira"
)

var sourceRefPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var jiraProjectPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
var fieldPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var jiraOrderByPattern = regexp.MustCompile(`(?i)\border\s+by\b`)

var allowedTables = map[string]bool{
	"incident": true, "sc_req_item": true, "sc_request": true, "change_request": true,
}

// SyncIntent is durable outbox data. TokenRef names material redeemed for one
// attempt; it is never the bearer token itself.
type SyncIntent struct {
	System             string `json:"system"`
	InstanceURL        string `json:"instance_url"`
	TokenRef           string `json:"token_ref"`
	SNTable            string `json:"sn_table,omitempty"`
	JiraProject        string `json:"jira_project,omitempty"`
	Query              string `json:"query,omitempty"`
	SubjectField       string `json:"subject_field"`
	ProfileField       string `json:"profile_field"`
	RequesterField     string `json:"requester_field,omitempty"`
	JustificationField string `json:"justification_field,omitempty"`
	PageLimit          int    `json:"page_limit"`
	SweepID            string `json:"sweep_id"`
	Cursor             string `json:"cursor,omitempty"`
	ReadCount          int    `json:"read_count"`
	ExpectedCount      *int   `json:"expected_count,omitempty"`
}

// Ticket is the bounded observation the relay reports. It contains only the
// fields the configured mapping names, not an arbitrary ServiceNow row.
type Ticket struct {
	SourceRef     string `json:"source_ref"`
	ExternalKey   string `json:"external_key,omitempty"`
	Subject       string `json:"subject,omitempty"`
	Profile       string `json:"profile,omitempty"`
	Requester     string `json:"requester,omitempty"`
	Justification string `json:"justification,omitempty"`
}

type SyncReport struct {
	System        string    `json:"system"`
	SweepID       string    `json:"sweep_id"`
	Cursor        string    `json:"cursor,omitempty"`
	ObservedAt    time.Time `json:"observed_at"`
	SourceRefs    []string  `json:"source_refs"`
	Tickets       []Ticket  `json:"tickets"`
	ReadCount     int       `json:"read_count"`
	ExpectedCount *int      `json:"expected_count,omitempty"`
	Complete      bool      `json:"complete"`
	NextCursor    string    `json:"next_cursor,omitempty"`
}

// Page is one provider response after it has been reduced to the small signed
// shape the control plane accepts. SourceRefs includes unmappable tickets: a
// cursor derived only from Tickets would skip an unowned/unmapped tail row.
type Page struct {
	Tickets       []Ticket
	SourceRefs    []string
	NextCursor    string
	ExpectedCount *int
	Complete      bool
}

func Endpoint(intent SyncIntent) (string, error) {
	base, err := url.Parse(strings.TrimSpace(intent.InstanceURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", errors.New("ticket intake: instance URL must be absolute")
	}
	if intent.PageLimit <= 0 || intent.PageLimit > MaxTickets {
		return "", fmt.Errorf("ticket intake: page limit must be between 1 and %d", MaxTickets)
	}
	if intent.SweepID != "" {
		parsed, parseErr := uuid.Parse(intent.SweepID)
		if parseErr != nil || parsed == uuid.Nil {
			return "", errors.New("ticket intake: sweep_id must be a non-zero UUID")
		}
	}
	if intent.ReadCount < 0 || (intent.ExpectedCount != nil && *intent.ExpectedCount < intent.ReadCount) {
		return "", errors.New("ticket intake: progress counts are not coherent")
	}
	if (intent.Cursor == "") != (intent.ReadCount == 0) {
		return "", errors.New("ticket intake: cursor and read_count must advance together")
	}
	if strings.TrimSpace(intent.TokenRef) != "" && !strings.HasPrefix(strings.TrimSpace(intent.TokenRef), "secret://") {
		return "", errors.New("ticket intake: token_ref must be a secret:// reference")
	}
	if err := validateFields(intent); err != nil {
		return "", err
	}
	switch strings.TrimSpace(intent.System) {
	case SystemServiceNow:
		return serviceNowEndpoint(base, intent)
	case SystemJira:
		return jiraEndpoint(base, intent)
	default:
		return "", errors.New("ticket intake: system must be servicenow or jira")
	}
}

func serviceNowEndpoint(base *url.URL, intent SyncIntent) (string, error) {
	table := strings.TrimSpace(intent.SNTable)
	if !allowedTables[table] {
		return "", errors.New("ticket intake: table is not request-shaped")
	}
	if cursor := strings.TrimSpace(intent.Cursor); cursor != "" && !ValidSourceRef(cursor) {
		return "", errors.New("ticket intake: ServiceNow cursor is not a usable sys_id")
	}
	query := strings.Trim(strings.TrimSpace(intent.Query), "^")
	if strings.Contains(strings.ToUpper(query), "ORDERBY") {
		return "", errors.New("ticket intake: query must not override stable sys_id ordering")
	}
	parts := make([]string, 0, 3)
	if query != "" {
		parts = append(parts, query)
	}
	if intent.Cursor != "" {
		parts = append(parts, "sys_id>"+intent.Cursor)
	}
	parts = append(parts, "ORDERBYsys_id")
	base.Path = strings.TrimRight(base.Path, "/") + "/api/now/table/" + table
	q := url.Values{}
	q.Set("sysparm_display_value", "all")
	q.Set("sysparm_limit", fmt.Sprintf("%d", intent.PageLimit))
	q.Set("sysparm_query", strings.Join(parts, "^"))
	base.RawQuery = q.Encode()
	base.Fragment = ""
	return base.String(), nil
}

func jiraEndpoint(base *url.URL, intent SyncIntent) (string, error) {
	project := strings.TrimSpace(intent.JiraProject)
	if !jiraProjectPattern.MatchString(project) {
		return "", errors.New("ticket intake: jira_project is not a bounded Jira project key")
	}
	query := strings.TrimSpace(intent.Query)
	if jiraOrderByPattern.MatchString(query) {
		return "", errors.New("ticket intake: Jira query must not override stable id ordering")
	}
	jql := `project = "` + project + `"`
	if query != "" {
		jql += " AND (" + query + ")"
	}
	jql += " ORDER BY id ASC"
	base.Path = strings.TrimRight(base.Path, "/") + "/rest/api/3/search/jql"
	q := url.Values{}
	q.Set("jql", jql)
	q.Set("maxResults", strconv.Itoa(intent.PageLimit))
	q.Set("fields", strings.Join(uniqueFields(intent), ","))
	if intent.Cursor != "" {
		if len(intent.Cursor) > 2048 || strings.TrimSpace(intent.Cursor) != intent.Cursor {
			return "", errors.New("ticket intake: Jira continuation token is not bounded")
		}
		q.Set("nextPageToken", intent.Cursor)
	}
	base.RawQuery = q.Encode()
	base.Fragment = ""
	return base.String(), nil
}

func validateFields(intent SyncIntent) error {
	if strings.TrimSpace(intent.SubjectField) == "" || strings.TrimSpace(intent.ProfileField) == "" {
		return errors.New("ticket intake: subject and profile fields are required")
	}
	for _, field := range []string{intent.SubjectField, intent.ProfileField, intent.RequesterField, intent.JustificationField} {
		field = strings.TrimSpace(field)
		if field != "" && !fieldPattern.MatchString(field) {
			return errors.New("ticket intake: mapped field name is not bounded")
		}
	}
	return nil
}

func uniqueFields(intent SyncIntent) []string {
	seen := map[string]bool{}
	fields := make([]string, 0, 4)
	for _, field := range []string{intent.SubjectField, intent.ProfileField, intent.RequesterField, intent.JustificationField} {
		field = strings.TrimSpace(field)
		if field != "" && !seen[field] {
			seen[field] = true
			fields = append(fields, field)
		}
	}
	sort.Strings(fields)
	return fields
}

func Parse(r io.Reader, intent SyncIntent) ([]Ticket, error) {
	page, err := ParsePage(r, intent)
	if err != nil {
		return nil, err
	}
	return page.Tickets, nil
}

// ParsePage dispatches to the provider-specific bounded decoder. It refuses a
// provider that differs from the durable intent instead of guessing a shape.
func ParsePage(r io.Reader, intent SyncIntent) (Page, error) {
	if err := validateFields(intent); err != nil {
		return Page{}, err
	}
	switch strings.TrimSpace(intent.System) {
	case SystemServiceNow:
		return parseServiceNowPage(r, intent)
	case SystemJira:
		return parseJiraPage(r, intent)
	default:
		return Page{}, errors.New("ticket intake: system must be servicenow or jira")
	}
}

func parseServiceNowPage(r io.Reader, intent SyncIntent) (Page, error) {
	var payload struct {
		Result []map[string]json.RawMessage `json:"result"`
	}
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&payload); err != nil {
		return Page{}, fmt.Errorf("ticket intake: parse ServiceNow response: %w", err)
	}
	if len(payload.Result) > MaxTickets || len(payload.Result) > intent.PageLimit {
		return Page{}, fmt.Errorf("ticket intake: response exceeds the %d-ticket bound", intent.PageLimit)
	}
	page := Page{Tickets: make([]Ticket, 0, len(payload.Result)), SourceRefs: make([]string, 0, len(payload.Result))}
	previous := intent.Cursor
	for _, raw := range payload.Result {
		row := Ticket{
			SourceRef: field(raw, "sys_id"), Subject: field(raw, intent.SubjectField),
			Profile: field(raw, intent.ProfileField), Requester: field(raw, intent.RequesterField),
			Justification: field(raw, intent.JustificationField),
		}
		if err := validateTicket(row); err != nil {
			return Page{}, err
		}
		if !ValidSourceRef(row.SourceRef) || (previous != "" && row.SourceRef <= previous) {
			return Page{}, errors.New("ticket intake: ServiceNow sys_id page is not a strict continuation")
		}
		previous = row.SourceRef
		page.SourceRefs = append(page.SourceRefs, row.SourceRef)
		page.Tickets = append(page.Tickets, row)
	}
	page.Complete = len(payload.Result) < intent.PageLimit
	if !page.Complete {
		page.NextCursor = previous
	}
	return page, nil
}

func parseJiraPage(r io.Reader, intent SyncIntent) (Page, error) {
	var payload struct {
		Issues []struct {
			ID     string                     `json:"id"`
			Key    string                     `json:"key"`
			Fields map[string]json.RawMessage `json:"fields"`
		} `json:"issues"`
		NextPageToken string `json:"nextPageToken"`
		IsLast        *bool  `json:"isLast"`
		Total         *int   `json:"total"`
	}
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&payload); err != nil {
		return Page{}, fmt.Errorf("ticket intake: parse Jira response: %w", err)
	}
	if len(payload.Issues) > MaxTickets || len(payload.Issues) > intent.PageLimit {
		return Page{}, fmt.Errorf("ticket intake: response exceeds the %d-ticket bound", intent.PageLimit)
	}
	if payload.IsLast == nil {
		return Page{}, errors.New("ticket intake: Jira response omits isLast completeness")
	}
	page := Page{
		Tickets: make([]Ticket, 0, len(payload.Issues)), SourceRefs: make([]string, 0, len(payload.Issues)),
		NextCursor: strings.TrimSpace(payload.NextPageToken), ExpectedCount: payload.Total, Complete: *payload.IsLast,
	}
	var previous uint64
	for _, issue := range payload.Issues {
		id, err := strconv.ParseUint(strings.TrimSpace(issue.ID), 10, 64)
		if err != nil || id == 0 || (previous != 0 && id <= previous) {
			return Page{}, errors.New("ticket intake: Jira issue ids are not a strict numeric continuation")
		}
		previous = id
		row := Ticket{
			SourceRef: issue.ID, ExternalKey: strings.TrimSpace(issue.Key),
			Subject: jiraField(issue.Fields, intent.SubjectField), Profile: jiraField(issue.Fields, intent.ProfileField),
			Requester: jiraField(issue.Fields, intent.RequesterField), Justification: jiraField(issue.Fields, intent.JustificationField),
		}
		if err := validateTicket(row); err != nil {
			return Page{}, err
		}
		page.SourceRefs = append(page.SourceRefs, row.SourceRef)
		page.Tickets = append(page.Tickets, row)
	}
	if page.Complete && page.NextCursor != "" {
		return Page{}, errors.New("ticket intake: terminal Jira response carries a continuation token")
	}
	if !page.Complete && page.NextCursor == "" {
		return Page{}, errors.New("ticket intake: incomplete Jira response has no continuation token")
	}
	if page.ExpectedCount != nil && *page.ExpectedCount < intent.ReadCount+len(page.SourceRefs) {
		return Page{}, errors.New("ticket intake: Jira total is behind the observed read count")
	}
	return page, nil
}

func ValidateReport(intent SyncIntent, report SyncReport) error {
	if report.ObservedAt.IsZero() || report.System != intent.System || report.SweepID != intent.SweepID || report.Cursor != intent.Cursor {
		return errors.New("ticket intake: report has no observation time")
	}
	if len(report.Tickets) > MaxTickets || len(report.SourceRefs) > intent.PageLimit {
		return fmt.Errorf("ticket intake: report exceeds the %d-ticket bound", MaxTickets)
	}
	if len(report.Tickets) != len(report.SourceRefs) {
		return errors.New("ticket intake: every observed source reference must carry exactly one mapped ticket")
	}
	if report.ReadCount != intent.ReadCount+len(report.SourceRefs) ||
		(report.ExpectedCount != nil && *report.ExpectedCount < report.ReadCount) ||
		(intent.ExpectedCount != nil && !sameCount(intent.ExpectedCount, report.ExpectedCount)) {
		return errors.New("ticket intake: report progress does not match its durable input")
	}
	seen := make(map[string]bool, len(report.SourceRefs))
	var previous string
	var previousJira uint64
	for _, ref := range report.SourceRefs {
		if !ValidSourceRef(ref) || seen[ref] {
			return errors.New("ticket intake: report source references are invalid or duplicated")
		}
		seen[ref] = true
		if intent.System == SystemServiceNow {
			if (previous == "" && intent.Cursor != "" && ref <= intent.Cursor) || (previous != "" && ref <= previous) {
				return errors.New("ticket intake: ServiceNow report is not a strict keyset continuation")
			}
			previous = ref
		} else {
			id, err := strconv.ParseUint(ref, 10, 64)
			if err != nil || id == 0 || (previousJira != 0 && id <= previousJira) {
				return errors.New("ticket intake: Jira report issue ids are not strictly ordered")
			}
			previousJira = id
		}
	}
	ticketRefs := make(map[string]bool, len(report.Tickets))
	for _, ticket := range report.Tickets {
		if err := validateTicket(ticket); err != nil || !seen[ticket.SourceRef] || ticketRefs[ticket.SourceRef] {
			if err != nil {
				return err
			}
			return errors.New("ticket intake: ticket is not bound once to an observed source reference")
		}
		ticketRefs[ticket.SourceRef] = true
	}
	if report.Complete {
		if report.NextCursor != "" {
			return errors.New("ticket intake: terminal report carries a continuation")
		}
		if report.ExpectedCount != nil && *report.ExpectedCount != report.ReadCount {
			return errors.New("ticket intake: terminal report does not cover the provider total")
		}
	} else {
		if report.NextCursor == "" {
			return errors.New("ticket intake: incomplete report has no continuation")
		}
		if intent.System == SystemServiceNow {
			if len(report.SourceRefs) != intent.PageLimit || report.NextCursor != previous {
				return errors.New("ticket intake: ServiceNow continuation is not its full page boundary")
			}
		}
	}
	return nil
}

// ValidSourceRef is the closed wire/storage alphabet for provider issue keys.
func ValidSourceRef(ref string) bool {
	return ref == strings.TrimSpace(ref) && sourceRefPattern.MatchString(ref)
}

func sameCount(left, right *int) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func jiraField(fields map[string]json.RawMessage, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	raw, ok := fields[name]
	if !ok {
		return ""
	}
	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		return strings.TrimSpace(plain)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return ""
	}
	for _, key := range []string{"displayName", "value", "name", "emailAddress", "accountId"} {
		if candidate, ok := object[key]; ok && json.Unmarshal(candidate, &plain) == nil && strings.TrimSpace(plain) != "" {
			return strings.TrimSpace(plain)
		}
	}
	return ""
}

func validateTicket(ticket Ticket) error {
	if !ValidSourceRef(ticket.SourceRef) {
		return errors.New("ticket intake: source_ref is missing or invalid")
	}
	for name, value := range map[string]string{
		"source_ref": ticket.SourceRef, "external_key": ticket.ExternalKey,
		"subject": ticket.Subject, "profile": ticket.Profile,
		"requester": ticket.Requester, "justification": ticket.Justification,
	} {
		if len(value) > 4096 {
			return fmt.Errorf("ticket intake: %s exceeds the 4096-byte field bound", name)
		}
	}
	return nil
}

func field(row map[string]json.RawMessage, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	raw, ok := row[name]
	if !ok {
		return ""
	}
	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		return strings.TrimSpace(plain)
	}
	var object struct {
		DisplayValue string `json:"display_value"`
		Value        string `json:"value"`
	}
	if err := json.Unmarshal(raw, &object); err != nil {
		return ""
	}
	if displayed := strings.TrimSpace(object.DisplayValue); displayed != "" {
		return displayed
	}
	return strings.TrimSpace(object.Value)
}
