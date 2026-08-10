// SPDX-License-Identifier: MPL-2.0

// Package ticketintake defines the reference-only ServiceNow read intent and
// its bounded parser. The network relay executes the read; the control plane
// consumes only this typed observation and decides which requests to open.
package ticketintake

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

const MaxTickets = 100

var allowedTables = map[string]bool{
	"incident": true, "sc_req_item": true, "sc_request": true, "change_request": true,
}

// SyncIntent is durable outbox data. TokenRef names material redeemed for one
// attempt; it is never the bearer token itself.
type SyncIntent struct {
	InstanceURL        string `json:"instance_url"`
	TokenRef           string `json:"token_ref"`
	SNTable            string `json:"sn_table"`
	Query              string `json:"query,omitempty"`
	SubjectField       string `json:"subject_field"`
	ProfileField       string `json:"profile_field"`
	RequesterField     string `json:"requester_field,omitempty"`
	JustificationField string `json:"justification_field,omitempty"`
	PageLimit          int    `json:"page_limit"`
}

// Ticket is the bounded observation the relay reports. It contains only the
// fields the configured mapping names, not an arbitrary ServiceNow row.
type Ticket struct {
	SysID         string `json:"sys_id"`
	Subject       string `json:"subject,omitempty"`
	Profile       string `json:"profile,omitempty"`
	Requester     string `json:"requester,omitempty"`
	Justification string `json:"justification,omitempty"`
}

type SyncReport struct {
	ObservedAt time.Time `json:"observed_at"`
	Tickets    []Ticket  `json:"tickets"`
}

func Endpoint(intent SyncIntent) (string, error) {
	base, err := url.Parse(strings.TrimSpace(intent.InstanceURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", errors.New("ticket intake: instance URL must be absolute")
	}
	if !allowedTables[strings.TrimSpace(intent.SNTable)] {
		return "", errors.New("ticket intake: table is not request-shaped")
	}
	if intent.PageLimit <= 0 || intent.PageLimit > MaxTickets {
		return "", fmt.Errorf("ticket intake: page limit must be between 1 and %d", MaxTickets)
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/now/table/" + strings.TrimSpace(intent.SNTable)
	q := url.Values{}
	q.Set("sysparm_display_value", "all")
	q.Set("sysparm_limit", fmt.Sprintf("%d", intent.PageLimit))
	if query := strings.TrimSpace(intent.Query); query != "" {
		q.Set("sysparm_query", query)
	}
	base.RawQuery = q.Encode()
	base.Fragment = ""
	return base.String(), nil
}

func Parse(r io.Reader, intent SyncIntent) ([]Ticket, error) {
	if strings.TrimSpace(intent.SubjectField) == "" || strings.TrimSpace(intent.ProfileField) == "" {
		return nil, errors.New("ticket intake: subject and profile fields are required")
	}
	var payload struct {
		Result []map[string]json.RawMessage `json:"result"`
	}
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("ticket intake: parse response: %w", err)
	}
	if len(payload.Result) > MaxTickets || len(payload.Result) > intent.PageLimit {
		return nil, fmt.Errorf("ticket intake: response exceeds the %d-ticket bound", intent.PageLimit)
	}
	rows := make([]Ticket, 0, len(payload.Result))
	for _, raw := range payload.Result {
		row := Ticket{
			SysID: field(raw, "sys_id"), Subject: field(raw, intent.SubjectField),
			Profile: field(raw, intent.ProfileField), Requester: field(raw, intent.RequesterField),
			Justification: field(raw, intent.JustificationField),
		}
		if err := validateTicket(row); err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func ValidateReport(report SyncReport) error {
	if report.ObservedAt.IsZero() {
		return errors.New("ticket intake: report has no observation time")
	}
	if len(report.Tickets) > MaxTickets {
		return fmt.Errorf("ticket intake: report exceeds the %d-ticket bound", MaxTickets)
	}
	for _, ticket := range report.Tickets {
		if err := validateTicket(ticket); err != nil {
			return err
		}
	}
	return nil
}

func validateTicket(ticket Ticket) error {
	for name, value := range map[string]string{
		"sys_id": ticket.SysID, "subject": ticket.Subject, "profile": ticket.Profile,
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
