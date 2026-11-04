// SPDX-License-Identifier: BUSL-1.1

package ticketintake

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Change-request approval read (P13). The requests intake opened from a
// ServiceNow change_request wait on that change's approval: a relay reads the
// approval and state of exactly those tickets, by sys_id, and reports nothing
// else. The control plane decides the matching trstctl request once from what
// ServiceNow says — approved or rejected — and never from prose.

// MaxStatusTickets bounds one status read.
const MaxStatusTickets = 100

// StatusTable is the one ServiceNow table whose approval decides a request.
const StatusTable = "change_request"

// ServiceNow approval values the control plane acts on.
const (
	ApprovalApproved = "approved"
	ApprovalRejected = "rejected"
)

var approvalPattern = regexp.MustCompile(`^[a-z_ ]{0,32}$`)
var statePattern = regexp.MustCompile(`^-?[0-9]{1,4}$|^$`)
var numberPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{0,40}$`)

// StatusIntent is durable outbox data for one status read. TokenRef names the
// intake schedule's token, redeemed for one attempt.
type StatusIntent struct {
	Schedule    string   `json:"schedule,omitempty"`
	StatusID    string   `json:"status_id"`
	InstanceURL string   `json:"instance_url"`
	TokenRef    string   `json:"token_ref"`
	SNTable     string   `json:"sn_table"`
	SourceRefs  []string `json:"source_refs"`
}

// TicketStatus is one ticket's approval and state as ServiceNow reports them.
type TicketStatus struct {
	SourceRef string `json:"source_ref"`
	Number    string `json:"number,omitempty"`
	Approval  string `json:"approval"`
	State     string `json:"state,omitempty"`
}

// StatusReport is what a relay returns for a status read.
type StatusReport struct {
	Schedule   string         `json:"schedule,omitempty"`
	StatusID   string         `json:"status_id"`
	ObservedAt time.Time      `json:"observed_at"`
	Tickets    []TicketStatus `json:"tickets"`
}

func validateStatusIntent(intent StatusIntent) error {
	if !ValidScheduleName(intent.Schedule) {
		return errors.New("ticket status: schedule must contain 1-40 lowercase letters, digits, underscores or hyphens")
	}
	if parsed, err := uuid.Parse(intent.StatusID); err != nil || parsed == uuid.Nil {
		return errors.New("ticket status: status_id must be a non-zero UUID")
	}
	if intent.SNTable != StatusTable {
		return errors.New("ticket status: only change_request approvals decide requests")
	}
	if !strings.HasPrefix(strings.TrimSpace(intent.TokenRef), "secret://") {
		return errors.New("ticket status: token_ref must be a secret:// reference")
	}
	if len(intent.SourceRefs) == 0 || len(intent.SourceRefs) > MaxStatusTickets {
		return fmt.Errorf("ticket status: a read names 1 to %d tickets", MaxStatusTickets)
	}
	seen := map[string]bool{}
	for _, ref := range intent.SourceRefs {
		if !ValidSourceRef(ref) || seen[ref] {
			return errors.New("ticket status: source refs must be distinct ServiceNow sys_ids")
		}
		seen[ref] = true
	}
	return nil
}

// StatusEndpoint is the one GET a status read makes: the approval and state of
// exactly the named change requests.
func StatusEndpoint(intent StatusIntent) (string, error) {
	if err := validateStatusIntent(intent); err != nil {
		return "", err
	}
	base, err := url.Parse(strings.TrimSpace(intent.InstanceURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", errors.New("ticket status: instance URL must be absolute")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/now/table/" + StatusTable
	q := url.Values{}
	q.Set("sysparm_query", "sys_idIN"+strings.Join(intent.SourceRefs, ","))
	q.Set("sysparm_fields", "sys_id,number,approval,state")
	q.Set("sysparm_limit", strconv.Itoa(len(intent.SourceRefs)))
	q.Set("sysparm_exclude_reference_link", "true")
	base.RawQuery = q.Encode()
	base.Fragment = ""
	return base.String(), nil
}

// ParseStatusPage reads a status response: only the named tickets, once each.
func ParseStatusPage(r io.Reader, intent StatusIntent) ([]TicketStatus, error) {
	var payload struct {
		Result []map[string]json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(r).Decode(&payload); err != nil {
		return nil, fmt.Errorf("ticket status: parse ServiceNow response: %w", err)
	}
	out := make([]TicketStatus, 0, len(payload.Result))
	for _, raw := range payload.Result {
		out = append(out, TicketStatus{SourceRef: field(raw, "sys_id"), Number: field(raw, "number"),
			Approval: strings.ToLower(field(raw, "approval")), State: field(raw, "state")})
	}
	if err := validateStatuses(intent, out); err != nil {
		return nil, err
	}
	return out, nil
}

func validateStatuses(intent StatusIntent, tickets []TicketStatus) error {
	if len(tickets) > len(intent.SourceRefs) {
		return errors.New("ticket status: the response names more tickets than were asked for")
	}
	asked := map[string]bool{}
	for _, ref := range intent.SourceRefs {
		asked[ref] = true
	}
	seen := map[string]bool{}
	for _, t := range tickets {
		if !asked[t.SourceRef] || seen[t.SourceRef] {
			return errors.New("ticket status: the response names a ticket that was not asked for, or one twice")
		}
		seen[t.SourceRef] = true
		if !approvalPattern.MatchString(t.Approval) || !statePattern.MatchString(t.State) || !numberPattern.MatchString(t.Number) {
			return errors.New("ticket status: a ticket's approval, state or number is not a ServiceNow value")
		}
	}
	return nil
}

// ValidateStatusReport checks a relay's report against its durable intent.
func ValidateStatusReport(intent StatusIntent, report StatusReport) error {
	if err := validateStatusIntent(intent); err != nil {
		return err
	}
	if report.StatusID != intent.StatusID || ScheduleName(report.Schedule) != ScheduleName(intent.Schedule) || report.ObservedAt.IsZero() {
		return errors.New("ticket status: the report is for another read")
	}
	return validateStatuses(intent, report.Tickets)
}
