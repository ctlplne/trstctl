// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
)

// Ticket-driven issuance-request intake (epic I3).
//
// The ticket the requester already filed in the ITSM BECOMES the request:
// origin says which system, ticket_ref names the exact record, and the whole
// existing lifecycle — approval with separation of duties, denial with a
// reason, expiry — applies unchanged. The intake opens requests; it decides
// nothing, exactly as the relay reads observe and decide nothing.

const (
	// ticketIntakeInterval is detection latency for due schedules.
	ticketIntakeInterval = time.Minute
	// ticketIntakePageLimit bounds one sweep's read (AN-7).
	ticketIntakePageLimit = 100
	// ticketIntakeRequestTTL is how long an intake-opened request lives
	// undecided before the existing expiry sweep closes it. Tickets carry
	// their own urgency; a stale unapproved request is the queue's problem to
	// surface, not the intake's to guess about.
	ticketIntakeRequestTTL = 7 * 24 * time.Hour
)

// TicketIntakeResult is what one sweep did, and what it refused to do.
type TicketIntakeResult struct {
	Read    int
	Opened  int
	Already int
	// Skipped counts tickets missing the mapped subject or profile — reported,
	// never guessed at.
	Skipped int
}

// RunTicketIntake is the leader-only ticker.
func (s *Server) RunTicketIntake(ctx context.Context) {
	if s.store == nil || s.orch == nil {
		return
	}
	sweep := func() {
		tenants, err := s.store.TenantsWithEnabledTicketIntake(ctx)
		if err != nil {
			s.logger.Warn("ticket intake: list tenants failed", slog.String("error", err.Error()))
			return
		}
		for _, tenantID := range tenants {
			sched, due, err := s.store.TicketIntakeDue(ctx, tenantID, time.Now())
			if err != nil || !due {
				continue
			}
			res, runErr := s.RunTicketIntakeOnce(ctx, tenantID, sched)
			msg := ""
			if runErr != nil {
				msg = runErr.Error()
				s.logger.Warn("ticket intake failed",
					slog.String("tenant_id", tenantID), slog.String("error", msg))
			} else {
				s.logger.Info("ticket intake complete",
					slog.String("tenant_id", tenantID),
					slog.Int("read", res.Read), slog.Int("opened", res.Opened),
					slog.Int("already", res.Already), slog.Int("skipped", res.Skipped))
			}
			if err := s.store.MarkTicketIntakeRun(ctx, tenantID, sched.System, time.Now().UTC(), msg); err != nil {
				s.logger.Warn("ticket intake: stamp failed",
					slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
			}
		}
	}
	sweep()
	tk := time.NewTicker(ticketIntakeInterval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			sweep()
		}
	}
}

// RunTicketIntakeOnce reads one page of tickets and opens requests.
func (s *Server) RunTicketIntakeOnce(ctx context.Context, tenantID string, sched store.TicketIntakeSchedule) (TicketIntakeResult, error) {
	var out TicketIntakeResult
	rows, err := s.fetchTicketRows(ctx, sched)
	if err != nil {
		return out, err
	}
	out.Read = len(rows)
	for _, row := range rows {
		sysID := ticketField(row, "sys_id")
		subject := ticketField(row, sched.SubjectField)
		profile := ticketField(row, sched.ProfileField)
		if sysID == "" {
			out.Skipped++
			continue
		}
		if subject == "" || profile == "" {
			// The mapped field is empty on this ticket. Guessing a subject
			// from a description column would open requests for prose;
			// skipping AND COUNTING is what lets an operator see the mapping
			// is wrong rather than wondering where their tickets went.
			out.Skipped++
			continue
		}
		ticketRef := sched.SNTable + ":" + sysID
		exists, err := s.store.IssuanceRequestExistsForTicket(ctx, tenantID, ticketRef)
		if err != nil {
			return out, err
		}
		if exists {
			// One ticket, one request, however many polls see it. A denied
			// request does NOT reopen: the denial was the answer to that
			// ticket, and a fresh ask needs a fresh ticket.
			out.Already++
			continue
		}
		requester := ticketField(row, sched.RequesterField)
		if requester == "" {
			// The lifecycle's separation-of-duties check needs a requester.
			// The ticket system is the closest attributable actor when the
			// ticket does not name one.
			requester = "servicenow:" + sched.SNTable
		}
		if _, err := s.orch.OpenIssuanceRequest(ctx, tenantID, projections.IssuanceRequestOpened{
			Subject:       subject,
			Profile:       profile,
			Requester:     requester,
			Justification: ticketField(row, sched.JustificationField),
			Origin:        "servicenow",
			TicketRef:     ticketRef,
			ExpiresAt:     time.Now().UTC().Add(ticketIntakeRequestTTL),
		}); err != nil {
			return out, err
		}
		out.Opened++
	}
	return out, nil
}

// fetchTicketRows reads one page from the ITSM. GET only, against a table the
// schema CHECK already bounded, through the same binding/egress rules the
// other ServiceNow reads use.
func (s *Server) fetchTicketRows(ctx context.Context, sched store.TicketIntakeSchedule) ([]map[string]json.RawMessage, error) {
	base, err := url.Parse(strings.TrimSpace(sched.InstanceURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("server: ticket intake instance URL must be absolute")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/now/table/" + sched.SNTable
	q := url.Values{}
	q.Set("sysparm_display_value", "all")
	q.Set("sysparm_limit", fmt.Sprintf("%d", ticketIntakePageLimit))
	if trimmed := strings.TrimSpace(sched.Query); trimmed != "" {
		q.Set("sysparm_query", trimmed)
	}
	base.RawQuery = q.Encode()
	base.Fragment = ""
	endpoint := base.String()

	client, err := cloudHTTPClient(endpoint, sched.AllowPrivateEndpoint, sched.PrivateEgressCIDRs)
	if err != nil {
		return nil, fmt.Errorf("server: ticket intake endpoint rejected: %w", err)
	}
	token, err := resolveDiscoveryCredentialRef(ctx, sched.TokenRef)
	if err != nil {
		return nil, fmt.Errorf("server: resolve ticket intake token ref: %w", err)
	}
	tokenBytes := []byte(token)
	defer secret.Wipe(tokenBytes)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", tokenBytes))
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("server: read tickets: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("server: ticket read failed with status %d: %s",
			resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	var payload struct {
		Result []map[string]json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("server: parse tickets: %w", err)
	}
	return payload.Result, nil
}

// ticketField extracts one field, handling both ServiceNow shapes: a plain
// string, and the {display_value, value} object display_value=all returns.
// The DISPLAY value wins for reference fields — a sys_id in a requester column
// is a value nobody can route an approval to.
func ticketField(row map[string]json.RawMessage, name string) string {
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
	var obj struct {
		DisplayValue string `json:"display_value"`
		Value        string `json:"value"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		if v := strings.TrimSpace(obj.DisplayValue); v != "" {
			return v
		}
		return strings.TrimSpace(obj.Value)
	}
	return ""
}
