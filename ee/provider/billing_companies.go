// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	corestore "trstctl.com/trstctl/internal/store"
)

// MSP-2: each customer's company in each billing or PSA system the deployment
// pushes usage to. The deployment config names the targets
// (provider.billing_sync.targets); a Provider operator maps a delegated
// customer to its company in a target, recorded as an immutable authority
// event and projected into provider_billing_companies. A customer's closed,
// signed usage periods go only to the company its own mapping names, and one
// company in one target belongs to one customer.

const (
	EventTenantBillingCompanySet     = "provider.tenant.billing_company.set"
	EventTenantBillingCompanyCleared = "provider.tenant.billing_company.cleared"
)

var (
	// ErrBillingCompanyConflict refuses mapping a company that another
	// customer already holds in the same target: that customer's counts and
	// this one's would reach the same company.
	ErrBillingCompanyConflict = errors.New("provider: this company is already mapped to another customer in this billing target")
	// ErrBillingTargetUnknown refuses a target the deployment does not
	// configure.
	ErrBillingTargetUnknown = errors.New("provider: no billing target with this ID is configured on this deployment")
)

// maxExternalCompanyID bounds a target's company identifier.
const maxExternalCompanyID = 128

// BillingTarget is one configured billing system, as the plane describes it
// (never its endpoint or credentials).
type BillingTarget struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Type    string `json:"type"`
	Cadence string `json:"cadence"`
	// Tickets says the target opens service tickets for customers' alerts
	// (MSP-3).
	Tickets bool `json:"tickets,omitempty"`
	// RMM says the target runs the agent through an RMM (MSP-9).
	RMM bool `json:"rmm,omitempty"`
}

// BillingCompany is one customer's company in one billing target.
type BillingCompany struct {
	TenantID          string    `json:"tenant_id"`
	TargetID          string    `json:"target_id"`
	ExternalCompanyID string    `json:"external_company_id,omitempty"`
	MappedBy          string    `json:"mapped_by,omitempty"`
	MappedAt          time.Time `json:"mapped_at,omitzero"`
}

// BillingCompanyStore reads the projected mappings and fences a mapping
// change with the Provider authority projection, so the check that no other
// customer holds a company and the event that maps it cannot interleave with
// another mapping.
type BillingCompanyStore interface {
	BillingCompanies(ctx context.Context, customerID string) ([]BillingCompany, error)
	BillingCompanyOwner(ctx context.Context, targetID, externalCompanyID string) (string, error)
	WithMappingFence(ctx context.Context, fn func(context.Context) error) error
}

// PGBillingCompanyStore reads provider_billing_companies.
type PGBillingCompanyStore struct{ store *corestore.Store }

// NewPGBillingCompanyStore returns the durable mapping store, or nil.
func NewPGBillingCompanyStore(store *corestore.Store) *PGBillingCompanyStore {
	if store == nil {
		return nil
	}
	return &PGBillingCompanyStore{store: store}
}

// BillingCompanies lists one customer's mappings under its own tenant.
func (p *PGBillingCompanyStore) BillingCompanies(ctx context.Context, customerID string) ([]BillingCompany, error) {
	if p == nil || p.store == nil || strings.TrimSpace(customerID) == "" {
		return nil, errors.New("provider: durable billing company store or customer is unavailable")
	}
	var out []BillingCompany
	err := p.store.WithTenant(ctx, customerID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text, target_id, external_company_id, mapped_by, mapped_at
			FROM provider_billing_companies WHERE tenant_id = $1 ORDER BY target_id`, customerID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c BillingCompany
			if err := rows.Scan(&c.TenantID, &c.TargetID, &c.ExternalCompanyID, &c.MappedBy, &c.MappedAt); err != nil {
				return err
			}
			c.MappedAt = c.MappedAt.UTC()
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// BillingCompanyOwner names the customer that holds a company in a target,
// or "" when none does.
func (p *PGBillingCompanyStore) BillingCompanyOwner(ctx context.Context, targetID, externalCompanyID string) (string, error) {
	if p == nil || p.store == nil {
		return "", errors.New("provider: durable billing company store is unavailable")
	}
	var owner string
	//trstctl:system-query — the one-company-one-customer check must see every customer's mapping; it reads only the owning tenant ID.
	err := p.store.SystemPool().QueryRow(ctx, `SELECT tenant_id::text FROM provider_billing_companies
		WHERE target_id = $1 AND external_company_id = $2`, targetID, externalCompanyID).Scan(&owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return owner, err
}

// WithMappingFence runs fn inside the Provider authority fence; the event
// append inside it re-enters the same fence.
func (p *PGBillingCompanyStore) WithMappingFence(ctx context.Context, fn func(context.Context) error) error {
	if p == nil || p.store == nil {
		return errors.New("provider: durable billing company store is unavailable")
	}
	return withAuthorityFence(ctx, p.store, fn)
}

// normalizeExternalCompanyID trims a company identifier and refuses an empty,
// over-long or control-character one.
func normalizeExternalCompanyID(raw string) (string, error) {
	id := strings.TrimSpace(raw)
	if id == "" || len(id) > maxExternalCompanyID {
		return "", fmt.Errorf("provider: external_company_id must be 1-%d characters", maxExternalCompanyID)
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return "", errors.New("provider: external_company_id must not contain control characters")
		}
	}
	return id, nil
}

func (s *Service) billingTarget(id string) (BillingTarget, bool) {
	for _, t := range s.billingTargets {
		if t.ID == id {
			return t, true
		}
	}
	return BillingTarget{}, false
}

// BillingTargets lists the configured targets, sorted by ID.
func (s *Service) BillingTargets() []BillingTarget {
	out := append([]BillingTarget(nil), s.billingTargets...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Service) requireBillingCompanies() error {
	if s.billingCompanies == nil || s.mutations == nil {
		return fmt.Errorf("%w: no durable billing company store is attached on this deployment", ErrForbidden)
	}
	return nil
}

// SetTenantBillingCompany maps a delegated customer to its company in one
// configured billing target. Mapping the same company again is a no-op
// replay; mapping a company another customer holds is refused.
func (s *Service) SetTenantBillingCompany(ctx context.Context, actor Operator, customerID, targetID, externalCompanyID string) error {
	if err := s.requirePermission(ctx, actor, PermBillingWrite); err != nil {
		return err
	}
	if err := s.authorize(ctx, actor, customerID, OpProvision); err != nil {
		return err
	}
	if _, ok := s.billingTarget(targetID); !ok {
		return ErrBillingTargetUnknown
	}
	company, err := normalizeExternalCompanyID(externalCompanyID)
	if err != nil {
		return err
	}
	if err := s.requireBillingCompanies(); err != nil {
		return err
	}
	now := s.clock()
	return s.billingCompanies.WithMappingFence(ctx, func(ctx context.Context) error {
		owner, err := s.billingCompanies.BillingCompanyOwner(ctx, targetID, company)
		if err != nil {
			return err
		}
		if owner != "" && owner != customerID {
			return ErrBillingCompanyConflict
		}
		mapping := BillingCompany{TenantID: customerID, TargetID: targetID, ExternalCompanyID: company, MappedBy: actor.Email}
		_, err = s.emit(ctx, EventTenantBillingCompanySet, customerID, AuthorityEvent{BillingCompany: &mapping,
			Audit: AuditEvent{Type: EventTenantBillingCompanySet, TenantID: customerID,
				OperatorID: actor.ID, OperatorEmail: actor.Email, Reason: "billing target " + targetID, At: now}})
		return err
	})
}

// ClearTenantBillingCompany removes a customer's mapping in one target; its
// periods are no longer pushed there.
func (s *Service) ClearTenantBillingCompany(ctx context.Context, actor Operator, customerID, targetID string) error {
	if err := s.requirePermission(ctx, actor, PermBillingWrite); err != nil {
		return err
	}
	if err := s.authorize(ctx, actor, customerID, OpProvision); err != nil {
		return err
	}
	if _, ok := s.billingTarget(targetID); !ok {
		return ErrBillingTargetUnknown
	}
	if err := s.requireBillingCompanies(); err != nil {
		return err
	}
	mapping := BillingCompany{TenantID: customerID, TargetID: targetID, MappedBy: actor.Email}
	_, err := s.emit(ctx, EventTenantBillingCompanyCleared, customerID, AuthorityEvent{BillingCompany: &mapping,
		Audit: AuditEvent{Type: EventTenantBillingCompanyCleared, TenantID: customerID,
			OperatorID: actor.ID, OperatorEmail: actor.Email, Reason: "billing target " + targetID, At: s.clock()}})
	return err
}

// TenantBillingCompanies is a customer's view: every configured target with
// the company it is mapped to there, if any.
type TenantBillingCompanies struct {
	Targets   []BillingTarget  `json:"targets"`
	Companies []BillingCompany `json:"companies"`
}

// ListTenantBillingCompanies reads a delegated customer's mappings.
func (s *Service) ListTenantBillingCompanies(ctx context.Context, actor Operator, customerID string) (TenantBillingCompanies, error) {
	if err := s.requireOperator(actor); err != nil {
		return TenantBillingCompanies{}, err
	}
	if err := s.authorize(ctx, actor, customerID, OpRead); err != nil {
		return TenantBillingCompanies{}, err
	}
	out := TenantBillingCompanies{Targets: s.BillingTargets(), Companies: []BillingCompany{}}
	if s.billingCompanies == nil {
		return out, nil
	}
	companies, err := s.billingCompanies.BillingCompanies(ctx, customerID)
	if err != nil {
		return TenantBillingCompanies{}, err
	}
	if companies != nil {
		out.Companies = companies
	}
	return out, nil
}

// applyBillingCompany projects a mapping event.
func applyBillingCompany(ctx context.Context, tx pgx.Tx, eventType, eventTenant string, payload AuthorityEvent, effectiveAt time.Time) error {
	c := payload.BillingCompany
	if c == nil || c.TenantID == "" || c.TenantID != eventTenant || !billingTargetIDValid(c.TargetID) {
		return fmt.Errorf("provider: %s needs the mapping of its own customer", eventType)
	}
	if eventType == EventTenantBillingCompanyCleared {
		//trstctl:system-query — customer-keyed mapping written by the trusted Provider projection; the event's tenant names the row.
		_, err := tx.Exec(ctx, `DELETE FROM provider_billing_companies WHERE tenant_id = $1 AND target_id = $2`, c.TenantID, c.TargetID)
		return err
	}
	if _, err := normalizeExternalCompanyID(c.ExternalCompanyID); err != nil {
		return err
	}
	//trstctl:system-query — customer-keyed mapping written by the trusted Provider projection; the event's tenant names the row.
	_, err := tx.Exec(ctx, `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, target_id) DO UPDATE SET external_company_id = EXCLUDED.external_company_id,
		mapped_by = EXCLUDED.mapped_by, mapped_at = EXCLUDED.mapped_at`,
		c.TenantID, c.TargetID, c.ExternalCompanyID, c.MappedBy, effectiveAt)
	return err
}

func billingTargetIDValid(id string) bool {
	if id == "" || len(id) > 63 || id[0] == '-' {
		return false
	}
	for _, r := range id {
		lower, digit := r >= 'a' && r <= 'z', r >= '0' && r <= '9'
		if !lower && !digit && r != '-' {
			return false
		}
	}
	return true
}

// BillingSyncPush is one customer's usage period in one target as the plane
// shows it (MSP-2): queued, held with its reason, delivered or failed.
type BillingSyncPush struct {
	TargetID          string    `json:"target_id"`
	PeriodStart       time.Time `json:"period_start"`
	PeriodEnd         time.Time `json:"period_end"`
	Status            string    `json:"status"`
	ExternalCompanyID string    `json:"external_company_id,omitempty"`
	EvidenceDigest    string    `json:"evidence_digest,omitempty"`
	Reason            string    `json:"reason,omitempty"`
	ResponseStatus    int       `json:"response_status,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// PSATicket is one alert subject's service ticket in a PSA target as the
// plane shows it (MSP-3): opening, open (with the PSA's ticket ID and the
// notes later alerts added), closing, closed, or failed with the reason.
type PSATicket struct {
	TargetID          string     `json:"target_id"`
	AlertKind         string     `json:"alert_kind"`
	Subject           string     `json:"subject"`
	Generation        int        `json:"generation"`
	Status            string     `json:"status"`
	ExternalCompanyID string     `json:"external_company_id"`
	ExternalTicketID  string     `json:"external_ticket_id,omitempty"`
	Summary           string     `json:"summary,omitempty"`
	Notes             int        `json:"notes"`
	Reason            string     `json:"reason,omitempty"`
	OpenedAt          *time.Time `json:"opened_at,omitempty"`
	ClosedAt          *time.Time `json:"closed_at,omitempty"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// PSATicketReader reads a customer's PSA tickets.
type PSATicketReader interface {
	PSATickets(ctx context.Context, tenantID string, limit int) ([]corestore.PSATicket, error)
}

// ListTenantPSATickets reads a delegated customer's PSA tickets, most
// recently changed first.
func (s *Service) ListTenantPSATickets(ctx context.Context, actor Operator, customerID string) ([]PSATicket, error) {
	if err := s.requireOperator(actor); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, actor, customerID, OpRead); err != nil {
		return nil, err
	}
	out := []PSATicket{}
	if s.psaTickets == nil {
		return out, nil
	}
	rows, err := s.psaTickets.PSATickets(ctx, customerID, 100)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		kind, subject, _ := strings.Cut(r.AlertKey, ":")
		out = append(out, PSATicket{TargetID: r.TargetID, AlertKind: kind, Subject: subject, Generation: r.Generation, Status: r.Status,
			ExternalCompanyID: r.ExternalCompanyID, ExternalTicketID: r.ExternalTicketID, Summary: r.Summary, Notes: r.Notes,
			Reason: r.Reason, OpenedAt: r.OpenedAt, ClosedAt: r.ClosedAt, UpdatedAt: r.UpdatedAt})
	}
	return out, nil
}

// RMMDevice is one device an RMM lists under a customer's organization, as
// the plane shows it (MSP-9): its agent (and how it matched), the health
// last reported back, and the agent action last run through the RMM.
type RMMDevice struct {
	TargetID     string    `json:"target_id"`
	DeviceID     string    `json:"device_id"`
	DeviceName   string    `json:"device_name,omitempty"`
	OrgID        string    `json:"org_id,omitempty"`
	Present      bool      `json:"present"`
	AgentID      string    `json:"agent_id,omitempty"`
	AgentMatch   string    `json:"agent_match,omitempty"`
	Health       string    `json:"health,omitempty"`
	Action       string    `json:"action,omitempty"`
	ActionStatus string    `json:"action_status,omitempty"`
	ActionReason string    `json:"action_reason,omitempty"`
	ActionBy     string    `json:"action_by,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RMMDeviceReader reads a customer's RMM devices.
type RMMDeviceReader interface {
	RMMDevices(ctx context.Context, tenantID string, limit int) ([]corestore.RMMDevice, error)
}

// ListTenantRMMDevices reads a delegated customer's RMM devices.
func (s *Service) ListTenantRMMDevices(ctx context.Context, actor Operator, customerID string) ([]RMMDevice, error) {
	if err := s.requireOperator(actor); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, actor, customerID, OpRead); err != nil {
		return nil, err
	}
	out := []RMMDevice{}
	if s.rmmDevices == nil {
		return out, nil
	}
	rows, err := s.rmmDevices.RMMDevices(ctx, customerID, 2000)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, RMMDevice{TargetID: r.TargetID, DeviceID: r.DeviceID, DeviceName: r.DeviceName, OrgID: r.OrgID, Present: r.Present,
			AgentID: r.AgentID, AgentMatch: r.AgentMatch, Health: r.Health, Action: r.Action, ActionStatus: r.ActionStatus,
			ActionReason: r.ActionReason, ActionBy: r.ActionBy, UpdatedAt: r.UpdatedAt})
	}
	return out, nil
}

// BillingSyncPushReader reads a customer's recorded pushes.
type BillingSyncPushReader interface {
	BillingSyncPushes(ctx context.Context, tenantID string, limit int) ([]corestore.BillingSyncPush, error)
}

// ListTenantBillingSyncPushes reads a delegated customer's recent pushes,
// newest period first.
func (s *Service) ListTenantBillingSyncPushes(ctx context.Context, actor Operator, customerID string) ([]BillingSyncPush, error) {
	if err := s.requireOperator(actor); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, actor, customerID, OpRead); err != nil {
		return nil, err
	}
	out := []BillingSyncPush{}
	if s.billingSyncPushes == nil {
		return out, nil
	}
	rows, err := s.billingSyncPushes.BillingSyncPushes(ctx, customerID, 100)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, BillingSyncPush{TargetID: r.TargetID, PeriodStart: r.PeriodStart, PeriodEnd: r.PeriodEnd, Status: r.Status,
			ExternalCompanyID: r.ExternalCompanyID, EvidenceDigest: r.EvidenceDigest, Reason: r.Reason,
			ResponseStatus: r.ResponseStatus, UpdatedAt: r.UpdatedAt})
	}
	return out, nil
}
