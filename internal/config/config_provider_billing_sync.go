// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ProviderBillingSync configures where the Provider plane pushes each
// customer's closed, signed usage periods (MSP-2): the operator's billing or
// PSA systems. A customer is pushed to a target only after a Provider operator
// maps it to its company there; the deployment config names the targets, the
// Provider plane owns the mappings.
type ProviderBillingSync struct {
	Targets []ProviderBillingTarget `json:"targets,omitempty"`
}

// ProviderBillingTarget is one external billing system. Type "json" is the
// generic signed JSON push of the billing-sync core; vendor PSA types arrive
// with their own connectors. Credentials are references resolved for each
// delivery, never values in config.
type ProviderBillingTarget struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name,omitempty"`
	Endpoint string `json:"endpoint"`
	// TokenRef is an optional bearer token reference; SigningKeyRef the HMAC
	// key reference every push is signed with (X-Trstctl-Signature).
	TokenRef      string `json:"token_ref,omitempty"`
	SigningKeyRef string `json:"signing_key_ref,omitempty"`
	// Cadence is the usage period pushed: "monthly" (the default) or "daily",
	// in whole UTC calendar periods.
	Cadence               string   `json:"cadence,omitempty"`
	AllowPrivateEndpoint  bool     `json:"allow_private_endpoint,omitempty"`
	AllowInsecureLoopback bool     `json:"allow_insecure_loopback,omitempty"`
	PrivateEgressCIDRs    []string `json:"private_egress_cidrs,omitempty"`
	// ConnectWise configures a "connectwise" target (MSP-3): each customer's
	// figures land as additions of its company's one active agreement of
	// AgreementType. Endpoint is the site's REST root,
	// https://{host}/{codebase}/apis/3.0.
	ConnectWise *ConnectWiseBillingTarget `json:"connectwise,omitempty"`
	// Autotask configures an "autotask" target (MSP-4): each customer's
	// figures become the whole units of its company's Recurring Service
	// contract services. Endpoint is the zone's REST root,
	// https://webservicesN.autotask.net/atservicesrest/v1.0.
	Autotask *AutotaskBillingTarget `json:"autotask,omitempty"`
	// Syncro configures a "syncro" target (MSP-6): each customer's figures
	// become the line quantities of its one active recurring invoice
	// schedule. Endpoint is the account's API root,
	// https://{subdomain}.syncromsp.com/api/v1.
	Syncro *SyncroBillingTarget `json:"syncro,omitempty"`
	// HaloPSA configures a "halopsa" target (MSP-5): each customer's
	// figures become the line quantities of its client's recurring invoice.
	// Endpoint is the instance root, https://{instance}.halopsa.com.
	HaloPSA *HaloPSABillingTarget `json:"halopsa,omitempty"`
	// Gradient configures a "gradient" target (MSP-7): each customer's
	// figures become its account's counts of Gradient services, which
	// Gradient forwards to the MSP's PSA. Endpoint is the API root,
	// https://app.usegradient.com.
	Gradient *GradientBillingTarget `json:"gradient,omitempty"`
}

// GradientBillingTarget is a Gradient Synthesize vendor integration.
type GradientBillingTarget struct {
	// TokenRef names the GRADIENT-TOKEN value the MSP's Gradient account
	// issues for this integration (file: or env:).
	TokenRef string `json:"token_ref"`
	// Services maps a meter to the Gradient service (SKU) ID whose count
	// carries it.
	Services map[string]string `json:"services"`
}

// HaloPSABillingTarget is a HaloPSA instance the Provider pushes usage to.
type HaloPSABillingTarget struct {
	// Tenant is the hosted tenant name of the token request; empty for a
	// self-hosted instance.
	Tenant string `json:"tenant,omitempty"`
	// ClientID is the API application's client ID; ClientSecretRef names
	// its client secret (file: or env:), resolved for each delivery.
	ClientID        string `json:"client_id"`
	ClientSecretRef string `json:"client_secret_ref"`
	// RecurringInvoiceName, when set, picks the recurring invoice among a
	// client's recurring invoices.
	RecurringInvoiceName string `json:"recurring_invoice_name,omitempty"`
	// Items maps a meter to the HaloPSA item ID whose line carries it.
	Items map[string]int64 `json:"items"`
	// Tickets, when set, opens a ticket for the customer's alerts (MSP-5).
	Tickets *HaloPSATickets `json:"tickets,omitempty"`
}

// HaloPSATickets is the ticket type and status IDs of alert tickets.
type HaloPSATickets struct {
	TicketTypeID   int64    `json:"ticket_type_id"`
	StatusNewID    int64    `json:"status_new_id,omitempty"`
	StatusClosedID int64    `json:"status_closed_id"`
	Kinds          []string `json:"kinds,omitempty"`
}

// SyncroBillingTarget is a Syncro account the Provider pushes usage to.
type SyncroBillingTarget struct {
	// APITokenRef names the API token (file: or env:), resolved for each
	// delivery and sent only in the Authorization header.
	APITokenRef string `json:"api_token_ref"`
	// ScheduleName, when set, picks the schedule among a customer's active
	// recurring invoice schedules.
	ScheduleName string `json:"schedule_name,omitempty"`
	// Products maps a meter to the Syncro product ID whose line carries it.
	Products map[string]int64 `json:"products"`
	// Tickets, when set, opens a ticket for the customer's alerts (MSP-6).
	Tickets *SyncroTickets `json:"tickets,omitempty"`
}

// SyncroTickets is the problem type and statuses of alert tickets.
type SyncroTickets struct {
	ProblemType  string   `json:"problem_type"`
	StatusNew    string   `json:"status_new,omitempty"`
	StatusClosed string   `json:"status_closed,omitempty"`
	Kinds        []string `json:"kinds,omitempty"`
}

// EffectiveStatusNew is the status a ticket opens with, "New" when unset.
func (t SyncroTickets) EffectiveStatusNew() string {
	if t.StatusNew != "" {
		return t.StatusNew
	}
	return "New"
}

// EffectiveStatusClosed is the status that closes a ticket, "Resolved"
// when unset.
func (t SyncroTickets) EffectiveStatusClosed() string {
	if t.StatusClosed != "" {
		return t.StatusClosed
	}
	return "Resolved"
}

// AutotaskBillingTarget is an Autotask PSA zone the Provider pushes usage to.
type AutotaskBillingTarget struct {
	// Username is the API user.
	Username string `json:"username"`
	// SecretRef names the API user's secret and IntegrationCodeRef the
	// integration's tracking identifier (file: or env:), resolved for each
	// delivery.
	SecretRef          string `json:"secret_ref"`
	IntegrationCodeRef string `json:"integration_code_ref"`
	// ContractName, when set, picks the contract among a company's current
	// Recurring Service contracts.
	ContractName string `json:"contract_name,omitempty"`
	// Services maps a meter to the Autotask service ID whose units carry
	// it. A meter without a service is not pushed.
	Services map[string]int64 `json:"services"`
	// Tickets, when set, opens a ticket under the customer's company for
	// its alerts (MSP-4).
	Tickets *AutotaskTickets `json:"tickets,omitempty"`
}

// AutotaskTickets holds the zone's picklist values for alert tickets.
type AutotaskTickets struct {
	QueueID        int64    `json:"queue_id,omitempty"`
	StatusNew      int64    `json:"status_new"`
	StatusComplete int64    `json:"status_complete"`
	Priority       int64    `json:"priority"`
	NoteType       int64    `json:"note_type,omitempty"`
	NotePublish    int64    `json:"note_publish,omitempty"`
	Kinds          []string `json:"kinds,omitempty"`
}

// EffectiveNoteType and EffectiveNotePublish default the note picklists to 1.
func (t AutotaskTickets) EffectiveNoteType() int64 {
	if t.NoteType > 0 {
		return t.NoteType
	}
	return 1
}

// EffectiveNotePublish is the note publish picklist value, 1 when unset.
func (t AutotaskTickets) EffectiveNotePublish() int64 {
	if t.NotePublish > 0 {
		return t.NotePublish
	}
	return 1
}

// TicketKinds is the alert kinds this target opens tickets for; nil when it
// opens none.
func (t ProviderBillingTarget) TicketKinds() []string {
	switch {
	case t.ConnectWise != nil && t.ConnectWise.Tickets != nil:
		return t.ConnectWise.Tickets.EffectiveKinds()
	case t.Autotask != nil && t.Autotask.Tickets != nil:
		if len(t.Autotask.Tickets.Kinds) == 0 {
			return append([]string(nil), PSATicketAlertKinds...)
		}
		return append([]string(nil), t.Autotask.Tickets.Kinds...)
	case t.Syncro != nil && t.Syncro.Tickets != nil:
		if len(t.Syncro.Tickets.Kinds) == 0 {
			return append([]string(nil), PSATicketAlertKinds...)
		}
		return append([]string(nil), t.Syncro.Tickets.Kinds...)
	case t.HaloPSA != nil && t.HaloPSA.Tickets != nil:
		if len(t.HaloPSA.Tickets.Kinds) == 0 {
			return append([]string(nil), PSATicketAlertKinds...)
		}
		return append([]string(nil), t.HaloPSA.Tickets.Kinds...)
	}
	return nil
}

// ConnectWiseBillingTarget is a ConnectWise PSA site the Provider pushes
// usage to.
type ConnectWiseBillingTarget struct {
	// CompanyID is the PSA login company the API member belongs to (the
	// first part of its Basic credentials), not a customer's company.
	CompanyID string `json:"company_id"`
	// ClientID is the integration's clientId: it identifies the
	// integration to ConnectWise; it does not authenticate.
	ClientID string `json:"client_id"`
	// PublicKeyRef and PrivateKeyRef name the API member's keys (file: or
	// env:), resolved for each delivery.
	PublicKeyRef  string `json:"public_key_ref"`
	PrivateKeyRef string `json:"private_key_ref"`
	// AgreementType names the agreement type each mapped company has one
	// active agreement of.
	AgreementType string `json:"agreement_type"`
	// Products maps a meter (certificates_current, agents, secrets_stored)
	// to the catalog identifier of its addition. A meter without a product
	// is not pushed.
	Products map[string]string `json:"products"`
	// Tickets, when set, opens a service ticket under the customer's
	// company for its alerts, notes later alerts on it and closes it when
	// the alert's condition clears (MSP-3).
	Tickets *ConnectWiseTickets `json:"tickets,omitempty"`
}

// ConnectWiseTickets configures alert tickets on a ConnectWise site.
type ConnectWiseTickets struct {
	// Board is the service board the tickets open on.
	Board string `json:"board"`
	// NewStatus is the status a ticket opens with; empty takes the board's
	// default.
	NewStatus string `json:"new_status,omitempty"`
	// ClosedStatus is the board's status that closes a ticket.
	ClosedStatus string `json:"closed_status"`
	// Kinds limits the alert kinds that open tickets; empty means all of
	// PSATicketAlertKinds.
	Kinds []string `json:"kinds,omitempty"`
}

// PSATicketAlertKinds are the alert kinds a PSA target can open tickets for:
// certificate expiry, a failed renewal, an unhealthy revocation endpoint and
// credential drift.
var PSATicketAlertKinds = []string{"certificate.expiry", "identity.renewal_failed", "revocation.health", "credential.drift"}

// EffectiveKinds is the alert kinds that open tickets.
func (t ConnectWiseTickets) EffectiveKinds() []string {
	if len(t.Kinds) == 0 {
		return append([]string(nil), PSATicketAlertKinds...)
	}
	return append([]string(nil), t.Kinds...)
}

// BillingSyncMeters are the meters a period push carries.
var BillingSyncMeters = []string{"agents", "certificates_current", "secrets_stored"}

var (
	connectWiseCompanyPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	connectWiseClientPattern  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// connectWiseConditionValue is what may sit inside a quoted conditions
	// value: the published grammar shows no escaping.
	connectWiseConditionValue = regexp.MustCompile(`^[A-Za-z0-9 _.,:;/()&@#+-]{1,100}$`)
)

// BillingTargetIDPattern is a target ID: lowercase, digits and dashes.
var BillingTargetIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ProviderBillingTargetTypes are the target types this build can push to.
var ProviderBillingTargetTypes = map[string]struct{}{"json": {}, "connectwise": {}, "autotask": {}, "syncro": {}, "halopsa": {}, "gradient": {}}

// EffectiveCadence is the target's cadence, monthly when unset.
func (t ProviderBillingTarget) EffectiveCadence() string {
	if c := strings.TrimSpace(t.Cadence); c != "" {
		return c
	}
	return "monthly"
}

// Target returns the configured target with this ID.
func (b ProviderBillingSync) Target(id string) (ProviderBillingTarget, bool) {
	for _, t := range b.Targets {
		if t.ID == id {
			return t, true
		}
	}
	return ProviderBillingTarget{}, false
}

func validateProviderBillingSync(b ProviderBillingSync) []error {
	var errs []error
	seen := map[string]bool{}
	for i, t := range b.Targets {
		where := fmt.Sprintf("provider.billing_sync.targets[%d]", i)
		if !BillingTargetIDPattern.MatchString(t.ID) {
			errs = append(errs, fmt.Errorf("%s.id must be 1-63 lowercase letters, digits or dashes", where))
		} else if seen[t.ID] {
			errs = append(errs, fmt.Errorf("%s.id %q is listed twice", where, t.ID))
		}
		seen[t.ID] = true
		if _, ok := ProviderBillingTargetTypes[t.Type]; !ok {
			errs = append(errs, fmt.Errorf("%s.type %q is not a billing target type this build pushes to (json, connectwise, autotask, syncro, halopsa, gradient)", where, t.Type))
		}
		if len(t.Name) > 128 {
			errs = append(errs, fmt.Errorf("%s.name is longer than 128 characters", where))
		}
		u, err := url.Parse(strings.TrimSpace(t.Endpoint))
		switch {
		case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http"):
			errs = append(errs, fmt.Errorf("%s.endpoint must be an absolute https URL", where))
		case u.Scheme == "http" && !t.AllowInsecureLoopback:
			errs = append(errs, fmt.Errorf("%s.endpoint must use https (http only with allow_insecure_loopback for a loopback test receiver)", where))
		case u.User != nil:
			errs = append(errs, fmt.Errorf("%s.endpoint must not carry credentials; use token_ref", where))
		}
		switch t.Type {
		case "json":
			errs = append(errs, validateJSONBillingTarget(where, t)...)
		case "connectwise":
			errs = append(errs, validateConnectWiseBillingTarget(where, t)...)
		case "autotask":
			errs = append(errs, validateAutotaskBillingTarget(where, t)...)
		case "syncro":
			errs = append(errs, validateSyncroBillingTarget(where, t)...)
		case "halopsa":
			errs = append(errs, validateHaloPSABillingTarget(where, t)...)
		case "gradient":
			errs = append(errs, validateGradientBillingTarget(where, t)...)
		}
		if t.Type != "gradient" && t.Gradient != nil {
			errs = append(errs, fmt.Errorf("%s.gradient applies to gradient targets only", where))
		}
		if t.Type != "halopsa" && t.HaloPSA != nil {
			errs = append(errs, fmt.Errorf("%s.halopsa applies to halopsa targets only", where))
		}
		if t.Type != "autotask" && t.Autotask != nil {
			errs = append(errs, fmt.Errorf("%s.autotask applies to autotask targets only", where))
		}
		if t.Type != "syncro" && t.Syncro != nil {
			errs = append(errs, fmt.Errorf("%s.syncro applies to syncro targets only", where))
		}
		switch t.EffectiveCadence() {
		case "monthly", "daily":
		default:
			errs = append(errs, fmt.Errorf("%s.cadence must be monthly or daily", where))
		}
		if t.AllowPrivateEndpoint && len(t.PrivateEgressCIDRs) == 0 {
			errs = append(errs, errors.New(where+".private_egress_cidrs must name the approved private destinations when allow_private_endpoint is set"))
		}
	}
	return errs
}

func validateJSONBillingTarget(where string, t ProviderBillingTarget) []error {
	var errs []error
	if strings.TrimSpace(t.SigningKeyRef) == "" {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref is required: every push is HMAC-signed so the receiver can refuse a changed or replayed period", where))
	} else if err := validateDeploymentCredentialRef(t.SigningKeyRef); err != nil {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref: %w", where, err))
	}
	if strings.TrimSpace(t.TokenRef) != "" {
		if err := validateDeploymentCredentialRef(t.TokenRef); err != nil {
			errs = append(errs, fmt.Errorf("%s.token_ref: %w", where, err))
		}
	}
	if t.ConnectWise != nil {
		errs = append(errs, fmt.Errorf("%s.connectwise applies to connectwise targets only", where))
	}
	return errs
}

var haloTenantPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// gradientServicePattern is a Gradient service ID as it sits in a URL path.
var gradientServicePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func validateGradientBillingTarget(where string, t ProviderBillingTarget) []error {
	var errs []error
	if strings.TrimSpace(t.SigningKeyRef) != "" || strings.TrimSpace(t.TokenRef) != "" {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref and token_ref apply to json targets only; a gradient target authenticates with gradient.token_ref", where))
	}
	if t.ConnectWise != nil {
		errs = append(errs, fmt.Errorf("%s.connectwise applies to connectwise targets only", where))
	}
	g := t.Gradient
	if g == nil {
		return append(errs, fmt.Errorf("%s.gradient is required for a gradient target", where))
	}
	where += ".gradient"
	if err := validateDeploymentCredentialRef(g.TokenRef); err != nil {
		errs = append(errs, fmt.Errorf("%s.token_ref: %w", where, err))
	}
	if len(g.Services) == 0 {
		errs = append(errs, fmt.Errorf("%s.services must map at least one meter (%s) to a Gradient service ID", where, strings.Join(BillingSyncMeters, ", ")))
	}
	for _, meter := range slices.Sorted(maps.Keys(g.Services)) {
		if !slices.Contains(BillingSyncMeters, meter) {
			errs = append(errs, fmt.Errorf("%s.services names %q, which is not a pushed meter (%s)", where, meter, strings.Join(BillingSyncMeters, ", ")))
		}
		if !gradientServicePattern.MatchString(g.Services[meter]) {
			errs = append(errs, fmt.Errorf("%s.services.%s must be a Gradient service ID (letters, digits, dashes or underscores)", where, meter))
		}
	}
	return errs
}

func validateHaloPSABillingTarget(where string, t ProviderBillingTarget) []error {
	var errs []error
	if strings.TrimSpace(t.SigningKeyRef) != "" || strings.TrimSpace(t.TokenRef) != "" {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref and token_ref apply to json targets only; a halopsa target signs in with its client credentials", where))
	}
	if t.ConnectWise != nil {
		errs = append(errs, fmt.Errorf("%s.connectwise applies to connectwise targets only", where))
	}
	hp := t.HaloPSA
	if hp == nil {
		return append(errs, fmt.Errorf("%s.halopsa is required for a halopsa target", where))
	}
	where += ".halopsa"
	if hp.Tenant != "" && !haloTenantPattern.MatchString(hp.Tenant) {
		errs = append(errs, fmt.Errorf("%s.tenant must be the hosted tenant name (letters, digits, dots, dashes or underscores)", where))
	}
	if !validConnectWiseName(hp.ClientID) {
		errs = append(errs, fmt.Errorf("%s.client_id must be the API application's client ID (1-100 characters)", where))
	}
	if err := validateDeploymentCredentialRef(hp.ClientSecretRef); err != nil {
		errs = append(errs, fmt.Errorf("%s.client_secret_ref: %w", where, err))
	}
	if hp.RecurringInvoiceName != "" && !validConnectWiseName(hp.RecurringInvoiceName) {
		errs = append(errs, fmt.Errorf("%s.recurring_invoice_name must be 1-100 characters", where))
	}
	if len(hp.Items) == 0 {
		errs = append(errs, fmt.Errorf("%s.items must map at least one meter (%s) to a HaloPSA item ID", where, strings.Join(BillingSyncMeters, ", ")))
	}
	for _, meter := range slices.Sorted(maps.Keys(hp.Items)) {
		if !slices.Contains(BillingSyncMeters, meter) {
			errs = append(errs, fmt.Errorf("%s.items names %q, which is not a pushed meter (%s)", where, meter, strings.Join(BillingSyncMeters, ", ")))
		}
		if hp.Items[meter] <= 0 {
			errs = append(errs, fmt.Errorf("%s.items.%s must be a HaloPSA item ID", where, meter))
		}
	}
	if tk := hp.Tickets; tk != nil {
		if tk.TicketTypeID <= 0 {
			errs = append(errs, fmt.Errorf("%s.tickets.ticket_type_id must be a ticket type ID", where))
		}
		if tk.StatusClosedID <= 0 || tk.StatusNewID < 0 || tk.StatusNewID == tk.StatusClosedID {
			errs = append(errs, fmt.Errorf("%s.tickets.status_closed_id must be a status ID, different from status_new_id", where))
		}
		for _, kind := range tk.Kinds {
			if !slices.Contains(PSATicketAlertKinds, kind) {
				errs = append(errs, fmt.Errorf("%s.tickets.kinds names %q, which is not a ticketed alert kind (%s)", where, kind, strings.Join(PSATicketAlertKinds, ", ")))
			}
		}
	}
	return errs
}

func validateSyncroBillingTarget(where string, t ProviderBillingTarget) []error {
	var errs []error
	if strings.TrimSpace(t.SigningKeyRef) != "" || strings.TrimSpace(t.TokenRef) != "" {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref and token_ref apply to json targets only; a syncro target authenticates with its api_token_ref", where))
	}
	if t.ConnectWise != nil {
		errs = append(errs, fmt.Errorf("%s.connectwise applies to connectwise targets only", where))
	}
	sy := t.Syncro
	if sy == nil {
		return append(errs, fmt.Errorf("%s.syncro is required for a syncro target", where))
	}
	where += ".syncro"
	if err := validateDeploymentCredentialRef(sy.APITokenRef); err != nil {
		errs = append(errs, fmt.Errorf("%s.api_token_ref: %w", where, err))
	}
	if sy.ScheduleName != "" && !validConnectWiseName(sy.ScheduleName) {
		errs = append(errs, fmt.Errorf("%s.schedule_name must be 1-100 characters", where))
	}
	if len(sy.Products) == 0 {
		errs = append(errs, fmt.Errorf("%s.products must map at least one meter (%s) to a Syncro product ID", where, strings.Join(BillingSyncMeters, ", ")))
	}
	for _, meter := range slices.Sorted(maps.Keys(sy.Products)) {
		if !slices.Contains(BillingSyncMeters, meter) {
			errs = append(errs, fmt.Errorf("%s.products names %q, which is not a pushed meter (%s)", where, meter, strings.Join(BillingSyncMeters, ", ")))
		}
		if sy.Products[meter] <= 0 {
			errs = append(errs, fmt.Errorf("%s.products.%s must be a Syncro product ID", where, meter))
		}
	}
	if tk := sy.Tickets; tk != nil {
		if !validConnectWiseName(tk.ProblemType) {
			errs = append(errs, fmt.Errorf("%s.tickets.problem_type must name a ticket problem type (1-100 characters)", where))
		}
		for _, status := range []struct{ name, value string }{{"status_new", tk.StatusNew}, {"status_closed", tk.StatusClosed}} {
			if status.value != "" && !validConnectWiseName(status.value) {
				errs = append(errs, fmt.Errorf("%s.tickets.%s must be a ticket status (1-100 characters)", where, status.name))
			}
		}
		if tk.EffectiveStatusNew() == tk.EffectiveStatusClosed() {
			errs = append(errs, fmt.Errorf("%s.tickets.status_new and status_closed must differ", where))
		}
		for _, kind := range tk.Kinds {
			if !slices.Contains(PSATicketAlertKinds, kind) {
				errs = append(errs, fmt.Errorf("%s.tickets.kinds names %q, which is not a ticketed alert kind (%s)", where, kind, strings.Join(PSATicketAlertKinds, ", ")))
			}
		}
	}
	return errs
}

func validateAutotaskBillingTarget(where string, t ProviderBillingTarget) []error {
	var errs []error
	if strings.TrimSpace(t.SigningKeyRef) != "" || strings.TrimSpace(t.TokenRef) != "" {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref and token_ref apply to json targets only; an autotask target authenticates with its API user", where))
	}
	if t.ConnectWise != nil {
		errs = append(errs, fmt.Errorf("%s.connectwise applies to connectwise targets only", where))
	}
	at := t.Autotask
	if at == nil {
		return append(errs, fmt.Errorf("%s.autotask is required for an autotask target", where))
	}
	where += ".autotask"
	if !validConnectWiseName(at.Username) {
		errs = append(errs, fmt.Errorf("%s.username must be the API user (1-100 characters)", where))
	}
	for _, ref := range []struct{ name, value string }{{"secret_ref", at.SecretRef}, {"integration_code_ref", at.IntegrationCodeRef}} {
		if err := validateDeploymentCredentialRef(ref.value); err != nil {
			errs = append(errs, fmt.Errorf("%s.%s: %w", where, ref.name, err))
		}
	}
	if at.ContractName != "" && !validConnectWiseName(at.ContractName) {
		errs = append(errs, fmt.Errorf("%s.contract_name must be 1-100 characters", where))
	}
	if len(at.Services) == 0 {
		errs = append(errs, fmt.Errorf("%s.services must map at least one meter (%s) to an Autotask service ID", where, strings.Join(BillingSyncMeters, ", ")))
	}
	for _, meter := range slices.Sorted(maps.Keys(at.Services)) {
		if !slices.Contains(BillingSyncMeters, meter) {
			errs = append(errs, fmt.Errorf("%s.services names %q, which is not a pushed meter (%s)", where, meter, strings.Join(BillingSyncMeters, ", ")))
		}
		if at.Services[meter] <= 0 {
			errs = append(errs, fmt.Errorf("%s.services.%s must be an Autotask service ID", where, meter))
		}
	}
	if tk := at.Tickets; tk != nil {
		if tk.StatusNew <= 0 || tk.StatusComplete <= 0 || tk.StatusNew == tk.StatusComplete {
			errs = append(errs, fmt.Errorf("%s.tickets.status_new and status_complete must be two different ticket status picklist values", where))
		}
		if tk.Priority <= 0 {
			errs = append(errs, fmt.Errorf("%s.tickets.priority must be a ticket priority picklist value", where))
		}
		if tk.QueueID < 0 || tk.NoteType < 0 || tk.NotePublish < 0 {
			errs = append(errs, fmt.Errorf("%s.tickets.queue_id, note_type and note_publish cannot be negative", where))
		}
		for _, kind := range tk.Kinds {
			if !slices.Contains(PSATicketAlertKinds, kind) {
				errs = append(errs, fmt.Errorf("%s.tickets.kinds names %q, which is not a ticketed alert kind (%s)", where, kind, strings.Join(PSATicketAlertKinds, ", ")))
			}
		}
	}
	return errs
}

func validateConnectWiseBillingTarget(where string, t ProviderBillingTarget) []error {
	var errs []error
	if strings.TrimSpace(t.SigningKeyRef) != "" || strings.TrimSpace(t.TokenRef) != "" {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref and token_ref apply to json targets only; a connectwise target authenticates with its API member's keys", where))
	}
	cw := t.ConnectWise
	if cw == nil {
		return append(errs, fmt.Errorf("%s.connectwise is required for a connectwise target", where))
	}
	where += ".connectwise"
	if !connectWiseCompanyPattern.MatchString(cw.CompanyID) {
		errs = append(errs, fmt.Errorf("%s.company_id must be the PSA login company (1-64 letters, digits, dots, dashes or underscores)", where))
	}
	if !connectWiseClientPattern.MatchString(cw.ClientID) {
		errs = append(errs, fmt.Errorf("%s.client_id must be the integration's clientId GUID", where))
	}
	for _, ref := range []struct{ name, value string }{{"public_key_ref", cw.PublicKeyRef}, {"private_key_ref", cw.PrivateKeyRef}} {
		if err := validateDeploymentCredentialRef(ref.value); err != nil {
			errs = append(errs, fmt.Errorf("%s.%s: %w", where, ref.name, err))
		}
	}
	if !connectWiseConditionValue.MatchString(cw.AgreementType) {
		errs = append(errs, fmt.Errorf("%s.agreement_type must be 1-100 letters, digits, spaces or common punctuation without quotes", where))
	}
	if len(cw.Products) == 0 {
		errs = append(errs, fmt.Errorf("%s.products must map at least one meter (%s) to a catalog product", where, strings.Join(BillingSyncMeters, ", ")))
	}
	if tk := cw.Tickets; tk != nil {
		if !validConnectWiseName(tk.Board) {
			errs = append(errs, fmt.Errorf("%s.tickets.board must name the service board (1-100 characters)", where))
		}
		if tk.NewStatus != "" && !validConnectWiseName(tk.NewStatus) {
			errs = append(errs, fmt.Errorf("%s.tickets.new_status must be a board status name (1-100 characters)", where))
		}
		if !validConnectWiseName(tk.ClosedStatus) {
			errs = append(errs, fmt.Errorf("%s.tickets.closed_status must name the board status that closes a ticket (1-100 characters)", where))
		}
		for _, kind := range tk.Kinds {
			if !slices.Contains(PSATicketAlertKinds, kind) {
				errs = append(errs, fmt.Errorf("%s.tickets.kinds names %q, which is not a ticketed alert kind (%s)", where, kind, strings.Join(PSATicketAlertKinds, ", ")))
			}
		}
	}
	for _, meter := range slices.Sorted(maps.Keys(cw.Products)) {
		product := cw.Products[meter]
		if !slices.Contains(BillingSyncMeters, meter) {
			errs = append(errs, fmt.Errorf("%s.products names %q, which is not a pushed meter (%s)", where, meter, strings.Join(BillingSyncMeters, ", ")))
		}
		if !connectWiseConditionValue.MatchString(product) {
			errs = append(errs, fmt.Errorf("%s.products.%s must be a catalog identifier of 1-100 letters, digits, spaces or common punctuation without quotes", where, meter))
		}
	}
	return errs
}

// validConnectWiseName is a board or status name: 1-100 characters, none of
// them control characters. Names travel only in JSON bodies, never inside a
// conditions query, so ConnectWise's sorting prefixes such as ">Closed" fit.
func validConnectWiseName(name string) bool {
	if strings.TrimSpace(name) == "" || utf8.RuneCountInString(name) > 100 {
		return false
	}
	return !strings.ContainsFunc(name, unicode.IsControl)
}

// validateDeploymentCredentialRef checks a deployment-level credential
// reference: a billing target belongs to the Provider, not to a tenant, so
// it reads a file or an environment variable, never a tenant's secret store.
func validateDeploymentCredentialRef(raw string) error {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "file:"):
		path := strings.TrimSpace(strings.TrimPrefix(raw, "file:"))
		if path == "" || !filepath.IsAbs(path) {
			return errors.New("file reference must contain an absolute path")
		}
		return nil
	case strings.HasPrefix(raw, "env:") && strings.TrimSpace(strings.TrimPrefix(raw, "env:")) != "":
		return nil
	default:
		return errors.New("must use file:/absolute/path or env:NAME")
	}
}
