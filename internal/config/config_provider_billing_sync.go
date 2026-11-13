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
	// Pax8 configures a "pax8" target (MSP-8): each customer's figures are
	// uploaded as usage lines of its Pax8 subscription. Endpoint is the API
	// root, https://api.pax8.com.
	Pax8 *Pax8BillingTarget `json:"pax8,omitempty"`
	// NinjaOne configures a "ninjaone" RMM target (MSP-9): the Provider lists
	// each mapped customer's devices under its NinjaOne organization, maps
	// them to the customer's agents, reports agent health to a device custom
	// field, and runs the agent's install, upgrade and remove scripts.
	// Endpoint is the regional host, e.g. https://app.ninjarmm.com. An RMM
	// target receives no usage periods and opens no tickets.
	NinjaOne *NinjaOneTarget `json:"ninjaone,omitempty"`
	// Datto configures a "datto" RMM target (MSP-10): the same for a Datto
	// RMM platform, whose sites are the customers' organizations and whose
	// ComStore components run the agent's install, upgrade and remove as
	// quick jobs. Endpoint is the platform's API host, e.g.
	// https://pinotage-api.centrastage.net.
	Datto *DattoTarget `json:"datto,omitempty"`
	// NCentral configures an "ncentral" RMM target (MSP-12): the same for an
	// N-able N-central server, whose customers are the organizations and
	// whose API-enabled repository scripts run the agent's install, upgrade
	// and remove as direct scheduled tasks. Endpoint is the server, e.g.
	// https://ncentral.example.com.
	NCentral *NCentralTarget `json:"ncentral,omitempty"`
	// Kaseya configures a "kaseya" RMM target (MSP-13): the same for a
	// Kaseya VSA 9 server, whose organizations are the customers' and whose
	// agent procedures run the agent's install, upgrade and remove. Endpoint
	// is the VSA server, e.g. https://vsa.example.com.
	Kaseya *KaseyaTarget `json:"kaseya,omitempty"`
	// Automate configures an "automate" RMM target (MSP-11): the same for a
	// ConnectWise Automate server, whose clients are the customers' and
	// whose execute command runs the agent's install, upgrade and remove
	// shell lines. Health is not written back to Automate yet. Endpoint is
	// the server, e.g. https://automate.example.com.
	Automate *AutomateTarget `json:"automate,omitempty"`
}

// AutomateTarget is a ConnectWise Automate server the Provider runs agents
// through.
type AutomateTarget struct {
	// Username is the integrator user; PasswordRef names its password
	// (file: or env:).
	Username    string `json:"username"`
	PasswordRef string `json:"password_ref"`
	// ClientID is the integration's client ID, sent as the clientID header.
	ClientID string `json:"client_id"`
	// ExecuteCommandID is the Automate command that executes a shell line.
	ExecuteCommandID int64 `json:"execute_command_id"`
	// InstallLine, UpgradeLine and RemoveLine are each action's shell line
	// in Automate's "<shell>!!! <arguments>" form; an install's enrollment
	// arguments are appended.
	InstallLine string `json:"install_line"`
	UpgradeLine string `json:"upgrade_line"`
	RemoveLine  string `json:"remove_line"`
}

// KaseyaTarget is a Kaseya VSA server the Provider runs agents through.
type KaseyaTarget struct {
	// Username is the VSA user; AccessTokenRef names the user's personal
	// access token (file: or env:).
	Username       string `json:"username"`
	AccessTokenRef string `json:"access_token_ref"`
	// InstallProcedureID, UpgradeProcedureID and RemoveProcedureID are the
	// agent procedures of each agent action.
	InstallProcedureID int64 `json:"install_procedure_id"`
	UpgradeProcedureID int64 `json:"upgrade_procedure_id"`
	RemoveProcedureID  int64 `json:"remove_procedure_id"`
	// EnrollmentField is the agent custom field an install's enrollment
	// line is written to; the install procedure reads it (a procedure run
	// now takes no parameters).
	EnrollmentField string `json:"enrollment_field"`
	// HealthField is the agent custom field the agent's health is written
	// to; empty reports none.
	HealthField string `json:"health_field,omitempty"`
}

// NCentralTarget is an N-able N-central server the Provider runs agents
// through.
type NCentralTarget struct {
	// UserJWTRef names the API-only user's JWT (file: or env:).
	UserJWTRef string `json:"user_jwt_ref"`
	// InstallScriptID, UpgradeScriptID and RemoveScriptID are the script
	// repository items (each with its API toggle on) of each agent action.
	InstallScriptID int64 `json:"install_script_id"`
	UpgradeScriptID int64 `json:"upgrade_script_id"`
	RemoveScriptID  int64 `json:"remove_script_id"`
	// CredentialType is the tasks' credential ("LocalSystem" when empty).
	CredentialType string `json:"credential_type,omitempty"`
	// HealthPropertyID is the device custom property the agent's health is
	// written to; 0 reports none.
	HealthPropertyID int64 `json:"health_property_id,omitempty"`
}

// DattoTarget is a Datto RMM platform the Provider runs agents through.
type DattoTarget struct {
	// APIKeyRef and APISecretRef name the API user's key and secret (file:
	// or env:); both are handled as credentials.
	APIKeyRef    string `json:"api_key_ref"`
	APISecretRef string `json:"api_secret_ref"`
	// InstallComponentUID, UpgradeComponentUID and RemoveComponentUID are
	// the components each agent action runs as a quick job.
	InstallComponentUID string `json:"install_component_uid"`
	UpgradeComponentUID string `json:"upgrade_component_uid"`
	RemoveComponentUID  string `json:"remove_component_uid"`
	// HealthUDF is the user-defined field (1-30) the agent's health is
	// written to; 0 reports none.
	HealthUDF int `json:"health_udf,omitempty"`
}

// NinjaOneTarget is a NinjaOne instance the Provider runs agents through.
type NinjaOneTarget struct {
	// ClientID is the API client's ID; ClientSecretRef names its secret
	// (file: or env:).
	ClientID        string `json:"client_id"`
	ClientSecretRef string `json:"client_secret_ref"`
	// InstallScriptID, UpgradeScriptID and RemoveScriptID are the
	// automation-library scripts of each agent action.
	InstallScriptID int64 `json:"install_script_id"`
	UpgradeScriptID int64 `json:"upgrade_script_id"`
	RemoveScriptID  int64 `json:"remove_script_id"`
	// RunAs is the scripts' credential role ("system" when empty).
	RunAs string `json:"run_as,omitempty"`
	// HealthField is the device custom field the agent's health is written
	// to; empty reports none.
	HealthField string `json:"health_field,omitempty"`
}

// RMMTargetTypes are the target types that run the agent through an RMM.
var RMMTargetTypes = map[string]bool{"ninjaone": true, "datto": true, "ncentral": true, "kaseya": true, "automate": true}

// IsRMM reports whether the target runs the agent's lifecycle through an
// RMM (MSP-9 onward).
func (t ProviderBillingTarget) IsRMM() bool { return RMMTargetTypes[t.Type] }

// PushesUsage reports whether the billing sweep pushes usage periods to
// the target.
func (t ProviderBillingTarget) PushesUsage() bool { return !t.IsRMM() }

// Pax8DefaultAudience is the audience of Pax8's client-credentials tokens.
const Pax8DefaultAudience = "api://p8p.client"

// Pax8BillingTarget is a Pax8 vendor integration.
type Pax8BillingTarget struct {
	// TokenURL is the OAuth2 token endpoint and Audience its audience
	// (default api://p8p.client), as Pax8 issues them at vendor onboarding.
	TokenURL string `json:"token_url"`
	Audience string `json:"audience,omitempty"`
	// ClientID is the vendor application's client ID; ClientSecretRef names
	// its secret (file: or env:).
	ClientID        string `json:"client_id"`
	ClientSecretRef string `json:"client_secret_ref"`
	// Products maps a meter to its Pax8 product and unit of measurement.
	Products map[string]Pax8Product `json:"products"`
}

// Pax8Product is the Pax8 product and unit a meter's usage line carries.
type Pax8Product struct {
	ProductID         string `json:"product_id"`
	UnitOfMeasurement string `json:"unit_of_measurement"`
}

// EffectiveAudience is the token audience, the Pax8 default when unset.
func (p Pax8BillingTarget) EffectiveAudience() string {
	if strings.TrimSpace(p.Audience) != "" {
		return p.Audience
	}
	return Pax8DefaultAudience
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
var ProviderBillingTargetTypes = map[string]struct{}{"json": {}, "connectwise": {}, "autotask": {}, "syncro": {}, "halopsa": {}, "gradient": {}, "pax8": {},
	"ninjaone": {}, "datto": {}, "ncentral": {}, "kaseya": {}, "automate": {}}

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
			errs = append(errs, fmt.Errorf("%s.type %q is not a target type this build connects to (json, connectwise, autotask, syncro, halopsa, gradient, pax8, ninjaone, datto, ncentral, kaseya, automate)", where, t.Type))
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
		case "pax8":
			errs = append(errs, validatePax8BillingTarget(where, t)...)
		case "ninjaone":
			errs = append(errs, validateNinjaOneTarget(where, t)...)
		case "datto":
			errs = append(errs, validateDattoTarget(where, t)...)
		case "ncentral":
			errs = append(errs, validateNCentralTarget(where, t)...)
		case "kaseya":
			errs = append(errs, validateKaseyaTarget(where, t)...)
		case "automate":
			errs = append(errs, validateAutomateTarget(where, t)...)
		}
		if t.Type != "automate" && t.Automate != nil {
			errs = append(errs, fmt.Errorf("%s.automate applies to automate targets only", where))
		}
		if t.Type != "kaseya" && t.Kaseya != nil {
			errs = append(errs, fmt.Errorf("%s.kaseya applies to kaseya targets only", where))
		}
		if t.Type != "ncentral" && t.NCentral != nil {
			errs = append(errs, fmt.Errorf("%s.ncentral applies to ncentral targets only", where))
		}
		if t.Type != "datto" && t.Datto != nil {
			errs = append(errs, fmt.Errorf("%s.datto applies to datto targets only", where))
		}
		if t.Type != "ninjaone" && t.NinjaOne != nil {
			errs = append(errs, fmt.Errorf("%s.ninjaone applies to ninjaone targets only", where))
		}
		if t.Type != "pax8" && t.Pax8 != nil {
			errs = append(errs, fmt.Errorf("%s.pax8 applies to pax8 targets only", where))
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

// rmmFieldPattern is an RMM custom field name.
var rmmFieldPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

func validateNinjaOneTarget(where string, t ProviderBillingTarget) []error {
	var errs []error
	if strings.TrimSpace(t.SigningKeyRef) != "" || strings.TrimSpace(t.TokenRef) != "" {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref and token_ref apply to json targets only; a ninjaone target signs in with its client credentials", where))
	}
	if t.ConnectWise != nil {
		errs = append(errs, fmt.Errorf("%s.connectwise applies to connectwise targets only", where))
	}
	n := t.NinjaOne
	if n == nil {
		return append(errs, fmt.Errorf("%s.ninjaone is required for a ninjaone target", where))
	}
	where += ".ninjaone"
	if !validConnectWiseName(n.ClientID) {
		errs = append(errs, fmt.Errorf("%s.client_id must be the API client's ID (1-100 characters)", where))
	}
	if err := validateDeploymentCredentialRef(n.ClientSecretRef); err != nil {
		errs = append(errs, fmt.Errorf("%s.client_secret_ref: %w", where, err))
	}
	for _, script := range []struct {
		name string
		id   int64
	}{{"install_script_id", n.InstallScriptID}, {"upgrade_script_id", n.UpgradeScriptID}, {"remove_script_id", n.RemoveScriptID}} {
		if script.id <= 0 {
			errs = append(errs, fmt.Errorf("%s.%s must be an automation-library script ID", where, script.name))
		}
	}
	if n.RunAs != "" && !validConnectWiseName(n.RunAs) {
		errs = append(errs, fmt.Errorf("%s.run_as must be a credential role (1-100 characters)", where))
	}
	if n.HealthField != "" && !rmmFieldPattern.MatchString(n.HealthField) {
		errs = append(errs, fmt.Errorf("%s.health_field must be a custom field name (a letter, then letters, digits or underscores)", where))
	}
	return errs
}

// dattoTargetIDMax keeps rmm-<id>-<36-character device UID> within a
// 64-character certificate name.
const dattoTargetIDMax = 64 - len("rmm-") - len("-") - 36

func validateDattoTarget(where string, t ProviderBillingTarget) []error {
	var errs []error
	if strings.TrimSpace(t.SigningKeyRef) != "" || strings.TrimSpace(t.TokenRef) != "" {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref and token_ref apply to json targets only; a datto target signs in with its API key and secret", where))
	}
	if t.ConnectWise != nil {
		errs = append(errs, fmt.Errorf("%s.connectwise applies to connectwise targets only", where))
	}
	if len(t.ID) > dattoTargetIDMax {
		errs = append(errs, fmt.Errorf("%s.id must be at most %d characters for a datto target: an installed agent enrolls as rmm-<id>-<device UID>, and a certificate name holds 64", where, dattoTargetIDMax))
	}
	d := t.Datto
	if d == nil {
		return append(errs, fmt.Errorf("%s.datto is required for a datto target", where))
	}
	where += ".datto"
	if err := validateDeploymentCredentialRef(d.APIKeyRef); err != nil {
		errs = append(errs, fmt.Errorf("%s.api_key_ref: %w", where, err))
	}
	if err := validateDeploymentCredentialRef(d.APISecretRef); err != nil {
		errs = append(errs, fmt.Errorf("%s.api_secret_ref: %w", where, err))
	}
	for _, component := range []struct{ name, uid string }{{"install_component_uid", d.InstallComponentUID},
		{"upgrade_component_uid", d.UpgradeComponentUID}, {"remove_component_uid", d.RemoveComponentUID}} {
		if !pax8IDPattern.MatchString(component.uid) {
			errs = append(errs, fmt.Errorf("%s.%s must be a component UID", where, component.name))
		}
	}
	if d.HealthUDF < 0 || d.HealthUDF > 30 {
		errs = append(errs, fmt.Errorf("%s.health_udf must be a user-defined field from 1 to 30 (0 for none)", where))
	}
	return errs
}

func validateNCentralTarget(where string, t ProviderBillingTarget) []error {
	var errs []error
	if strings.TrimSpace(t.SigningKeyRef) != "" || strings.TrimSpace(t.TokenRef) != "" {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref and token_ref apply to json targets only; an ncentral target authenticates with its API user's JWT", where))
	}
	if t.ConnectWise != nil {
		errs = append(errs, fmt.Errorf("%s.connectwise applies to connectwise targets only", where))
	}
	n := t.NCentral
	if n == nil {
		return append(errs, fmt.Errorf("%s.ncentral is required for an ncentral target", where))
	}
	where += ".ncentral"
	if err := validateDeploymentCredentialRef(n.UserJWTRef); err != nil {
		errs = append(errs, fmt.Errorf("%s.user_jwt_ref: %w", where, err))
	}
	for _, script := range []struct {
		name string
		id   int64
	}{{"install_script_id", n.InstallScriptID}, {"upgrade_script_id", n.UpgradeScriptID}, {"remove_script_id", n.RemoveScriptID}} {
		if script.id <= 0 {
			errs = append(errs, fmt.Errorf("%s.%s must be a script repository item ID", where, script.name))
		}
	}
	if n.CredentialType != "" && !validConnectWiseName(n.CredentialType) {
		errs = append(errs, fmt.Errorf("%s.credential_type must be a task credential type (1-100 characters)", where))
	}
	if n.HealthPropertyID < 0 {
		errs = append(errs, fmt.Errorf("%s.health_property_id must be a device custom property ID (0 for none)", where))
	}
	return errs
}

func validateKaseyaTarget(where string, t ProviderBillingTarget) []error {
	var errs []error
	if strings.TrimSpace(t.SigningKeyRef) != "" || strings.TrimSpace(t.TokenRef) != "" {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref and token_ref apply to json targets only; a kaseya target signs in with its user's personal access token", where))
	}
	if t.ConnectWise != nil {
		errs = append(errs, fmt.Errorf("%s.connectwise applies to connectwise targets only", where))
	}
	k := t.Kaseya
	if k == nil {
		return append(errs, fmt.Errorf("%s.kaseya is required for a kaseya target", where))
	}
	where += ".kaseya"
	if !validConnectWiseName(k.Username) || strings.Contains(k.Username, ":") {
		errs = append(errs, fmt.Errorf("%s.username must be the VSA user (1-100 characters, no colon)", where))
	}
	if err := validateDeploymentCredentialRef(k.AccessTokenRef); err != nil {
		errs = append(errs, fmt.Errorf("%s.access_token_ref: %w", where, err))
	}
	for _, proc := range []struct {
		name string
		id   int64
	}{{"install_procedure_id", k.InstallProcedureID}, {"upgrade_procedure_id", k.UpgradeProcedureID}, {"remove_procedure_id", k.RemoveProcedureID}} {
		if proc.id <= 0 {
			errs = append(errs, fmt.Errorf("%s.%s must be an agent procedure ID", where, proc.name))
		}
	}
	if !rmmFieldPattern.MatchString(k.EnrollmentField) {
		errs = append(errs, fmt.Errorf("%s.enrollment_field must name the custom field the install procedure reads (a letter, then letters, digits or underscores)", where))
	}
	if k.HealthField != "" && (!rmmFieldPattern.MatchString(k.HealthField) || k.HealthField == k.EnrollmentField) {
		errs = append(errs, fmt.Errorf("%s.health_field must be another custom field name", where))
	}
	return errs
}

func validateAutomateTarget(where string, t ProviderBillingTarget) []error {
	var errs []error
	if strings.TrimSpace(t.SigningKeyRef) != "" || strings.TrimSpace(t.TokenRef) != "" {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref and token_ref apply to json targets only; an automate target signs in with its integrator user", where))
	}
	if t.ConnectWise != nil {
		errs = append(errs, fmt.Errorf("%s.connectwise applies to connectwise targets only", where))
	}
	a := t.Automate
	if a == nil {
		return append(errs, fmt.Errorf("%s.automate is required for an automate target", where))
	}
	where += ".automate"
	if !validConnectWiseName(a.Username) {
		errs = append(errs, fmt.Errorf("%s.username must be the integrator user (1-100 characters)", where))
	}
	if err := validateDeploymentCredentialRef(a.PasswordRef); err != nil {
		errs = append(errs, fmt.Errorf("%s.password_ref: %w", where, err))
	}
	if !pax8IDPattern.MatchString(a.ClientID) {
		errs = append(errs, fmt.Errorf("%s.client_id must be the integration's client ID (a GUID)", where))
	}
	if a.ExecuteCommandID <= 0 {
		errs = append(errs, fmt.Errorf("%s.execute_command_id must be the Automate command that executes a shell line", where))
	}
	for _, line := range []struct{ name, value string }{{"install_line", a.InstallLine}, {"upgrade_line", a.UpgradeLine}, {"remove_line", a.RemoveLine}} {
		v := strings.TrimSpace(line.value)
		if !strings.Contains(v, "!!! ") || len(v) > 1000 || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			errs = append(errs, fmt.Errorf("%s.%s must be a shell line in Automate's \"<shell>!!! <arguments>\" form (at most 1000 characters)", where, line.name))
		}
	}
	return errs
}

// pax8IDPattern is a Pax8 product or subscription ID.
var pax8IDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func validatePax8BillingTarget(where string, t ProviderBillingTarget) []error {
	var errs []error
	if strings.TrimSpace(t.SigningKeyRef) != "" || strings.TrimSpace(t.TokenRef) != "" {
		errs = append(errs, fmt.Errorf("%s.signing_key_ref and token_ref apply to json targets only; a pax8 target signs in with its client credentials", where))
	}
	if t.ConnectWise != nil {
		errs = append(errs, fmt.Errorf("%s.connectwise applies to connectwise targets only", where))
	}
	p := t.Pax8
	if p == nil {
		return append(errs, fmt.Errorf("%s.pax8 is required for a pax8 target", where))
	}
	where += ".pax8"
	u, err := url.Parse(strings.TrimSpace(p.TokenURL))
	switch {
	case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http"):
		errs = append(errs, fmt.Errorf("%s.token_url must be an absolute https URL", where))
	case u.Scheme == "http" && !t.AllowInsecureLoopback:
		errs = append(errs, fmt.Errorf("%s.token_url must use https (http only with allow_insecure_loopback for a loopback test receiver)", where))
	case u.User != nil:
		errs = append(errs, fmt.Errorf("%s.token_url must not carry credentials", where))
	}
	if p.Audience != "" && !validConnectWiseName(p.Audience) {
		errs = append(errs, fmt.Errorf("%s.audience must be 1-100 characters", where))
	}
	if !validConnectWiseName(p.ClientID) {
		errs = append(errs, fmt.Errorf("%s.client_id must be the vendor application's client ID (1-100 characters)", where))
	}
	if err := validateDeploymentCredentialRef(p.ClientSecretRef); err != nil {
		errs = append(errs, fmt.Errorf("%s.client_secret_ref: %w", where, err))
	}
	if len(p.Products) == 0 {
		errs = append(errs, fmt.Errorf("%s.products must map at least one meter (%s) to a Pax8 product", where, strings.Join(BillingSyncMeters, ", ")))
	}
	for _, meter := range slices.Sorted(maps.Keys(p.Products)) {
		prod := p.Products[meter]
		if !slices.Contains(BillingSyncMeters, meter) {
			errs = append(errs, fmt.Errorf("%s.products names %q, which is not a pushed meter (%s)", where, meter, strings.Join(BillingSyncMeters, ", ")))
		}
		if !pax8IDPattern.MatchString(prod.ProductID) || !validConnectWiseName(prod.UnitOfMeasurement) {
			errs = append(errs, fmt.Errorf("%s.products.%s needs a Pax8 product ID (a UUID) and a unit of measurement", where, meter))
		}
	}
	return errs
}

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
