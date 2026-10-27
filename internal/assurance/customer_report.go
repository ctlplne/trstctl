// SPDX-License-Identifier: BUSL-1.1

package assurance

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/branding"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// CustomerFormat names the customer assurance report's schema (A187): one
// tenant's plain-language account of its credentials over a period, in the
// tenant's white-label brand, for a Provider to share with that customer.
const CustomerFormat = "trstctl.customer-assurance-report/v1"

// ExpiringWithin is how far ahead the report counts a certificate as expiring.
const ExpiringWithin = 30 * 24 * time.Hour

// MaxEvidenceBytes bounds an incident evidence bundle the report carries
// whole; a larger one is named by its digest.
const MaxEvidenceBytes = 64 << 10

// maxLogoBytes bounds the brand logo the report embeds.
const maxLogoBytes = 256 << 10

// maxReasonRunes bounds a failure or incident reason.
const maxReasonRunes = 240

// defaultAccent is the console's brand accent.
const defaultAccent = "#174f42"

var (
	// Raster images only: an SVG can carry script, so it is not embedded.
	logoDataURI = regexp.MustCompile(`^data:image/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/]+={0,2}$`)
	hexColor    = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)
)

// CustomerInputs is what one customer assurance report is built from.
type CustomerInputs struct {
	TenantID   string
	TenantName string
	Brand      branding.Brand
	// GeneratedAt is when the inventory was read; [From, Through) is the
	// period the changes cover.
	GeneratedAt   time.Time
	From, Through time.Time
	Facts         store.CustomerAssuranceFacts
	Inventory     store.ComplianceInventoryCounts
	// Records are the assurance records of the credentials whose lifecycle
	// changed in the period; RecordsNote says why there are none to read.
	Records          []Record
	RecordsTruncated bool
	RecordsNote      string
	// Previous is the verified report of the period before; PreviousNote
	// says why there is none.
	Previous     *CustomerReport
	PreviousNote string
}

// CustomerReport is one customer assurance report. HTML is its branded
// rendering; the report is signed with the rendering inside it.
type CustomerReport struct {
	Format        string               `json:"format"`
	TenantID      string               `json:"tenant_id"`
	TenantName    string               `json:"tenant_name"`
	Brand         CustomerBrand        `json:"brand"`
	PeriodFrom    time.Time            `json:"period_from"`
	PeriodThrough time.Time            `json:"period_through"`
	GeneratedAt   time.Time            `json:"generated_at"`
	Summary       []string             `json:"summary"`
	Inventory     CustomerInventory    `json:"inventory"`
	Credentials   CustomerCredentials  `json:"credentials"`
	Verification  CustomerVerification `json:"verification"`
	Incidents     CustomerIncidents    `json:"incidents"`
	Changes       CustomerChanges      `json:"changes"`
	// Limits says what the report does not establish.
	Limits     []string `json:"limits"`
	HTML       string   `json:"html"`
	HTMLSHA256 string   `json:"html_sha256"`
}

// CustomerBrand is the brand the report is rendered in.
type CustomerBrand struct {
	ProductName string `json:"product_name"`
	LogoDataURI string `json:"logo_data_uri,omitempty"`
	Accent      string `json:"accent"`
	Footer      string `json:"footer,omitempty"`
	// Custom is false when the tenant has no white-label brand.
	Custom bool `json:"custom"`
}

// CustomerInventory is the tenant's inventory when the report was generated.
type CustomerInventory struct {
	ActiveCertificates int `json:"active_certificates"`
	OwnedCertificates  int `json:"owned_certificates"`
	// OwnershipCoveragePercent rounds down; it is absent with no active
	// certificate.
	OwnershipCoveragePercent *int                  `json:"ownership_coverage_percent,omitempty"`
	Unowned                  []CustomerCertificate `json:"unowned"`
	CryptoAssets             int                   `json:"crypto_assets"`
	DiscoveryInventoryRows   int                   `json:"discovery_inventory_rows"`
}

// CustomerCertificate names one certificate.
type CustomerCertificate struct {
	ID       string     `json:"id"`
	Subject  string     `json:"subject"`
	NotAfter *time.Time `json:"not_after,omitempty"`
	Owner    string     `json:"owner,omitempty"`
}

// CustomerCredentials is expiry now, and renewal, revocation and failure in
// the period.
type CustomerCredentials struct {
	ExpiringWithinDays int                   `json:"expiring_within_days"`
	Expiring           int                   `json:"expiring"`
	ExpiringSoonest    []CustomerCertificate `json:"expiring_soonest"`
	ExpiredActive      int                   `json:"expired_active"`
	Added              int                   `json:"added"`
	Renewed            int                   `json:"renewed"`
	Revoked            int                   `json:"revoked"`
	FailedRenewals     int                   `json:"failed_renewals"`
	FailedDeliveries   int                   `json:"failed_deliveries"`
	Failures           []CustomerFailure     `json:"failures"`
}

// CustomerFailure is one failed renewal run or connector delivery.
type CustomerFailure struct {
	Kind    string    `json:"kind"`
	ID      string    `json:"id"`
	Subject string    `json:"subject"`
	Via     string    `json:"via,omitempty"`
	Status  string    `json:"status"`
	Reason  string    `json:"reason,omitempty"`
	At      time.Time `json:"at"`
}

// CustomerVerification is what was checked independently of the product's
// own record of delivering a certificate.
type CustomerVerification struct {
	VerifiedDeliveries       int `json:"verified_deliveries"`
	EndpointObservations     int `json:"endpoint_observations"`
	EndpointsMatching        int `json:"endpoints_matching"`
	EndpointsMismatched      int `json:"endpoints_mismatched"`
	EndpointsUnreachable     int `json:"endpoints_unreachable"`
	EndpointsCheckedInPeriod int `json:"endpoints_checked_in_period"`
	// ChangedCredentials changed in the period; each is independently
	// verified (seen served from outside the product's own record), known
	// only from that record, or not verified at all.
	ChangedCredentials          int    `json:"changed_credentials"`
	ChangedCredentialsTruncated bool   `json:"changed_credentials_truncated,omitempty"`
	IndependentlyVerified       int    `json:"independently_verified"`
	RecordedOnly                int    `json:"recorded_only"`
	NotVerified                 int    `json:"not_verified"`
	Note                        string `json:"note,omitempty"`
}

// CustomerIncidents are the incident runs open or active in the period.
type CustomerIncidents struct {
	InPeriod       int                `json:"in_period"`
	OpenedInPeriod int                `json:"opened_in_period"`
	Open           int                `json:"open"`
	Items          []CustomerIncident `json:"items"`
}

// CustomerIncident is one incident run with its evidence bundle.
type CustomerIncident struct {
	Kind           string    `json:"kind"`
	ID             string    `json:"id"`
	Status         string    `json:"status"`
	Phase          string    `json:"phase"`
	Reason         string    `json:"reason,omitempty"`
	OpenedAt       time.Time `json:"opened_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	EvidenceFormat string    `json:"evidence_format,omitempty"`
	EvidenceSHA256 string    `json:"evidence_sha256,omitempty"`
	// Evidence is the bundle itself when it is at most MaxEvidenceBytes.
	Evidence string `json:"evidence,omitempty"`
}

// CustomerChanges compares the report with the previous period's.
type CustomerChanges struct {
	Comparable            bool           `json:"comparable"`
	Note                  string         `json:"note,omitempty"`
	PreviousPeriodFrom    *time.Time     `json:"previous_period_from,omitempty"`
	PreviousPeriodThrough *time.Time     `json:"previous_period_through,omitempty"`
	PreviousGeneratedAt   *time.Time     `json:"previous_generated_at,omitempty"`
	Metrics               []MetricChange `json:"metrics"`
}

// MetricChange is one figure in both periods.
type MetricChange struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Previous int    `json:"previous"`
	Current  int    `json:"current"`
	Delta    int    `json:"delta"`
	Sentence string `json:"sentence"`
}

type customerMetric struct {
	key, label string
	value      func(CustomerReport) (int, bool)
}

func always(v func(CustomerReport) int) func(CustomerReport) (int, bool) {
	return func(r CustomerReport) (int, bool) { return v(r), true }
}

// customerMetrics are the figures compared across periods, in report order.
var customerMetrics = []customerMetric{
	{"active_certificates", "Active certificates", always(func(r CustomerReport) int { return r.Inventory.ActiveCertificates })},
	{"ownership_coverage_percent", "Ownership coverage (%)", func(r CustomerReport) (int, bool) {
		if r.Inventory.OwnershipCoveragePercent == nil {
			return 0, false
		}
		return *r.Inventory.OwnershipCoveragePercent, true
	}},
	{"expiring", "Certificates expiring within 30 days", always(func(r CustomerReport) int { return r.Credentials.Expiring })},
	{"expired_active", "Expired certificates still active", always(func(r CustomerReport) int { return r.Credentials.ExpiredActive })},
	{"renewed", "Certificates renewed", always(func(r CustomerReport) int { return r.Credentials.Renewed })},
	{"revoked", "Certificates revoked", always(func(r CustomerReport) int { return r.Credentials.Revoked })},
	{"failed_renewals", "Failed renewals", always(func(r CustomerReport) int { return r.Credentials.FailedRenewals })},
	{"failed_deliveries", "Failed deliveries", always(func(r CustomerReport) int { return r.Credentials.FailedDeliveries })},
	{"verified_deliveries", "Verified deliveries", always(func(r CustomerReport) int { return r.Verification.VerifiedDeliveries })},
	{"endpoints_matching", "Endpoints serving the expected certificate", always(func(r CustomerReport) int { return r.Verification.EndpointsMatching })},
	{"endpoints_mismatched", "Endpoints serving a different certificate", always(func(r CustomerReport) int { return r.Verification.EndpointsMismatched })},
	{"endpoints_unreachable", "Endpoints that could not be reached", always(func(r CustomerReport) int { return r.Verification.EndpointsUnreachable })},
	{"independently_verified", "Changed credentials independently verified", always(func(r CustomerReport) int { return r.Verification.IndependentlyVerified })},
	{"incidents_opened", "Incidents opened", always(func(r CustomerReport) int { return r.Incidents.OpenedInPeriod })},
	{"incidents_open", "Incidents open", always(func(r CustomerReport) int { return r.Incidents.Open })},
}

// BuildCustomerReport assembles and renders one report.
func BuildCustomerReport(in CustomerInputs) (CustomerReport, error) {
	f := in.Facts
	r := CustomerReport{
		Format: CustomerFormat, TenantID: in.TenantID, TenantName: firstNonEmpty(in.TenantName, in.TenantID),
		Brand:      customerBrand(in.Brand),
		PeriodFrom: in.From.UTC(), PeriodThrough: in.Through.UTC(), GeneratedAt: in.GeneratedAt.UTC(),
		Inventory: CustomerInventory{
			ActiveCertificates: f.ActiveCertificates, OwnedCertificates: f.OwnedCertificates,
			Unowned:      customerCertificates(f.UnownedSoonest),
			CryptoAssets: in.Inventory.CryptoAssets, DiscoveryInventoryRows: in.Inventory.InventoryRows,
		},
		Credentials: CustomerCredentials{
			ExpiringWithinDays: int(ExpiringWithin / (24 * time.Hour)), Expiring: f.Expiring,
			ExpiringSoonest: customerCertificates(f.ExpiringSoonest), ExpiredActive: f.ExpiredActive,
			Added: f.AddedInPeriod, Renewed: f.RenewedInPeriod, Revoked: f.RevokedInPeriod,
			FailedRenewals: f.FailedRenewals, FailedDeliveries: f.FailedDeliveries, Failures: []CustomerFailure{},
		},
		Verification: CustomerVerification{
			VerifiedDeliveries: f.VerifiedDeliveries, EndpointObservations: f.EndpointObservations,
			EndpointsMatching: f.EndpointsMatching, EndpointsMismatched: f.EndpointsMismatched,
			EndpointsUnreachable: f.EndpointsUnreachable, EndpointsCheckedInPeriod: f.EndpointsCheckedInPeriod,
			ChangedCredentials: len(in.Records), ChangedCredentialsTruncated: in.RecordsTruncated,
			Note: in.RecordsNote,
		},
		Incidents: CustomerIncidents{
			InPeriod: f.IncidentsInPeriod, OpenedInPeriod: f.IncidentsOpenedInPeriod, Open: f.IncidentsOpen,
			Items: []CustomerIncident{},
		},
		Limits: []string{
			fmt.Sprintf("Each list names at most %d items; the count beside it is exact.", store.CustomerAssuranceListLimit),
			"Endpoint results are the latest observation of each endpoint from each vantage, not every check made in the period.",
			"Failures are the renewal runs and connector deliveries this deployment recorded; work done outside it is not seen.",
		},
	}
	if r.Inventory.ActiveCertificates > 0 {
		pct := r.Inventory.OwnedCertificates * 100 / r.Inventory.ActiveCertificates
		r.Inventory.OwnershipCoveragePercent = &pct
	}
	for _, failure := range f.Failures {
		r.Credentials.Failures = append(r.Credentials.Failures, CustomerFailure{
			Kind: failure.Kind, ID: failure.ID, Subject: failure.Subject, Via: failure.Via,
			Status: failure.Status, Reason: clip(failure.Reason), At: failure.At.UTC(),
		})
	}
	for _, record := range in.Records {
		switch {
		case slices.Contains(record.IndependentlyObserved, StageVerification):
			r.Verification.IndependentlyVerified++
		case slices.Contains(record.RecordedOnly, StageVerification):
			r.Verification.RecordedOnly++
		default:
			r.Verification.NotVerified++
		}
	}
	if in.RecordsTruncated {
		r.Limits = append(r.Limits, fmt.Sprintf("Only the %d most recently changed credentials are classified by how their deployment was verified.", PackLimit))
	}
	for _, incident := range f.Incidents {
		item := CustomerIncident{
			Kind: incident.Kind, ID: incident.ID, Status: incident.Status, Phase: incident.Phase,
			Reason: clip(incident.Reason), OpenedAt: incident.OpenedAt.UTC(), UpdatedAt: incident.UpdatedAt.UTC(),
			EvidenceFormat: incident.EvidenceFormat,
		}
		if incident.Evidence != "" {
			item.EvidenceSHA256 = crypto.SHA256Hex([]byte(incident.Evidence))
			if len(incident.Evidence) <= MaxEvidenceBytes {
				item.Evidence = incident.Evidence
			} else {
				r.Limits = append(r.Limits, fmt.Sprintf("Incident %s's evidence is larger than %d KiB, so the report names it by its SHA-256 digest; read it from the incident.", incident.ID, MaxEvidenceBytes>>10))
			}
		}
		r.Incidents.Items = append(r.Incidents.Items, item)
	}
	if in.Brand.LogoDataURI != "" && r.Brand.LogoDataURI == "" {
		r.Limits = append(r.Limits, fmt.Sprintf("The brand's logo is not a PNG, JPEG, GIF or WebP data URI of at most %d KiB, so it is not shown.", maxLogoBytes>>10))
	}
	r.Changes = compareCustomerReports(r, in.Previous, in.PreviousNote)
	r.Summary = customerSummary(r)
	html, err := renderCustomerHTML(r)
	if err != nil {
		return CustomerReport{}, err
	}
	r.HTML, r.HTMLSHA256 = html, crypto.SHA256Hex([]byte(html))
	return r, nil
}

func customerBrand(b branding.Brand) CustomerBrand {
	def := branding.Default()
	out := CustomerBrand{
		ProductName: firstNonEmpty(strings.TrimSpace(b.ProductName), def.ProductName), Accent: defaultAccent,
		Footer: strings.TrimSpace(b.EmailFooter),
	}
	out.Custom = out.ProductName != def.ProductName || b.LogoDataURI != "" || len(b.TokenOverrides) > 0 || out.Footer != ""
	if len(b.LogoDataURI) <= maxLogoBytes && logoDataURI.MatchString(b.LogoDataURI) {
		out.LogoDataURI = b.LogoDataURI
	}
	if accent := strings.TrimSpace(b.TokenOverrides["accent"]); hexColor.MatchString(accent) {
		out.Accent = strings.ToLower(accent)
	}
	return out
}

func customerCertificates(in []store.AssuranceCertificate) []CustomerCertificate {
	out := make([]CustomerCertificate, 0, len(in))
	for _, c := range in {
		var notAfter *time.Time
		if c.NotAfter != nil {
			t := c.NotAfter.UTC()
			notAfter = &t
		}
		out = append(out, CustomerCertificate{ID: c.ID, Subject: c.Subject, NotAfter: notAfter, Owner: c.Owner})
	}
	return out
}

// compareCustomerReports compares every metric both reports carry.
func compareCustomerReports(current CustomerReport, previous *CustomerReport, note string) CustomerChanges {
	changes := CustomerChanges{Metrics: []MetricChange{}}
	if previous == nil {
		changes.Note = firstNonEmpty(note, "There is no earlier report to compare with.")
		return changes
	}
	changes.Comparable = true
	from, through, generated := previous.PeriodFrom, previous.PeriodThrough, previous.GeneratedAt
	changes.PreviousPeriodFrom, changes.PreviousPeriodThrough, changes.PreviousGeneratedAt = &from, &through, &generated
	for _, m := range customerMetrics {
		now, okNow := m.value(current)
		was, okWas := m.value(*previous)
		if !okNow || !okWas {
			continue
		}
		change := MetricChange{Key: m.key, Label: m.label, Previous: was, Current: now, Delta: now - was}
		switch {
		case now > was:
			change.Sentence = fmt.Sprintf("%s rose from %d to %d.", m.label, was, now)
		case now < was:
			change.Sentence = fmt.Sprintf("%s fell from %d to %d.", m.label, was, now)
		default:
			change.Sentence = fmt.Sprintf("%s stayed at %d.", m.label, now)
		}
		changes.Metrics = append(changes.Metrics, change)
	}
	return changes
}

// customerSummary is the report in a few plain sentences.
func customerSummary(r CustomerReport) []string {
	inv, cred, ver, inc := r.Inventory, r.Credentials, r.Verification, r.Incidents
	out := []string{}
	if inv.OwnershipCoveragePercent == nil {
		out = append(out, "There are no active certificates in the inventory.")
	} else {
		out = append(out, fmt.Sprintf("%s holds %s; %d of them (%d%%) have a named owner.",
			r.TenantName, plural(inv.ActiveCertificates, "active certificate", "active certificates"),
			inv.OwnedCertificates, *inv.OwnershipCoveragePercent))
	}
	switch {
	case cred.Expiring == 0:
		out = append(out, fmt.Sprintf("No certificate expires in the next %d days.", cred.ExpiringWithinDays))
	case len(cred.ExpiringSoonest) > 0 && cred.ExpiringSoonest[0].NotAfter != nil:
		out = append(out, fmt.Sprintf("%s in the next %d days; the soonest is %s on %s.",
			plural(cred.Expiring, "certificate expires", "certificates expire"), cred.ExpiringWithinDays,
			cred.ExpiringSoonest[0].Subject, cred.ExpiringSoonest[0].NotAfter.Format("2006-01-02")))
	default:
		out = append(out, fmt.Sprintf("%s in the next %d days.", plural(cred.Expiring, "certificate expires", "certificates expire"), cred.ExpiringWithinDays))
	}
	if cred.ExpiredActive > 0 {
		out = append(out, fmt.Sprintf("%s already expired and %s still active.",
			plural(cred.ExpiredActive, "certificate has", "certificates have"), pluralWord(cred.ExpiredActive, "is", "are")))
	}
	out = append(out, fmt.Sprintf("In this period %s renewed, %s added to the inventory and %s revoked.",
		plural(cred.Renewed, "certificate was", "certificates were"), countWas(cred.Added), countWas(cred.Revoked)))
	if cred.FailedRenewals+cred.FailedDeliveries == 0 {
		out = append(out, "No renewal or delivery failed.")
	} else {
		out = append(out, fmt.Sprintf("%s and %s failed; each is listed below.",
			plural(cred.FailedRenewals, "renewal", "renewals"), plural(cred.FailedDeliveries, "delivery", "deliveries")))
	}
	if ver.EndpointObservations > 0 {
		out = append(out, fmt.Sprintf("Of %s, %d served the expected certificate, %d served a different one and %d could not be reached.",
			plural(ver.EndpointObservations, "endpoint check", "endpoint checks"), ver.EndpointsMatching, ver.EndpointsMismatched, ver.EndpointsUnreachable))
	} else {
		out = append(out, "No endpoint has been checked for the certificate it serves.")
	}
	if ver.ChangedCredentials > 0 {
		out = append(out, fmt.Sprintf("Of %s that changed in this period, %d %s seen served from outside %s's own record.",
			plural(ver.ChangedCredentials, "credential", "credentials"), ver.IndependentlyVerified,
			pluralWord(ver.IndependentlyVerified, "was", "were"), r.Brand.ProductName))
	}
	if inc.InPeriod == 0 {
		out = append(out, "No incident was open or active in this period.")
	} else {
		out = append(out, fmt.Sprintf("%s opened in this period and %s open; each is listed with its evidence.",
			plural(inc.OpenedInPeriod, "incident was", "incidents were"), plural(inc.Open, "is", "are")))
	}
	if !r.Changes.Comparable {
		out = append(out, r.Changes.Note)
	} else {
		changed := []string{}
		for _, m := range r.Changes.Metrics {
			if m.Delta != 0 && len(changed) < 4 {
				changed = append(changed, strings.TrimSuffix(m.Sentence, "."))
			}
		}
		if len(changed) == 0 {
			out = append(out, "Nothing measured changed since the previous report.")
		} else {
			out = append(out, "Since the previous report: "+strings.Join(changed, "; ")+".")
		}
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func countWas(n int) string { return fmt.Sprintf("%d %s", n, pluralWord(n, "was", "were")) }

func clip(s string) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= maxReasonRunes {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxReasonRunes]) + "..."
}

// CheckCustomerReport decodes a customer assurance report payload and checks
// that the rendering inside it is the one its digest names. It checks no
// signature: verify the signed scheduled report around it first.
func CheckCustomerReport(payload []byte) (CustomerReport, error) {
	var r CustomerReport
	if err := json.Unmarshal(payload, &r); err != nil {
		return CustomerReport{}, fmt.Errorf("assurance: decode customer report: %w", err)
	}
	if r.Format != CustomerFormat || r.TenantID == "" {
		return CustomerReport{}, errors.New("assurance: not a customer assurance report")
	}
	if r.HTML == "" || crypto.SHA256Hex([]byte(r.HTML)) != r.HTMLSHA256 {
		return CustomerReport{}, errors.New("assurance: the report's HTML rendering does not match its digest")
	}
	return r, nil
}
