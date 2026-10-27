// SPDX-License-Identifier: BUSL-1.1

package assurance

import (
	"bytes"
	"html/template"
	"time"
)

// customerTemplate renders a report as one self-contained HTML page: styles
// inline, the logo embedded, nothing fetched. html/template escapes every
// value the tenant or its inventory supplied.
var customerTemplate = template.Must(template.New("customer").Funcs(template.FuncMap{
	"day": func(t time.Time) string { return t.UTC().Format("2006-01-02") },
	"dayp": func(t *time.Time) string {
		if t == nil {
			return "no expiry recorded"
		}
		return t.UTC().Format("2006-01-02")
	},
	"stamp": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"incidentKind": func(kind string) string {
		if kind == "issuer_compromise" {
			return "Issuer compromise"
		}
		return "Credential compromise"
	},
	"failureKind": func(kind string) string {
		if kind == "renewal" {
			return "Renewal"
		}
		return "Delivery"
	},
	"short": func(digest string) string {
		if len(digest) > 16 {
			return digest[:16]
		}
		return digest
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.R.Brand.ProductName}} assurance report: {{.R.TenantName}}</title>
<style>
:root { --accent: {{.R.Brand.Accent}}; --ink: #1f2328; --muted: #59636e; --line: #d1d9e0; }
body { margin: 0; background: #ffffff; color: var(--ink); font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
main { max-width: 880px; margin: 0 auto; padding: 32px 16px; }
header { display: flex; align-items: center; gap: 16px; padding-bottom: 16px; border-bottom: 3px solid var(--accent); }
header img { max-height: 48px; max-width: 200px; }
h1 { margin: 0; font-size: 22px; }
h2 { margin: 28px 0 8px; font-size: 17px; color: var(--accent); }
.period { margin: 4px 0 0; color: var(--muted); }
table { width: 100%; border-collapse: collapse; margin: 8px 0; }
th, td { padding: 6px 8px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.muted { color: var(--muted); }
code { font-size: 13px; overflow-wrap: anywhere; }
footer { margin-top: 32px; padding-top: 12px; border-top: 1px solid var(--line); color: var(--muted); font-size: 13px; }
@media print { main { padding: 0; } }
</style>
</head>
<body>
<main>
<header>
{{if .Logo}}<img src="{{.Logo}}" alt="{{.R.Brand.ProductName}}">{{end}}
<div>
<h1>{{.R.Brand.ProductName}} assurance report</h1>
<p class="period">{{.R.TenantName}} &middot; {{day .R.PeriodFrom}} to {{day .R.PeriodThrough}}</p>
</div>
</header>

<section>
<h2>Summary</h2>
<ul>{{range .R.Summary}}<li>{{.}}</li>{{end}}</ul>
</section>

<section>
<h2>Inventory and ownership</h2>
<table>
<tr><th>Active certificates</th><td class="num">{{.R.Inventory.ActiveCertificates}}</td></tr>
<tr><th>With a named owner</th><td class="num">{{.R.Inventory.OwnedCertificates}}{{with .R.Inventory.OwnershipCoveragePercent}} ({{.}}%){{end}}</td></tr>
<tr><th>Cryptographic assets</th><td class="num">{{.R.Inventory.CryptoAssets}}</td></tr>
<tr><th>Discovery inventory records</th><td class="num">{{.R.Inventory.DiscoveryInventoryRows}}</td></tr>
</table>
{{if .R.Inventory.Unowned}}<p>Certificates without an owner, soonest expiry first:</p>
<table><tr><th>Certificate</th><th>Expires</th></tr>
{{range .R.Inventory.Unowned}}<tr><td>{{.Subject}}</td><td>{{dayp .NotAfter}}</td></tr>{{end}}
</table>{{end}}
</section>

<section>
<h2>Expiring, renewed and failed credentials</h2>
<table>
<tr><th>Expiring within {{.R.Credentials.ExpiringWithinDays}} days</th><td class="num">{{.R.Credentials.Expiring}}</td></tr>
<tr><th>Expired but still active</th><td class="num">{{.R.Credentials.ExpiredActive}}</td></tr>
<tr><th>Renewed in the period</th><td class="num">{{.R.Credentials.Renewed}}</td></tr>
<tr><th>Added to the inventory in the period</th><td class="num">{{.R.Credentials.Added}}</td></tr>
<tr><th>Revoked in the period</th><td class="num">{{.R.Credentials.Revoked}}</td></tr>
<tr><th>Failed renewals</th><td class="num">{{.R.Credentials.FailedRenewals}}</td></tr>
<tr><th>Failed deliveries</th><td class="num">{{.R.Credentials.FailedDeliveries}}</td></tr>
</table>
{{if .R.Credentials.ExpiringSoonest}}<p>Expiring soonest:</p>
<table><tr><th>Certificate</th><th>Owner</th><th>Expires</th></tr>
{{range .R.Credentials.ExpiringSoonest}}<tr><td>{{.Subject}}</td><td>{{if .Owner}}{{.Owner}}{{else}}<span class="muted">none</span>{{end}}</td><td>{{dayp .NotAfter}}</td></tr>{{end}}
</table>{{end}}
{{if .R.Credentials.Failures}}<p>Failures:</p>
<table><tr><th>What</th><th>Where</th><th>When</th><th>Reason</th></tr>
{{range .R.Credentials.Failures}}<tr><td>{{failureKind .Kind}}{{if .Via}} via {{.Via}}{{end}}</td><td>{{.Subject}}</td><td>{{stamp .At}}</td><td>{{.Reason}}</td></tr>{{end}}
</table>{{end}}
</section>

<section>
<h2>Verification</h2>
<table>
<tr><th>Deliveries verified in the period</th><td class="num">{{.R.Verification.VerifiedDeliveries}}</td></tr>
<tr><th>Endpoints serving the expected certificate</th><td class="num">{{.R.Verification.EndpointsMatching}}</td></tr>
<tr><th>Endpoints serving a different certificate</th><td class="num">{{.R.Verification.EndpointsMismatched}}</td></tr>
<tr><th>Endpoints that could not be reached</th><td class="num">{{.R.Verification.EndpointsUnreachable}}</td></tr>
<tr><th>Endpoints checked in the period</th><td class="num">{{.R.Verification.EndpointsCheckedInPeriod}}</td></tr>
<tr><th>Credentials that changed in the period</th><td class="num">{{.R.Verification.ChangedCredentials}}</td></tr>
<tr><th>&hellip; seen served from outside {{.R.Brand.ProductName}}'s own record</th><td class="num">{{.R.Verification.IndependentlyVerified}}</td></tr>
<tr><th>&hellip; known only from {{.R.Brand.ProductName}}'s own record</th><td class="num">{{.R.Verification.RecordedOnly}}</td></tr>
<tr><th>&hellip; not verified</th><td class="num">{{.R.Verification.NotVerified}}</td></tr>
</table>
{{with .R.Verification.Note}}<p class="muted">{{.}}</p>{{end}}
</section>

<section>
<h2>Incidents</h2>
{{if .R.Incidents.Items}}<table><tr><th>Incident</th><th>Status</th><th>Opened</th><th>Updated</th><th>Evidence</th></tr>
{{range .R.Incidents.Items}}<tr><td>{{incidentKind .Kind}}{{with .Reason}}<br><span class="muted">{{.}}</span>{{end}}</td><td>{{.Status}} ({{.Phase}})</td><td>{{stamp .OpenedAt}}</td><td>{{stamp .UpdatedAt}}</td><td>{{if .EvidenceSHA256}}{{.EvidenceFormat}} <code>sha256:{{short .EvidenceSHA256}}</code>{{else}}<span class="muted">none recorded</span>{{end}}</td></tr>{{end}}
</table>{{else}}<p>No incident was open or active in this period.</p>{{end}}
</section>

<section>
<h2>Compared with the previous period</h2>
{{if .R.Changes.Comparable}}<table><tr><th>Measure</th><th class="num">Previous</th><th class="num">Now</th><th class="num">Change</th></tr>
{{range .R.Changes.Metrics}}<tr><td>{{.Label}}</td><td class="num">{{.Previous}}</td><td class="num">{{.Current}}</td><td class="num">{{if gt .Delta 0}}+{{end}}{{.Delta}}</td></tr>{{end}}
</table>{{else}}<p>{{.R.Changes.Note}}</p>{{end}}
</section>

<section>
<h2>What this report does not show</h2>
<ul>{{range .R.Limits}}<li>{{.}}</li>{{end}}</ul>
</section>

<footer>
{{with .R.Brand.Footer}}<p>{{.}}</p>{{end}}
<p>Generated {{stamp .R.GeneratedAt}}. This page is the rendering inside a signed report; verify the signed report offline before relying on it.</p>
</footer>
</main>
</body>
</html>
`))

type customerView struct {
	R    CustomerReport
	Logo template.URL
}

func renderCustomerHTML(r CustomerReport) (string, error) {
	view := customerView{R: r}
	if r.Brand.LogoDataURI != "" && logoDataURI.MatchString(r.Brand.LogoDataURI) {
		// #nosec G203 -- the logo matched logoDataURI: a base64 PNG, JPEG, GIF or WebP data URI, never script-capable SVG or another scheme (CWE-79).
		view.Logo = template.URL(r.Brand.LogoDataURI)
	}
	var out bytes.Buffer
	if err := customerTemplate.Execute(&out, view); err != nil {
		return "", err
	}
	return out.String(), nil
}
