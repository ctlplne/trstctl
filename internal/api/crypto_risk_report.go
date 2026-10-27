// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/cryptoreadiness"
	"trstctl.com/trstctl/internal/cryptorisk"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/keyposture"
	"trstctl.com/trstctl/internal/store"
)

// The cryptographic risk report joins the crypto inventory, the rated
// certificate inventory, the graph's dependents and the migration campaigns into
// one prioritized list. It reads every certificate a page at a time, not the
// rogue-certificate posture's single page.
const (
	cryptoRiskCertificatePage = 500
	cryptoRiskMaxCertificates = 50000
	cryptoRiskFindingPage     = 1000
	cryptoRiskMaxFindings     = 100000
	// cryptoRiskOnDemandLimit and cryptoRiskScheduledLimit bound the listed
	// items; the summary and the period comparison still count every key.
	cryptoRiskOnDemandLimit  = 1000
	cryptoRiskScheduledLimit = 20000
	cryptoRiskReportType     = "crypto_risk"
)

var cryptoRiskQuery = []param{
	{name: "limit", typ: "integer", desc: "maximum keys listed (1-1000, default 1000); the summary and the changes still count every key"},
}

// CryptoRiskExport is the report as CSV, one row per key in priority order.
type CryptoRiskExport struct {
	Filename    string    `json:"filename"`
	ContentType string    `json:"content_type"`
	GeneratedAt time.Time `json:"generated_at"`
	Truncated   bool      `json:"truncated"`
	CSV         string    `json:"csv"`
}

func (a *API) getCryptoRiskReport(w http.ResponseWriter, r *http.Request) {
	limit := cryptoRiskOnDemandLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > cryptoRiskOnDemandLimit {
			a.writeError(w, errStatus(http.StatusBadRequest, fmt.Sprintf("limit must be an integer between 1 and %d", cryptoRiskOnDemandLimit)))
			return
		}
		limit = n
	}
	report, err := a.onDemandCryptoRiskReport(r, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, report)
}

func (a *API) exportCryptoRiskReport(w http.ResponseWriter, r *http.Request) {
	report, err := a.onDemandCryptoRiskReport(r, cryptoRiskScheduledLimit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	var body bytes.Buffer
	if err := cryptorisk.WriteCSV(&body, report); err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, CryptoRiskExport{
		Filename:    "trstctl-crypto-risk-" + report.GeneratedAt.Format("20060102T150405Z") + ".csv",
		ContentType: "text/csv", GeneratedAt: report.GeneratedAt, Truncated: report.Truncated, CSV: body.String(),
	})
}

// onDemandCryptoRiskReport builds the report for the caller. Certificates are
// listed only for a caller that may read them; the comparison is with the
// tenant's newest completed scheduled report.
func (a *API) onDemandCryptoRiskReport(r *http.Request, limit int) (cryptorisk.Report, error) {
	tenantID, ok := a.tenant(r)
	if !ok {
		return cryptorisk.Report{}, errStatus(http.StatusUnauthorized, "unauthorized")
	}
	principal, _ := a.principalFor(r)
	withCertificates := principal.Can(authz.CertsRead, authz.Scope{TenantID: tenantID})
	now := time.Now().UTC()
	in, err := a.cryptoRiskInputs(r.Context(), tenantID, now, withCertificates)
	if err != nil {
		return cryptorisk.Report{}, err
	}
	in.Previous, in.PreviousNote = a.previousCryptoRiskReport(r.Context(), tenantID, "", time.Time{})
	in.Limit = limit
	report := cryptorisk.Build(in)
	if !withCertificates {
		report.Coverage += " Certificates are not listed: this token may not read certificates."
	}
	return report, nil
}

// cryptoRiskInputs reads the report's inputs under the tenant.
func (a *API) cryptoRiskInputs(ctx context.Context, tenantID string, now time.Time, withCertificates bool) (cryptorisk.Inputs, error) {
	g, err := graph.Build(ctx, a.store, tenantID)
	if err != nil {
		return cryptorisk.Inputs{}, err
	}
	readiness, err := cryptoreadiness.BuildFromGraph(ctx, a.store, tenantID, g)
	if err != nil {
		return cryptorisk.Inputs{}, err
	}
	assets, err := a.store.ListCryptoAssets(ctx, tenantID)
	if err != nil {
		return cryptorisk.Inputs{}, err
	}
	in := cryptorisk.Inputs{TenantID: tenantID, Now: now, Readiness: readiness, Assets: make([]cryptorisk.Asset, 0, len(assets))}
	for _, x := range assets {
		in.Assets = append(in.Assets, cryptorisk.Asset{
			ID: x.ID, Kind: x.Kind, Location: x.Location, Algorithm: firstNonEmpty(x.Algorithm, x.Protocol, x.Cipher), KeyBits: x.KeyBits,
			Strength: x.Strength, QuantumVulnerable: x.QuantumVulnerable, OutOfPolicy: x.OutOfPolicy, Reasons: x.Reasons,
			CertificateFingerprint: x.CertificateFingerprint,
		})
	}
	if !withCertificates {
		return in, nil
	}
	discovered, limited, err := a.discoveredKeyVerdicts(ctx, tenantID)
	if err != nil {
		return cryptorisk.Inputs{}, err
	}
	if limited {
		in.InputLimit = fmt.Sprintf("only the first %d rated discovery findings were read", cryptoRiskMaxFindings)
	}
	after, read := store.ZeroUUID, 0
	for {
		page, err := a.store.ListCertificatesPage(ctx, tenantID, after, nil, cryptoRiskCertificatePage, nil)
		if err != nil {
			return cryptorisk.Inputs{}, err
		}
		for _, c := range page {
			if c.Status == "revoked" || c.Status == "superseded" {
				continue
			}
			v := rogueCertificateVerdict(c, discovered)
			algorithm, bits := certificateKeySize(c)
			cert := cryptorisk.Certificate{
				ID: c.ID, Subject: c.Subject, Issuer: c.Issuer, Serial: c.Serial, Fingerprint: c.Fingerprint,
				Algorithm: algorithm, KeyBits: bits, WeakReasons: v.WeakReasons, Dependents: certificateDependents(g, c.ID),
			}
			if v.Distrusted() {
				cert.Distrust = &cryptorisk.Distrust{Entry: v.DistrustEntry, How: v.DistrustHow}
			}
			in.Certificates = append(in.Certificates, cert)
		}
		read += len(page)
		if len(page) < cryptoRiskCertificatePage {
			return in, nil
		}
		if read >= cryptoRiskMaxCertificates {
			in.InputLimit = strings.TrimSpace(in.InputLimit + fmt.Sprintf(" only the first %d certificates were rated", read))
			return in, nil
		}
		after = page[len(page)-1].ID
	}
}

// discoveredKeyVerdicts reads the verdict every reader recorded on a discovery
// finding while the certificate's bytes were at hand, by fingerprint.
func (a *API) discoveredKeyVerdicts(ctx context.Context, tenantID string) (map[string]keyposture.Verdict, bool, error) {
	out := map[string]keyposture.Verdict{}
	after, read := store.ZeroUUID, 0
	for {
		page, err := a.store.ListDiscoveryFindingsFiltered(ctx, tenantID, store.DiscoveryFindingFilter{KeyVerdict: true}, after, cryptoRiskFindingPage)
		if err != nil {
			return nil, false, err
		}
		for _, row := range page {
			meta := map[string]any{}
			if row.Fingerprint == "" || json.Unmarshal(row.Metadata, &meta) != nil {
				continue
			}
			if v := keyposture.FromMetadata(meta); !v.Empty() {
				fp := strings.ToLower(row.Fingerprint)
				out[fp] = out[fp].Merge(v)
			}
		}
		read += len(page)
		if len(page) < cryptoRiskFindingPage {
			return out, false, nil
		}
		if read >= cryptoRiskMaxFindings {
			return out, true, nil
		}
		after = page[len(page)-1].ID
	}
}

// certificateKeySize reads the key algorithm and size from the certificate's
// bytes when trstctl kept them, else from the recorded algorithm name
// ("RSA-2048", "ECDSA P-256"), and reports 0 bits when neither says.
func certificateKeySize(c store.Certificate) (string, int) {
	raw := c.CertificateDER
	if len(raw) == 0 {
		raw = c.CertificatePEM
	}
	if len(raw) > 0 {
		if info, err := certinfo.Inspect(raw); err == nil && info.KeyAlgorithm != "" {
			return info.KeyAlgorithm, info.PublicKeyBits
		}
	}
	return recordedKeySize(c.KeyAlgorithm)
}

func recordedKeySize(name string) (string, int) {
	name = strings.TrimSpace(name)
	upper := strings.ToUpper(name)
	for _, curve := range []struct {
		names []string
		bits  int
	}{
		{[]string{"P-224", "P224", "SECP224R1"}, 224},
		{[]string{"P-256", "P256", "SECP256R1", "PRIME256V1"}, 256},
		{[]string{"P-384", "P384", "SECP384R1"}, 384},
		{[]string{"P-521", "P521", "SECP521R1"}, 521},
	} {
		for _, n := range curve.names {
			if strings.Contains(upper, n) {
				return name, curve.bits
			}
		}
	}
	for _, token := range strings.FieldsFunc(upper, func(r rune) bool { return r < '0' || r > '9' }) {
		if bits, err := strconv.Atoi(token); err == nil && bits >= 512 && bits <= 16384 {
			return name, bits
		}
	}
	return name, 0
}

// certificateDependents is what the graph shows downstream of a certificate.
func certificateDependents(g *graph.Graph, certificateID string) cryptorisk.Dependents {
	imp := g.BlastRadius("cert:" + certificateID)
	deps := cryptorisk.Dependents{Count: len(imp.Affected), ByKind: map[string]int{}, Names: []string{}, Source: "blast_radius"}
	for kind, nodes := range imp.ByKind {
		deps.ByKind[string(kind)] = len(nodes)
	}
	for _, n := range imp.Affected {
		if len(deps.Names) == 10 {
			break
		}
		deps.Names = append(deps.Names, firstNonEmpty(n.Name, n.ID))
	}
	return deps
}

// previousCryptoRiskReport reads the newest completed crypto-risk report before
// `before` (scheduleID narrows it to one schedule) back from the report archive,
// and verifies it before anything is compared with it. When there is none, or it
// cannot be read or verified, the note says so and nothing is compared.
func (a *API) previousCryptoRiskReport(ctx context.Context, tenantID, scheduleID string, before time.Time) (*cryptorisk.Report, string) {
	payload, runID, note := a.previousScheduledReport(ctx, tenantID, scheduleID, cryptoRiskReportType, "crypto-risk", before)
	if payload == nil {
		return nil, note
	}
	var report cryptorisk.Report
	if err := json.Unmarshal(payload, &report); err != nil || report.Format != cryptorisk.Format || report.TenantID != tenantID {
		return nil, "The previous report (run " + runID + ") could not be read and verified, so nothing is compared."
	}
	return &report, ""
}

// scheduledCryptoRiskReport is the crypto_risk payload of one scheduled run,
// compared with the schedule's previous completed run.
func (a *API) scheduledCryptoRiskReport(ctx context.Context, tenantID string, schedule store.ComplianceReportSchedule) (json.RawMessage, error) {
	in, err := a.cryptoRiskInputs(ctx, tenantID, time.Now().UTC(), true)
	if err != nil {
		return nil, err
	}
	in.Previous, in.PreviousNote = a.previousCryptoRiskReport(ctx, tenantID, schedule.ID, schedule.NextRunAt)
	in.Limit = cryptoRiskScheduledLimit
	return json.Marshal(cryptorisk.Build(in))
}
