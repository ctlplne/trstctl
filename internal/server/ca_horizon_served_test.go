// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/store"
)

// The CA calendar, proven against the assembled binary (H5).
//
// The acceptance criterion is specific: a root expiring in 30 months raises a
// scheduled, re-firing warning whose severity scales to the horizon, and a leaf
// whose validity is compressed by an approaching parent expiry is flagged.
// Neither is reachable through leaf expiry alerting, whose widest window is 90
// days — which is exactly why an expiring root was invisible.

func seedCAAuthority(t *testing.T, ctx context.Context, st *store.Store, tenantID, cn, kind, serial string, notAfter time.Time) store.CAAuthority {
	t.Helper()
	ca, err := st.InsertCAAuthority(ctx, store.CAAuthority{
		TenantID: tenantID, CommonName: cn, Kind: kind, Status: "active",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\n" + serial + "\n-----END CERTIFICATE-----",
		Serial:         serial, NotAfter: &notAfter,
	})
	if err != nil {
		t.Fatalf("seed CA authority %s: %v", cn, err)
	}
	return ca
}

func TestServedCAHorizonAlertsYearsAheadAndReAlertsOnEachTightening(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := t.Context()

	now := time.Now().UTC()
	// 30 months out: far outside every leaf window, and exactly the point at
	// which a trust-anchor migration has to start being funded.
	root := seedCAAuthority(t, ctx, h.store, h.tenant, "acme root R1", "root", "ca-root-01", now.Add(30*30*24*time.Hour))

	alerted, err := h.srv.runCAHorizonAlertsOnce(ctx)
	if err != nil {
		t.Fatalf("first horizon sweep: %v", err)
	}
	if alerted != 1 {
		t.Fatalf("first sweep alerted %d authorities, want 1 — a root 30 months out is invisible to leaf expiry alerting", alerted)
	}

	alert := singleCAHorizonAlert(t, ctx, h.store, h.tenant)
	if alert.Kind != notify.KindCAHorizon {
		t.Fatalf("alert kind = %q, want %q", alert.Kind, notify.KindCAHorizon)
	}
	if alert.AuthorityID != root.ID || alert.Subject != "acme root R1" || alert.AuthorityKind != "root" {
		t.Fatalf("alert does not identify the authority: %+v", alert)
	}
	if alert.HorizonMonths == nil || *alert.HorizonMonths != 36 {
		t.Fatalf("alert horizon months = %v, want 36", alert.HorizonMonths)
	}
	if alert.Severity != notify.AlertSeverityLow {
		t.Fatalf("severity at 36 months = %q, want %q — three years out is a planning signal, not an alarm",
			alert.Severity, notify.AlertSeverityLow)
	}
	if alert.RenewBy.IsZero() || !alert.RenewBy.Before(alert.NotAfter) {
		t.Fatalf("alert renew_by = %v, want a date before the expiry %v", alert.RenewBy, alert.NotAfter)
	}

	// A second sweep with no time passed must be silent: the recorded band
	// already matches, so re-alerting happens on tightening, not on cadence.
	if alerted, err = h.srv.runCAHorizonAlertsOnce(ctx); err != nil || alerted != 0 {
		t.Fatalf("repeat sweep alerted %d (err %v), want 0", alerted, err)
	}

	// Tighten to five months. That is a new band, so it re-fires, and severity
	// rises with the shrinking runway — the re-alerting G5 asks for.
	if err := setAuthorityNotAfter(ctx, h.store, h.tenant, root.ID, now.Add(5*30*24*time.Hour)); err != nil {
		t.Fatalf("tighten horizon: %v", err)
	}
	if alerted, err = h.srv.runCAHorizonAlertsOnce(ctx); err != nil || alerted != 1 {
		t.Fatalf("tightened sweep alerted %d (err %v), want 1 — crossing into a tighter band is news", alerted, err)
	}
	tightened := latestCAHorizonAlert(t, ctx, h.store, h.tenant)
	if tightened.HorizonMonths == nil || *tightened.HorizonMonths != 6 {
		t.Fatalf("tightened horizon months = %v, want 6", tightened.HorizonMonths)
	}
	if tightened.Severity != notify.AlertSeverityWarning {
		t.Fatalf("severity at 6 months = %q, want %q", tightened.Severity, notify.AlertSeverityWarning)
	}
}

func TestServedCAHorizonFlagsLeafValidityCompression(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleLeafValidity = 90 * 24 * time.Hour
	})
	ctx := t.Context()

	// An intermediate with 30 days left cannot issue the 90-day leaves this
	// deployment asks for. Issuance keeps succeeding; the certificates just get
	// shorter, and nothing errors. That silent truncation is the finding.
	seedCAAuthority(t, ctx, h.store, h.tenant, "acme issuing I1", "intermediate", "ca-int-01",
		time.Now().UTC().Add(30*24*time.Hour))

	alerted, err := h.srv.runCAHorizonAlertsOnce(ctx)
	if err != nil || alerted != 1 {
		t.Fatalf("compression sweep alerted %d (err %v), want 1", alerted, err)
	}
	alert := singleCAHorizonAlert(t, ctx, h.store, h.tenant)
	if alert.Kind != notify.KindCAValidityCompression {
		t.Fatalf("alert kind = %q, want %q — a compressing parent is a different problem with a different fix",
			alert.Kind, notify.KindCAValidityCompression)
	}
	if alert.Severity != notify.AlertSeverityCritical {
		t.Fatalf("severity = %q, want %q at 30 days of parent life", alert.Severity, notify.AlertSeverityCritical)
	}
	if !strings.Contains(alert.Detail, "truncated") {
		t.Fatalf("detail must explain the truncation in plain language, got %q", alert.Detail)
	}
}

// TestServedCAHorizonStaysQuietBeyondTheWidestBand keeps the calendar from
// becoming noise: a healthy root a decade out is known, fine, and not news.
func TestServedCAHorizonStaysQuietBeyondTheWidestBand(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := t.Context()

	seedCAAuthority(t, ctx, h.store, h.tenant, "acme root R0", "root", "ca-root-00",
		time.Now().UTC().Add(10*365*24*time.Hour))

	if alerted, err := h.srv.runCAHorizonAlertsOnce(ctx); err != nil || alerted != 0 {
		t.Fatalf("sweep alerted %d (err %v) for a root ten years out, want 0", alerted, err)
	}
}

// TestServedCAAuthorityAPICarriesTheHorizon proves the console half: the horizon
// travels on the served authority list, so the CA page no longer has to decide
// for itself whether a not_after two years out is "healthy".
func TestServedCAAuthorityAPICarriesTheHorizon(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleLeafValidity = 90 * 24 * time.Hour
	})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant, "issuers:read")

	notAfter := time.Now().UTC().Add(30 * 30 * 24 * time.Hour)
	seedCAAuthority(t, ctx, h.store, h.tenant, "acme root R1", "root", "ca-root-01", notAfter)

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/ca/authorities", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list authorities = %d, want 200; body=%s", status, body)
	}
	var listed struct {
		Items []struct {
			CommonName string `json:"common_name"`
			Horizon    *struct {
				BandMonths         *int       `json:"band_months"`
				MonthsRemaining    int        `json:"months_remaining"`
				Severity           string     `json:"severity"`
				RenewBy            *time.Time `json:"renew_by"`
				ValidityCompressed bool       `json:"validity_compressed"`
				LeafValidityDays   int        `json:"leaf_validity_days"`
				Expired            bool       `json:"expired"`
			} `json:"horizon"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatalf("decode authorities: %v body=%s", err, body)
	}
	if len(listed.Items) != 1 {
		t.Fatalf("listed %d authorities, want 1; body=%s", len(listed.Items), body)
	}
	got := listed.Items[0].Horizon
	if got == nil {
		t.Fatal("the served authority carries no horizon; the console would be back to reading a raw not_after")
	}
	if got.BandMonths == nil || *got.BandMonths != 36 {
		t.Fatalf("band_months = %v, want 36", got.BandMonths)
	}
	if got.MonthsRemaining < 28 || got.MonthsRemaining > 31 {
		t.Fatalf("months_remaining = %d, want about 30", got.MonthsRemaining)
	}
	if got.RenewBy == nil || !got.RenewBy.Before(notAfter) {
		t.Fatalf("renew_by = %v, want a date before the expiry", got.RenewBy)
	}
	if got.LeafValidityDays != 90 {
		t.Fatalf("leaf_validity_days = %d, want 90 — the yardstick has to be stated for the date to be interpretable",
			got.LeafValidityDays)
	}
	if got.ValidityCompressed || got.Expired {
		t.Fatalf("a root 30 months out is neither compressing nor expired: %+v", got)
	}
}

// TestCertificateHealthDifferentiatesBeyondNinetyDays covers the other half of
// G5: the health dashboard lumped everything past 90 days into "later", which is
// how a multi-year CA expiry stayed invisible on the dashboard too.
func TestCertificateHealthDifferentiatesBeyondNinetyDays(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "66666666-6666-6666-6666-666666666666"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	now := time.Now().UTC()
	seed := func(fingerprint string, in time.Duration) {
		notAfter := now.Add(in)
		notBefore := now.Add(-time.Hour)
		if _, err := st.UpsertCertificate(ctx, store.Certificate{
			TenantID: tenantID, Subject: "CN=" + fingerprint, Fingerprint: fingerprint,
			Serial: fingerprint, Issuer: "CN=acme", KeyAlgorithm: "ECDSA-P256",
			NotBefore: &notBefore, NotAfter: &notAfter, Source: "issued",
		}); err != nil {
			t.Fatalf("seed certificate %s: %v", fingerprint, err)
		}
	}
	seed("sha256:leaf-60d", 60*24*time.Hour)
	seed("sha256:mid-200d", 200*24*time.Hour)
	seed("sha256:long-18m", 18*30*24*time.Hour)
	seed("sha256:root-30m", 30*30*24*time.Hour)
	seed("sha256:root-10y", 10*365*24*time.Hour)

	snap, err := st.CertificateHealth(ctx, tenantID, now, 25)
	if err != nil {
		t.Fatalf("certificate health: %v", err)
	}
	buckets := map[string]int{}
	total := 0
	for _, b := range snap.ExpiryBuckets {
		buckets[b.Name] = b.Count
		total += b.Count
	}
	if total != snap.Summary.Total {
		t.Fatalf("buckets sum to %d but total is %d; the bands must stay a partition", total, snap.Summary.Total)
	}
	for name, want := range map[string]int{
		"expiring_90d":  1, // the 60-day leaf
		"expiring_180d": 0,
		"expiring_1y":   1, // the 200-day certificate
		"expiring_2y":   1, // the 18-month certificate
		"expiring_3y":   1, // the 30-month root
		"later":         1, // the ten-year root
	} {
		if buckets[name] != want {
			t.Errorf("bucket %q = %d, want %d (buckets: %v)", name, buckets[name], want, buckets)
		}
	}
	if snap.Summary.Expiring3y != 4 {
		t.Errorf("cumulative expiring_3y = %d, want 4", snap.Summary.Expiring3y)
	}
	if snap.Summary.Expiring90d != 1 {
		t.Errorf("cumulative expiring_90d = %d, want 1", snap.Summary.Expiring90d)
	}
}

func setAuthorityNotAfter(ctx context.Context, st *store.Store, tenantID, id string, notAfter time.Time) error {
	return st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE ca_authorities SET not_after = $3 WHERE tenant_id = $1 AND id = $2`,
			tenantID, id, notAfter)
		return err
	})
}

func caHorizonAlerts(t *testing.T, ctx context.Context, st *store.Store, tenantID string) []notify.Alert {
	t.Helper()
	payloads := outboxPayloadsForDestination(t, ctx, st, tenantID, notify.DestinationCAHorizon)
	out := make([]notify.Alert, 0, len(payloads))
	for _, payload := range payloads {
		var alert notify.Alert
		if err := json.Unmarshal(payload, &alert); err != nil {
			t.Fatalf("decode ca-horizon alert: %v", err)
		}
		out = append(out, alert)
	}
	return out
}

func singleCAHorizonAlert(t *testing.T, ctx context.Context, st *store.Store, tenantID string) notify.Alert {
	t.Helper()
	alerts := caHorizonAlerts(t, ctx, st, tenantID)
	if len(alerts) != 1 {
		t.Fatalf("ca-horizon outbox holds %d alerts, want 1", len(alerts))
	}
	return alerts[0]
}

func latestCAHorizonAlert(t *testing.T, ctx context.Context, st *store.Store, tenantID string) notify.Alert {
	t.Helper()
	alerts := caHorizonAlerts(t, ctx, st, tenantID)
	if len(alerts) == 0 {
		t.Fatal("ca-horizon outbox is empty")
	}
	return alerts[len(alerts)-1]
}

// outboxPayloadsForDestination reads the queued notification intents directly.
// The assertions are about what the scheduler committed, not about what a channel
// happened to render, so this reads the durable evidence rather than a sink.
func outboxPayloadsForDestination(t *testing.T, ctx context.Context, st *store.Store, tenantID, destination string) [][]byte {
	t.Helper()
	var payloads [][]byte
	err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = $2 ORDER BY id`,
			tenantID, destination)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var payload []byte
			if err := rows.Scan(&payload); err != nil {
				return err
			}
			payloads = append(payloads, payload)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("read %s outbox: %v", destination, err)
	}
	return payloads
}
