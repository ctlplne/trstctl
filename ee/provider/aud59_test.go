// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

const aud59ProviderCredential = "Bearer aud59-provider-operator" // #nosec G101 -- deterministic non-deployable test bearer (CWE-798).

var (
	aud59PeriodStart = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	aud59PeriodEnd   = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
)

// aud59EvidenceStore records every customer whose billing data was touched.
// That makes the important negative observable: an undelegated path must be
// refused BEFORE even a coverage query runs, or timing still reveals whether
// that customer has usage.
type aud59EvidenceStore struct {
	records  map[string][]billing.UsageRecord
	issued   map[string]int64
	askedFor []string
}

func (s *aud59EvidenceStore) CoverageFor(_ context.Context, tenantID string) (billing.Coverage, error) {
	s.askedFor = append(s.askedFor, "coverage:"+tenantID)
	return billing.Coverage{
		Durable:      true,
		ObservedFrom: aud59PeriodStart.Add(-time.Hour),
		ObservedTo:   aud59PeriodEnd.Add(time.Hour),
	}, nil
}

func (s *aud59EvidenceStore) Query(_ context.Context, from, to time.Time, tenantID string) ([]billing.UsageRecord, error) {
	s.askedFor = append(s.askedFor, "usage:"+tenantID)
	var out []billing.UsageRecord
	for _, record := range s.records[tenantID] {
		if !record.PeriodStart.Before(from) && record.PeriodStart.Before(to) {
			out = append(out, record)
		}
	}
	return out, nil
}

func (s *aud59EvidenceStore) IssuedInPeriod(_ context.Context, tenantID string, _, _ time.Time) (int64, bool, error) {
	s.askedFor = append(s.askedFor, "reconcile:"+tenantID)
	return s.issued[tenantID], true, nil
}

func aud59EvidenceQuery(format string) string {
	query := "?period_start=" + aud59PeriodStart.Format(time.RFC3339) +
		"&period_end=" + aud59PeriodEnd.Format(time.RFC3339)
	if format != "" {
		query += "&format=" + format
	}
	return query
}

func aud59Request(handler http.Handler, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", aud59ProviderCredential)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func aud59Handler(t *testing.T, store *aud59EvidenceStore, delegations StaticDelegations) (http.Handler, *jose.SigningKey) {
	t.Helper()
	key, err := jose.GenerateRSASigningKey("aud59-audit-evidence")
	if err != nil {
		t.Fatal(err)
	}
	publicJWKS, err := key.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	return NewHandler(Config{
		License:       providerLicense(t, 10),
		Authenticator: stubAuth{accept: aud59ProviderCredential},
		Delegations:   delegations,
		Evidence: billing.EvidenceDeps{
			Reader: store, Reconciler: store, Signer: &billing.AuditKeySigner{Key: key},
		},
		EvidenceVerificationJWKS: publicJWKS,
	}), key
}

func TestAUD59ProviderEvidenceAuthorizesBeforeCustomerRLSRead(t *testing.T) {
	store := &aud59EvidenceStore{
		records: map[string][]billing.UsageRecord{},
		issued:  map[string]int64{},
	}
	handler, _ := aud59Handler(t, store, StaticDelegations{
		{OperatorID: "op-1", CustomerID: "tenant-alpha", Operations: []Operation{OpRead}},
		{OperatorID: "op-1", CustomerID: "tenant-bravo", Operations: []Operation{OpRead}},
		// Charlie exists from billing's point of view, but this operator has no
		// row. Knowing its path must not be enough to read it.
	})

	for _, customer := range []string{"tenant-alpha", "tenant-bravo"} {
		rec := aud59Request(handler, "/provider/v1/tenants/"+customer+"/usage-evidence"+aud59EvidenceQuery(""))
		if rec.Code != http.StatusOK {
			t.Fatalf("delegated customer %s evidence = %d body=%s", customer, rec.Code, rec.Body.String())
		}
	}
	before := len(store.askedFor)
	denied := aud59Request(handler, "/provider/v1/tenants/tenant-charlie/usage-evidence"+aud59EvidenceQuery(""))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("undelegated customer evidence = %d body=%s, want 403", denied.Code, denied.Body.String())
	}
	if got := store.askedFor[before:]; len(got) != 0 {
		t.Fatalf("undelegated customer reached billing storage: %v", got)
	}

	wrongOperation, _ := aud59Handler(t, store, StaticDelegations{
		{OperatorID: "op-1", CustomerID: "tenant-alpha", Operations: []Operation{OpSuspend}},
	})
	before = len(store.askedFor)
	denied = aud59Request(wrongOperation, "/provider/v1/tenants/tenant-alpha/usage-evidence"+aud59EvidenceQuery(""))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("suspend-only grant read billing evidence with status %d", denied.Code)
	}
	if got := store.askedFor[before:]; len(got) != 0 {
		t.Fatalf("wrong-operation grant reached billing storage: %v", got)
	}
}

func TestAUD59ProviderEvidenceReturnsVerifiableJSONAndFinanceCSV(t *testing.T) {
	store := &aud59EvidenceStore{
		records: map[string][]billing.UsageRecord{
			"tenant-alpha": {{
				TenantID: "tenant-alpha", Meter: usage.MeterCertificatesIssued,
				Kind: billing.KindCounter, Value: 3, PeriodStart: aud59PeriodStart.Add(14 * 24 * time.Hour),
			}},
		},
		issued: map[string]int64{"tenant-alpha": 3},
	}
	handler, key := aud59Handler(t, store, StaticDelegations{
		{OperatorID: "op-1", CustomerID: "tenant-alpha", Operations: []Operation{OpRead}},
	})

	jsonResponse := aud59Request(handler, "/provider/v1/tenants/tenant-alpha/usage-evidence"+aud59EvidenceQuery(""))
	if jsonResponse.Code != http.StatusOK || !strings.HasPrefix(jsonResponse.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("JSON evidence = %d content-type=%q body=%s", jsonResponse.Code, jsonResponse.Header().Get("Content-Type"), jsonResponse.Body.String())
	}
	var document billing.EvidenceDocument
	if err := json.Unmarshal(jsonResponse.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode JSON evidence: %v", err)
	}
	if !document.Signable || document.CustomerID != "tenant-alpha" || document.Signature == nil {
		t.Fatalf("signed Provider evidence lost authority or customer binding: %+v", document)
	}
	canonical, err := key.JWKS().VerifyArtifact(document.Signature.JWS, jose.ArtifactBillingInvoice)
	if err != nil {
		t.Fatalf("verify invoice JWS: %v", err)
	}
	if got := crypto.SHA256Hex(canonical); got != document.Digest {
		t.Fatalf("verified JWS payload digest = %s, document digest = %s", got, document.Digest)
	}

	keysResponse := aud59Request(handler, "/provider/v1/evidence/verification-keys")
	if keysResponse.Code != http.StatusOK {
		t.Fatalf("Provider verification keys = %d body=%s", keysResponse.Code, keysResponse.Body.String())
	}
	keys, err := jose.ParseJWKSet(keysResponse.Body.Bytes())
	if err != nil {
		t.Fatalf("parse served verification keys: %v", err)
	}
	if _, err := keys.VerifyArtifact(document.Signature.JWS, jose.ArtifactBillingInvoice); err != nil {
		t.Fatalf("served public keys do not verify the served invoice: %v", err)
	}

	csvResponse := aud59Request(handler, "/provider/v1/tenants/tenant-alpha/usage-evidence"+aud59EvidenceQuery("csv"))
	if csvResponse.Code != http.StatusOK || !strings.HasPrefix(csvResponse.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("CSV evidence = %d content-type=%q body=%s", csvResponse.Code, csvResponse.Header().Get("Content-Type"), csvResponse.Body.String())
	}
	if disposition := csvResponse.Header().Get("Content-Disposition"); !strings.Contains(disposition, "tenant-alpha") {
		t.Fatalf("CSV filename does not bind the selected customer: %q", disposition)
	}
	rows, err := csv.NewReader(strings.NewReader(csvResponse.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("strict finance CSV parse: %v", err)
	}
	if len(rows) != 2 || strings.Join(rows[0], ",") != strings.Join(billing.EvidenceCSVHeader, ",") {
		t.Fatalf("finance CSV shape = %#v", rows)
	}
	if rows[1][0] != "tenant-alpha" || rows[1][3] != "true" || rows[1][5] != usage.MeterCertificatesIssued || rows[1][7] != "3" || rows[1][8] != "true" || rows[1][10] != document.Digest {
		t.Fatalf("finance row drifted from signed JSON: %#v", rows[1])
	}
}

func aud59SeedIssuedTransition(t *testing.T, store *corestore.Store, tenantID string, sequence int64, at time.Time) {
	t.Helper()
	if err := store.WithTenant(t.Context(), tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(),
			`INSERT INTO identity_transitions
			 (tenant_id, identity_id, seq, from_state, to_state, event_type, occurred_at)
			 VALUES ($1, gen_random_uuid(), $2, 'pending', 'issued', 'identity.issued', $3)`,
			tenantID, sequence, at)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAUD59ProviderEvidenceSurvivesRestartAndRefusesReconciliationDivergence(t *testing.T) {
	ctx := t.Context()
	tenantID := CustomerID("aud59-restart-customer")
	firstStore := openProviderStore(t)
	firstBilling := billing.NewPGStore(firstStore)
	midpoint := aud59PeriodStart.Add(14 * 24 * time.Hour)
	if err := firstBilling.AddCounters(ctx, []billing.CounterDelta{
		{TenantID: tenantID, Meter: usage.MeterCertificatesIssued, Period: aud59PeriodStart.Add(-time.Hour), Delta: 0},
		{TenantID: tenantID, Meter: usage.MeterCertificatesIssued, Period: midpoint, Delta: 3},
		{TenantID: tenantID, Meter: usage.MeterCertificatesIssued, Period: aud59PeriodEnd.Add(time.Hour), Delta: 0},
	}); err != nil {
		t.Fatal(err)
	}
	for sequence := int64(1); sequence <= 3; sequence++ {
		aud59SeedIssuedTransition(t, firstStore, tenantID, sequence, midpoint.Add(time.Duration(sequence)*time.Minute))
	}
	firstStore.Close()

	// A fresh Store and PGStore share no process memory with the writer above.
	// The only surviving authority is PostgreSQL's forced-RLS meter/coverage and
	// independently projected event history.
	restartedStore, err := corestore.Open(ctx, providerTestDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restartedStore.Close() })
	restartedBilling := billing.NewPGStore(restartedStore)
	key, err := jose.GenerateRSASigningKey("aud59-restart-audit")
	if err != nil {
		t.Fatal(err)
	}
	publicJWKS, err := key.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(Config{
		License:       providerLicense(t, 10),
		Authenticator: stubAuth{accept: aud59ProviderCredential},
		Delegations: StaticDelegations{{
			OperatorID: "op-1", CustomerID: tenantID, Operations: []Operation{OpRead},
		}},
		Evidence: billing.EvidenceDeps{
			Reader: restartedBilling, Reconciler: restartedBilling,
			Signer: &billing.AuditKeySigner{Key: key},
		},
		EvidenceVerificationJWKS: publicJWKS,
	})

	path := "/provider/v1/tenants/" + tenantID + "/usage-evidence" + aud59EvidenceQuery("")
	first := aud59Request(handler, path)
	if first.Code != http.StatusOK {
		t.Fatalf("evidence after restart = %d body=%s", first.Code, first.Body.String())
	}
	var agreed billing.EvidenceDocument
	if err := json.Unmarshal(first.Body.Bytes(), &agreed); err != nil {
		t.Fatal(err)
	}
	if !agreed.Signable || agreed.Signature == nil || len(agreed.Lines) != 1 || agreed.Lines[0].Value != 3 {
		t.Fatalf("restart lost durable/reconciled evidence: %+v", agreed)
	}

	// Skew only the meter. A second Provider pull must name the disagreement and
	// remove the signature instead of letting a durable but wrong 4 look green.
	if err := restartedBilling.AddCounters(ctx, []billing.CounterDelta{{
		TenantID: tenantID, Meter: usage.MeterCertificatesIssued, Period: midpoint, Delta: 1,
	}}); err != nil {
		t.Fatal(err)
	}
	divergedResponse := aud59Request(handler, path)
	if divergedResponse.Code != http.StatusOK {
		t.Fatalf("divergent evidence response = %d body=%s", divergedResponse.Code, divergedResponse.Body.String())
	}
	var diverged billing.EvidenceDocument
	if err := json.Unmarshal(divergedResponse.Body.Bytes(), &diverged); err != nil {
		t.Fatal(err)
	}
	if diverged.Signable || diverged.Signature != nil || !strings.Contains(diverged.Reason, "4") || !strings.Contains(diverged.Reason, "3") {
		t.Fatalf("meter/event divergence was presented as invoice evidence: %+v", diverged)
	}
}
