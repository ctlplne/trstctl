// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A listener taken under management: discovery observed its old certificate at
// 127.0.0.1:10443, an operator issued and deployed a managed one, and a relay probe
// verified the managed certificate is what the listener now serves. The observed
// baseline must then read as superseded, not as a live row with an owner gap and an
// expiry due tomorrow (DP2-030). The issued row, an observation at another
// listener, and a probe that did not verify anything leave every row untouched, and
// replaying the verification converges.
func TestEndpointVerifiedSupersedesObservedBaseline(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	log := openLog(t)
	proj := projections.New(s)
	apply := func(eventType string, payload map[string]any) events.Event {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		ev, err := log.Append(ctx, events.Event{Type: eventType, TenantID: tenantA, Data: data})
		if err != nil {
			t.Fatalf("append %s: %v", eventType, err)
		}
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return proj.ApplyTx(ctx, tx, ev) }); err != nil {
			t.Fatalf("apply %s: %v", eventType, err)
		}
		return ev
	}
	tomorrow := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)
	const location, elsewhere = "127.0.0.1:10443", "127.0.0.1:10444"
	const baselineFP, managedFP, elsewhereFP = "fp-observed-baseline", "fp-managed-issued", "fp-observed-elsewhere"
	record := func(id, fingerprint, source, where string) {
		apply(projections.EventCertificateRecorded, map[string]any{
			"id": id, "subject": "CN=apache.partner-lab.example.com", "sans": []string{"apache.partner-lab.example.com"},
			"issuer": "CN=Some CA", "serial": fingerprint, "fingerprint": fingerprint, "key_algorithm": "RSA-2048",
			"not_after": tomorrow, "deployment_location": where, "source": source,
			"certificate_der": base64.StdEncoding.EncodeToString([]byte("der-" + fingerprint)),
			"certificate_pem": base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nZGVy\n-----END CERTIFICATE-----\n")),
		})
	}
	record("70707070-0000-4000-8000-000000000001", baselineFP, "discovery:network", location)
	record("70707070-0000-4000-8000-000000000002", managedFP, "issued", location)
	record("70707070-0000-4000-8000-000000000003", elsewhereFP, "discovery:network", elsewhere)

	status := func(fingerprint string) string {
		t.Helper()
		var got string
		if err := s.SystemPool().QueryRow(ctx, `SELECT status FROM certificates WHERE tenant_id = $1::uuid AND fingerprint = $2`, tenantA, fingerprint).Scan(&got); err != nil {
			t.Fatalf("status of %s: %v", fingerprint, err)
		}
		return got
	}
	verify := func(reached bool, mismatch string) map[string]any {
		return map[string]any{
			"endpoint_id": "ep-apache", "address": location, "vantage": "relay", "reached": reached, "mismatch": mismatch,
			"expected_fingerprint": managedFP, "observed_fingerprint": map[bool]string{true: managedFP, false: ""}[reached],
			"checked_sans": reached, "checked_chain": reached, "not_after": tomorrow,
		}
	}
	// A probe that never reached the listener verified nothing: the baseline stays live.
	apply(projections.EventEndpointVerified, verify(false, ""))
	if got := status(baselineFP); got != "active" {
		t.Fatalf("baseline after an unreached probe = %q, want active", got)
	}
	// The relay saw the managed certificate at the listener: the baseline is superseded.
	good := apply(projections.EventEndpointVerified, verify(true, ""))
	if got := status(baselineFP); got != "superseded" {
		t.Fatalf("baseline after the managed certificate was verified at its listener = %q, want superseded", got)
	}
	for fp, want := range map[string]string{managedFP: "active", elsewhereFP: "active"} {
		if got := status(fp); got != want {
			t.Fatalf("%s = %q, want %q (only the same-listener discovery baseline is retired)", fp, got, want)
		}
	}
	// Replaying the same verification (the tail after the inline apply) converges.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return proj.ApplyTx(ctx, tx, good) }); err != nil {
		t.Fatalf("replay verification: %v", err)
	}
	var superseded int
	if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM certificates WHERE tenant_id = $1::uuid AND status = 'superseded'`, tenantA).Scan(&superseded); err != nil {
		t.Fatal(err)
	}
	if superseded != 1 {
		t.Fatalf("superseded rows after replay = %d, want exactly the baseline", superseded)
	}
}
