// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

type stubDriller struct {
	report IsolationDrillReport
	err    error
	calls  int
}

func (d *stubDriller) RunIsolationDrill(context.Context) (IsolationDrillReport, error) {
	d.calls++
	return d.report, d.err
}

func drillService(t *testing.T, audit *captureAudit, driller IsolationDriller) *Service {
	t.Helper()
	return NewService(Config{
		License: providerLicense(t, 0),
		Audit:   audit,
		Drills:  driller,
		Clock:   fixedClock(),
	})
}

// The isolation drill is deployment-wide assurance: it is admin-only, it records
// an attestation of the outcome, and it stamps the recorded time.
func TestIsolationDrillIsAdminOnlyAndRecordsAttestation(t *testing.T) {
	ctx := context.Background()
	audit := &captureAudit{}
	driller := &stubDriller{report: IsolationDrillReport{
		Passed: true,
		Checks: []IsolationDrillCheck{{Name: "cross_tenant_read_denied", Passed: true}},
	}}
	svc := drillService(t, audit, driller)

	report, err := svc.RunIsolationDrill(ctx, providerOperator("op-1"))
	if err != nil {
		t.Fatalf("admin drill: %v", err)
	}
	if !report.Passed || driller.calls != 1 {
		t.Fatalf("report=%+v calls=%d, want a passed report from one drill", report, driller.calls)
	}
	if report.RanAt != fixedClock()() {
		t.Fatalf("RanAt = %v, want it stamped from the service clock", report.RanAt)
	}
	if !audit.Contains("provider.isolation.drill") {
		t.Fatalf("no attestation recorded; audit types = %v", audit.Types())
	}
}

// A non-admin operator — however fully delegated — cannot probe the whole
// deployment's isolation. Removing the admin gate makes this pass a drill.
func TestIsolationDrillRefusesNonAdmin(t *testing.T) {
	ctx := context.Background()
	audit := &captureAudit{}
	driller := &stubDriller{report: IsolationDrillReport{Passed: true}}
	svc := drillService(t, audit, driller)

	operator := Operator{ID: "op-2", Email: "op2@provider.example.test", Role: OperatorOperator, MFA: true}
	if _, err := svc.RunIsolationDrill(ctx, operator); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin drill error = %v, want ErrForbidden", err)
	}
	if driller.calls != 0 {
		t.Fatalf("the driller ran %d times for a refused operator; the gate must precede it", driller.calls)
	}
	if audit.Contains("provider.isolation.drill") {
		t.Fatalf("a refused drill still recorded an attestation")
	}
}

// A plane with no driller attached must refuse rather than report a pass nothing
// tested.
func TestIsolationDrillRefusesWithoutADriller(t *testing.T) {
	ctx := context.Background()
	audit := &captureAudit{}
	svc := drillService(t, audit, nil)

	_, err := svc.RunIsolationDrill(ctx, providerOperator("op-1"))
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("drill without a driller = %v, want ErrForbidden", err)
	}
	if audit.Contains("provider.isolation.drill") {
		t.Fatalf("recorded an attestation with nothing to attest")
	}
}

// A drill that RAN and found isolation broken is recorded — the failed drill is
// the one that most needs to be on the record — and returned as Passed=false,
// not swallowed as an error.
func TestFailedIsolationDrillIsStillRecorded(t *testing.T) {
	ctx := context.Background()
	audit := &captureAudit{}
	driller := &stubDriller{report: IsolationDrillReport{
		Passed: false,
		Checks: []IsolationDrillCheck{{Name: "cross_tenant_write_refused", Passed: false, Detail: "hijack accepted"}},
	}}
	svc := drillService(t, audit, driller)

	report, err := svc.RunIsolationDrill(ctx, providerOperator("op-1"))
	if err != nil {
		t.Fatalf("a failed drill must not surface as an error: %v", err)
	}
	if report.Passed {
		t.Fatalf("report.Passed = true, want false")
	}
	if !audit.Contains("provider.isolation.drill") {
		t.Fatalf("a failed drill was not recorded; audit types = %v", audit.Types())
	}
	if reason := audit.events[len(audit.events)-1].Reason; reason != "failed" {
		t.Fatalf("attestation outcome = %q, want \"failed\"", reason)
	}
}

// The drill is reachable on the wire: POST /provider/v1/isolation-drill runs it
// and returns the report as JSON with a 200, whatever the result.
func TestIsolationDrillServedRoute(t *testing.T) {
	audit := &captureAudit{}
	h := NewHandler(Config{
		License:       providerLicense(t, 0),
		Authenticator: stubAuth{accept: "Bearer real-credential"},
		Audit:         audit,
		Drills: &stubDriller{report: IsolationDrillReport{
			Passed: true,
			Checks: []IsolationDrillCheck{{Name: "cross_tenant_read_denied", Passed: true}},
		}},
		Clock: fixedClock(),
	})
	rec := providerRequest(t, h, http.MethodPost, "/provider/v1/isolation-drill", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("drill route = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var report IsolationDrillReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode served report: %v", err)
	}
	if !report.Passed || len(report.Checks) != 1 {
		t.Fatalf("served report = %+v, want one passed check", report)
	}
	if !audit.Contains("provider.isolation.drill") {
		t.Fatalf("served drill recorded no attestation; types = %v", audit.Types())
	}
}
