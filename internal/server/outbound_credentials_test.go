// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/outboundcred"
)

// CR-008: a worker resolves a tenant-authored env reference only inside the scope
// of the tenant and integration it runs for, only when the operator bound it to
// both, and only after pinning the client it hands the value to.
func TestWorkerResolvesBoundEnvCredentialsOnlyForTheirTenantIntegrationAndOrigins(t *testing.T) {
	const (
		tenant = "c8000000-0000-4000-8000-000000000011"
		other  = "c8000000-0000-4000-8000-000000000012"
		ref    = "env:TRSTCTL_CR008_UNIT_TOKEN" // #nosec G101 -- a reference name, no credential value (CWE-798)
	)
	t.Setenv("TRSTCTL_CR008_UNIT_TOKEN", "cr008-unit-value")
	var bound, elsewhere atomic.Int32
	boundServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		bound.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer boundServer.Close()
	otherServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer otherServer.Close()
	bindings, err := outboundcred.New([]outboundcred.Binding{{Ref: ref, TenantID: tenant, Integrations: []string{"cloud_secret"},
		Origins: []string{boundServer.URL, "syslog+tls://collector.example:6514"}}})
	if err != nil {
		t.Fatal(err)
	}
	scoped := withOutboundCredentialScope(context.Background(), bindings, tenant, "cloud_secret")

	if _, err := resolveBoundCredentialRef(context.Background(), ref, &http.Client{}); !errors.Is(err, outboundcred.ErrNotBound) {
		t.Fatalf("resolution outside a tenant integration scope = %v, want ErrNotBound", err)
	}
	if _, err := resolveBoundCredentialRef(scoped, ref); !errors.Is(err, outboundcred.ErrNotBound) {
		t.Fatalf("resolution with no client to pin = %v, want ErrNotBound", err)
	}
	for name, ctx := range map[string]context.Context{
		"another tenant":      withOutboundCredentialScope(context.Background(), bindings, other, "cloud_secret"),
		"another integration": withOutboundCredentialScope(context.Background(), bindings, tenant, "audit_feed"),
	} {
		if value, err := resolveBoundCredentialRef(ctx, ref, &http.Client{}); !errors.Is(err, outboundcred.ErrNotBound) || value != "" {
			t.Fatalf("%s: resolved %q, %v; want ErrNotBound and no value", name, value, err)
		}
	}

	client := &http.Client{}
	value, err := resolveBoundCredentialRef(scoped, ref, client)
	if err != nil || value != "cr008-unit-value" {
		t.Fatalf("bound resolution = %q, %v", value, err)
	}
	if resp, err := client.Get(boundServer.URL + "/v1/secret"); err != nil {
		t.Fatalf("the pinned client refused its bound origin: %v", err)
	} else {
		_ = resp.Body.Close()
	}
	if _, err := client.Get(otherServer.URL + "/v1/secret"); !errors.Is(err, outboundcred.ErrNotBound) || elsewhere.Load() != 0 {
		t.Fatalf("the pinned client reached another origin: %v (requests there: %d)", err, elsewhere.Load())
	}
	if bound.Load() != 1 {
		t.Fatalf("bound origin saw %d requests, want 1", bound.Load())
	}

	// Fixed-destination clients name every destination instead.
	if _, err := boundCredentialEnvValue(scoped, ref, "syslog+tls://collector.example"); err != nil {
		t.Fatalf("a bound syslog destination was refused: %v", err)
	}
	if _, err := boundCredentialEnvValue(scoped, ref, "syslog+tls://collector.example:7514"); !errors.Is(err, outboundcred.ErrNotBound) {
		t.Fatalf("an unbound syslog port = %v, want ErrNotBound", err)
	}
	if _, err := boundCredentialEnvValue(scoped, ref); !errors.Is(err, outboundcred.ErrNotBound) {
		t.Fatalf("a value with no destination = %v, want ErrNotBound", err)
	}
}

// CR-008: the retired process-wide list approves nothing, and startup says which of
// its references no binding covers.
func TestRetiredEnvCredentialListWarnsAboutUnboundReferences(t *testing.T) {
	bindings, err := outboundcred.New([]outboundcred.Binding{{Ref: "env:TRSTCTL_CR008_BOUND", TenantID: "c8000000-0000-4000-8000-000000000011",
		Integrations: []string{"audit_feed"}, Origins: []string{"https://hec.example"}}})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	warnRetiredOutboundEnvCredentialRefs(slog.New(slog.NewTextHandler(&out, nil)), []string{"env:TRSTCTL_CR008_BOUND", " env:TRSTCTL_CR008_UNBOUND ",
		"env:cr008 pasted-value/not+a+name"}, bindings)
	logged := out.String()
	if !strings.Contains(logged, "level=WARN") || !strings.Contains(logged, "outbound_env_credential_bindings") ||
		!strings.Contains(logged, "env:TRSTCTL_CR008_UNBOUND") || strings.Contains(logged, "unbound_refs=[env:TRSTCTL_CR008_BOUND") {
		t.Fatalf("retired-list warning = %q", logged)
	}
	// An entry that is not a well-formed name is counted, never logged.
	if strings.Contains(logged, "pasted-value") || !strings.Contains(logged, "malformed_entries=1") {
		t.Fatalf("retired-list warning echoed a malformed entry or did not count it: %q", logged)
	}
	out.Reset()
	warnRetiredOutboundEnvCredentialRefs(slog.New(slog.NewTextHandler(&out, nil)), nil, bindings)
	if out.Len() != 0 {
		t.Fatalf("a deployment without the retired list was warned: %q", out.String())
	}
}

// CR-008 / CR-405 class: an unset variable is named for the operator only when
// the reference is a well-formed env name; a malformed one, which could be a raw
// value pasted where a reference belongs, is never echoed.
func TestUnsetEnvCredentialNamesOnlyAWellFormedVariable(t *testing.T) {
	_, err := lookupEnvCredential("env:TRSTCTL_CR008_NEVER_SET_VARIABLE")
	if err == nil || !strings.Contains(err.Error(), "TRSTCTL_CR008_NEVER_SET_VARIABLE is not set") {
		t.Fatalf("an unset well-formed variable = %v, want it named", err)
	}
	for _, raw := range []string{"env:cr008 raw-value/with+symbols", "env:9CR008", "env:" + strings.Repeat("A", 129)} {
		_, err := lookupEnvCredential(raw)
		if err == nil || strings.Contains(err.Error(), strings.TrimPrefix(raw, "env:")) {
			t.Fatalf("a malformed reference was echoed: %v", err)
		}
	}
}
