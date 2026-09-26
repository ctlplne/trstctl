// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestServedManagedTenantChecksReviewedAccountBeforeMutationAndReplay(t *testing.T) {
	h := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()}, func(d *Deps) {
		d.License = testManagedOfferingLicenseManager(t)
	})
	registerServedTenant(t, h, "Reviewed provider account fixture")
	const subject = "provider-operator+東京"
	token := seedScopedTokenSubject(t, h.store, h.tenant, subject, "access:read", "access:write")
	const customer = "77777777-7777-4777-8777-777777777777"
	const key = "reviewed-account-registration"
	requestBody, err := json.Marshal(map[string]string{"tenant_id": customer, "name": "Reviewed customer"})
	if err != nil {
		t.Fatal(err)
	}
	send := func(tenant string, subjects []string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/managed-offering/tenants", bytes.NewReader(requestBody))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		if tenant != "" {
			req.Header.Set("X-Tenant-ID", tenant)
		}
		for _, value := range subjects {
			req.Header.Add("X-Trstctl-Expected-Subject", value)
		}
		res, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, body
	}
	for _, tc := range []struct {
		name     string
		tenant   string
		subjects []string
		status   int
	}{
		{"changed operator", h.tenant, []string{"previous-operator"}, http.StatusConflict},
		{"changed tenant", "88888888-8888-4888-8888-888888888888", []string{url.PathEscape(subject)}, http.StatusForbidden},
		{"duplicate subject", h.tenant, []string{url.PathEscape(subject), "previous-operator"}, http.StatusBadRequest},
		{"malformed subject", h.tenant, []string{"%zz"}, http.StatusBadRequest},
		{"empty subject", h.tenant, []string{""}, http.StatusBadRequest},
		{"missing tenant assertion", "", []string{url.PathEscape(subject)}, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := send(tc.tenant, tc.subjects)
			if status != tc.status {
				t.Fatalf("reviewed account refusal = %d, want %d", status, tc.status)
			}
			if got := managedTenantRegisteredEvents(t, h.log, customer); len(got) != 0 {
				t.Fatalf("refused account emitted %d registration events", len(got))
			}
			if _, err := h.store.GetTenant(context.Background(), customer); err == nil {
				t.Fatal("refused account created a tenant")
			}
		})
		if t.Failed() {
			return
		}
	}
	status, original := send(h.tenant, []string{url.PathEscape(subject)})
	if status != http.StatusCreated {
		t.Fatalf("matching reviewed account = %d, want 201", status)
	}
	if status, _ := send(h.tenant, []string{"previous-operator"}); status != http.StatusConflict {
		t.Fatalf("cached result bypassed reviewed account assertion: %d", status)
	}
	status, replay := send(h.tenant, []string{url.PathEscape(subject)})
	if status != http.StatusCreated || !bytes.Equal(original, replay) {
		t.Fatal("matching reviewed account did not recover the original result")
	}
	if got := managedTenantRegisteredEvents(t, h.log, customer); len(got) != 1 {
		t.Fatalf("registration event count = %d, want 1", len(got))
	}
}
