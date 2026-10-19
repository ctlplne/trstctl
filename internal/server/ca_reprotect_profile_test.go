// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/profile"
)

// A reviewed CA succession is a continuation of the exact deployed subject
// and key, not a new API enrollment. Its profile still bounds every
// certificate property; only the new-enrollment protocol allowlist is
// inapplicable. Ordinary API enrollment must keep refusing this profile.
func TestCAReprotectProfilePreservesCertificatePolicyWithoutOpeningAPIEnrollment(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()
	const name = "ca-reprotect-acme-only"
	storeServerTestProfile(t, h.store, h.tenant, name, profile.CertificateProfile{
		Name: name, MaxValidity: profile.Duration(24 * time.Hour),
		AllowedProtocols: []string{"acme"}, AllowedDNSSuffixes: []string{"qa.invalid"},
		AllowedEKUs: []string{"serverAuth"},
	})
	h.handler.defaultProfile = name
	csr := serverTestCSR(t, "host.qa.invalid", nil)
	if _, err := h.handler.enforceProfile(ctx, h.tenant, csr, []string{"host.qa.invalid"}, time.Hour); err == nil || !strings.Contains(err.Error(), `enrollment protocol "api"`) {
		t.Fatalf("ordinary API enrollment must remain refused: %v", err)
	}
	if _, err := h.handler.enforceProfileForCAReprotect(ctx, h.tenant, csr, []string{"host.qa.invalid"}, time.Hour); err != nil {
		t.Fatalf("bound administrative continuation should pass certificate policy: %v", err)
	}
	if _, err := h.handler.enforceProfileForCAReprotect(ctx, h.tenant, csr, []string{"host.qa.invalid"}, 25*time.Hour); err == nil || !strings.Contains(err.Error(), "caps validity") {
		t.Fatalf("administrative continuation must retain TTL cap: %v", err)
	}
	outside := serverTestCSR(t, "host.other.invalid", nil)
	if _, err := h.handler.enforceProfileForCAReprotect(ctx, h.tenant, outside, []string{"host.other.invalid"}, time.Hour); err == nil || !strings.Contains(err.Error(), "DNS SAN") {
		t.Fatalf("administrative continuation must retain name policy: %v", err)
	}
	clientAuth := serverTestCSR(t, "host.qa.invalid", []string{"clientAuth"})
	if _, err := h.handler.enforceProfileForCAReprotect(ctx, h.tenant, clientAuth, []string{"host.qa.invalid"}, time.Hour); err == nil || !strings.Contains(err.Error(), "extended key usage") {
		t.Fatalf("administrative continuation must retain EKU policy: %v", err)
	}
	var apiDenied, continuationAllowed bool
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type != "issuance.profile_evaluated" {
			return nil
		}
		var decision struct {
			Protocol string `json:"protocol"`
			Decision string `json:"decision"`
		}
		if err := json.Unmarshal(event.Data, &decision); err != nil {
			return err
		}
		apiDenied = apiDenied || decision.Protocol == "api" && decision.Decision == "deny"
		continuationAllowed = continuationAllowed || decision.Protocol == "ca-reprotect" && decision.Decision == "allow"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !apiDenied || !continuationAllowed {
		t.Fatalf("profile audit must distinguish denied API enrollment from allowed CA continuation: api_denied=%t continuation_allowed=%t", apiDenied, continuationAllowed)
	}
}
