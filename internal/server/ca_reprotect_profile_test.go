// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/decommission/reprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
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

func TestCAReprotectSignerUsesIdentitySelectedCurrentPolicy(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()
	storeServerTestProfile(t, h.store, h.tenant, "unrelated-default", profile.CertificateProfile{
		Name: "unrelated-default", AllowedDNSSuffixes: []string{"elsewhere.invalid"},
	})
	storeServerTestProfile(t, h.store, h.tenant, "selected-host-policy", profile.CertificateProfile{
		Name: "selected-host-policy", MaxValidity: profile.Duration(24 * time.Hour),
		AllowedDNSSuffixes: []string{"qa.invalid"}, AllowedProtocols: []string{"acme"},
	})
	h.handler.defaultProfile = "unrelated-default"
	owner, err := h.orch.CreateOwner(ctx, h.tenant, string(store.OwnerService), "QA host owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "host.qa.invalid", OwnerID: owner.ID,
		Attributes: json.RawMessage(`{"profile_name":"selected-host-policy"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	csr := serverTestCSR(t, "host.qa.invalid", nil)
	if _, err := h.handler.enforceProfileForCAReprotect(ctx, h.tenant, csr, []string{"host.qa.invalid"}, time.Hour); err == nil {
		t.Fatal("unrelated default unexpectedly permitted the host name")
	}
	requirement, err := h.orch.ProfileApprovalRequirementByName(ctx, h.tenant, "selected-host-policy")
	if err != nil {
		t.Fatal(err)
	}
	binding := requirement.IssuanceBinding()
	plan := reprotect.CredentialPlan{IdentityID: identity.ID, ProfileName: "selected-host-policy", TTLSeconds: 3600}
	selectedBinding, err := h.handler.caReprotectProfileBinding(ctx, h.tenant, plan)
	if err != nil || selectedBinding.ProfileName != binding.ProfileName || selectedBinding.ProfileVersion != binding.ProfileVersion || selectedBinding.EffectiveTTLSeconds != 3600 {
		t.Fatalf("signer did not bind the selected policy and reviewed TTL: %+v err=%v", selectedBinding, err)
	}
	changedPlan := plan
	changedPlan.ProfileName = "unrelated-default"
	if _, err := h.handler.caReprotectProfileBinding(ctx, h.tenant, changedPlan); err == nil {
		t.Fatal("signer accepted a policy name different from the immutable plan")
	}
	legacyPlan := plan
	legacyPlan.ProfileName = ""
	if recovered, err := h.handler.caReprotectProfileBinding(ctx, h.tenant, legacyPlan); err != nil || recovered.ProfileName != "selected-host-policy" {
		t.Fatalf("legacy plan did not recover under the identity's current selection: %+v err=%v", recovered, err)
	}
	if _, err := h.handler.enforceProfileForCAReprotect(ctx, h.tenant, csr, []string{"host.qa.invalid"}, time.Hour, binding); err != nil {
		t.Fatalf("identity-selected policy refused the reviewed host: %v", err)
	}
	storeServerTestProfile(t, h.store, h.tenant, "selected-host-policy", profile.CertificateProfile{
		Name: "selected-host-policy", AllowedDNSSuffixes: []string{"elsewhere.invalid"},
	})
	if _, err := h.handler.enforceProfileForCAReprotect(ctx, h.tenant, csr, []string{"host.qa.invalid"}, time.Hour, binding); err == nil || !strings.Contains(err.Error(), "changed before signing") {
		t.Fatalf("stale policy revision authorized signing: %v", err)
	}
	var selectedAllow, staleDeny bool
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type != "issuance.profile_evaluated" {
			return nil
		}
		var decision struct {
			Profile  string `json:"profile"`
			Version  int    `json:"version"`
			Decision string `json:"decision"`
			Protocol string `json:"protocol"`
		}
		if err := json.Unmarshal(event.Data, &decision); err != nil {
			return err
		}
		if decision.Profile == "selected-host-policy" && decision.Version == binding.ProfileVersion && decision.Protocol == "ca-reprotect" {
			selectedAllow = selectedAllow || decision.Decision == "allow"
			staleDeny = staleDeny || decision.Decision == "deny"
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !selectedAllow || !staleDeny {
		t.Fatalf("selected policy audit lost allow/deny transition: allowed=%t denied=%t", selectedAllow, staleDeny)
	}
}
