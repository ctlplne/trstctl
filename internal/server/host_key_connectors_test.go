// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
	"trstctl.com/trstctl/internal/store"
)

// TestTPMHeldRenewalsAreQueuedForNginxHAProxyAndPostfixTPMO1L2: under a
// profile that requires TPM-held host keys, a renewal for an nginx, haproxy
// or postfix target is queued with key custody "tpm", the connectors proven
// against their stock packages with the tpm2 provider; any other connector,
// apache here, is refused with the connectors that can.
func TestTPMHeldRenewalsAreQueuedForNginxHAProxyAndPostfixTPMO1L2(t *testing.T) {
	hostTPM, err := deviceattesttest.NewTPMIdentity(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "profiles:write")
	spec := map[string]any{"max_validity": "12m", "allowed_protocols": []string{"api"}, "allowed_dns_suffixes": []string{"tpm.test"},
		"host_key_attestation": map[string]any{"required": true, "format": "tpm", "attestation_roots_pem": []string{string(hostTPM.RootPEM())}}}
	if code, body := secretsReq(t, h, http.MethodPost, "/api/v1/profiles", token, map[string]any{"name": "tpm-o1-l2", "spec": spec}); code != http.StatusCreated {
		t.Fatalf("profile: HTTP %d %s", code, body)
	}
	rec, err := h.store.GetActiveProfile(t.Context(), h.tenant, "tpm-o1-l2")
	if err != nil {
		t.Fatal(err)
	}
	binding := &store.OperationApprovalIssuanceBinding{ProfileName: "tpm-o1-l2", ProfileID: rec.ID,
		ProfileVersion: rec.Version, ProfileSpecDigest: store.ProfileSpecDigest(rec.Spec)}
	d := &issuanceDispatcher{store: h.store}
	for _, connector := range []string{"nginx", "haproxy", "postfix"} {
		custody, err := d.hostRenewalKeyCustody(t.Context(), h.tenant, store.DeploymentTarget{Type: connector}, binding)
		if err != nil || custody != "tpm" {
			t.Errorf("%s: custody %q, %v; want tpm", connector, custody, err)
		}
	}
	if _, err := d.hostRenewalKeyCustody(t.Context(), h.tenant, store.DeploymentTarget{Type: "apache"}, binding); err == nil ||
		!strings.Contains(err.Error(), "the apache connector cannot install one (nginx, haproxy, postfix can)") {
		t.Fatalf("apache = %v, want the connectors that can", err)
	}
}
