// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
)

// Check the exact client's leaf through the actual event, projection and API.
// Receiving a CSR proves no storage, exportability, or named generator claim.
func assertServedRequesterCustody(t *testing.T, h *servedHarness, leaf []byte) {
	t.Helper()
	fingerprint := crypto.SHA256Hex(leaf)
	c, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if c.KeyOrigin != string(custody.OriginRequester) || c.KeyStorage != "" || c.KeyExportable != "" || c.KeyGeneratedBy != "" {
		t.Fatalf("CSR provenance: origin=%q storage=%q exportability=%q generator=%q", c.KeyOrigin, c.KeyStorage, c.KeyExportable, c.KeyGeneratedBy)
	}
	recorded := false
	if err := h.log.Replay(t.Context(), 0, func(e events.Event) error {
		if e.TenantID != h.tenant || e.Type != "certificate.recorded" {
			return nil
		}
		var data struct {
			Fingerprint string `json:"fingerprint"`
			KeyOrigin   string `json:"key_origin"`
		}
		if err := json.Unmarshal(e.Data, &data); err != nil {
			return err
		}
		if data.Fingerprint == fingerprint && data.KeyOrigin == string(custody.OriginRequester) {
			recorded = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !recorded {
		t.Fatal("requester provenance is absent from the immutable certificate event")
	}
	token := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+c.ID, token, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"key_origin":"requester"`) || !strings.Contains(string(body), "for this issuance") {
		t.Fatalf("served custody evidence: status=%d body=%s", status, body)
	}
}
