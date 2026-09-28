// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestServedImportSourceLabelCannotAssertIssuance(t *testing.T) {
	h := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()})
	registerServedTenant(t, h, "Imported certificate tenant fixture")
	token := seedScopedToken(t, h.store, h.tenant, "certs:write", "certs:read")
	for _, source := range []string{"issued", "protocol:acme", "external-ca:owned-authority"} {
		t.Run(source, func(t *testing.T) {
			code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates", token, "import-label-"+source, map[string]any{"pem": servedCloudCertPEM(t, "import.example.test"), "source": source})
			if code != http.StatusCreated {
				t.Fatalf("import status=%d body=%s", code, body)
			}
			var imported struct {
				Source string `json:"source"`
			}
			if err := json.Unmarshal(body, &imported); err != nil {
				t.Fatal(err)
			}
			if imported.Source != source {
				t.Error("operator's source label was changed")
			}
			var unexpected int
			if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
				return tx.QueryRow(t.Context(), `SELECT count(*) FROM certificate_metadata_receipts WHERE tenant_id=$1 AND issuance_status IS DISTINCT FROM 'not_mint'`, h.tenant).Scan(&unexpected)
			}); err != nil {
				t.Fatal(err)
			}
			if unexpected != 0 {
				t.Errorf("ordinary import created %d mint or unverified-issuance facts; want no issuance assertion", unexpected)
			}
		})
	}
}
