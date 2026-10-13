// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"

	"github.com/jackc/pgx/v5"
)

// A late duplicate create projection must not clear a terminal revocation on
// an independently restored api_tokens row. This occurs during catch-up from a
// checkpoint older than the row in a PostgreSQL backup.
func TestAPITokenCreatedReplayPreservesTerminalRevocation(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	raw := seedScopedToken(t, h.store, h.tenant, "access:read")
	hash, err := auth.HashAPIToken([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := h.store.LookupAPITokenByHash(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	err = h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		if err := h.store.ApplyAPITokenRevokedTx(t.Context(), tx, h.tenant, rec.ID, "operator", "replay guard", at); err != nil {
			return err
		}
		return h.store.ApplyAPITokenCreatedTx(t.Context(), tx, store.APITokenRecord{
			ID: rec.ID, TenantID: h.tenant, TokenHash: hash, Subject: rec.Subject,
			Scopes: rec.Scopes, CreatedAt: rec.CreatedAt,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.store.GetAPIToken(t.Context(), h.tenant, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt == nil || got.RevokedBy != "operator" || got.RevocationReason != "replay guard" {
		t.Fatalf("late create reopened revoked bearer: %+v", got)
	}
	if status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", raw, "", nil); status != http.StatusUnauthorized {
		t.Fatalf("late create readmitted revoked bearer: status=%d body=%s", status, body)
	}
}
