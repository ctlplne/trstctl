// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/store"
)

func TestCR063SwitchingWatchRequiresPrivateEgressGrant(t *testing.T) {
	private, err := tlsprobe.NewServingTestServer("svc.cr063.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(private.Close)
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "cr063-certs-writer", "certs:read", "certs:write")
	call := func(method, path, key string, payload any) (int, []byte) {
		t.Helper()
		return doBearer(t, h.ts, method, path, tok, key, payload)
	}
	export, err := json.Marshal(map[string]any{"certificates": []map[string]any{{
		"certificate_pem": string(private.LeafPEM), "folder": "Web/Internal", "application": "cr063",
		"owner_email": "owner@cr063.test", "endpoints": []string{private.Addr},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"name": "CR063 watch", "export": string(export)}
	code, body := call(http.MethodPost, "/api/v1/switching/imports/preview", "", request)
	if code != http.StatusOK {
		t.Fatalf("preview = HTTP %d %s", code, body)
	}
	var preview struct {
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(body, &preview); err != nil || preview.Digest == "" {
		t.Fatalf("preview digest = %q (%v)", preview.Digest, err)
	}
	request["preview_digest"] = preview.Digest
	code, body = call(http.MethodPost, "/api/v1/switching/imports", "cr063-import", request)
	if code != http.StatusCreated {
		t.Fatalf("apply = HTTP %d %s", code, body)
	}
	var imp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &imp); err != nil || imp.ID == "" {
		t.Fatalf("import ID = %q (%v)", imp.ID, err)
	}
	for i := 0; i < 20; i++ {
		if _, err := h.srv.ApplySwitchingImportsOnce(ctx); err != nil {
			t.Fatal(err)
		}
		got, err := h.store.GetSwitchingImport(ctx, h.tenant, imp.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status == "completed" {
			break
		}
		if i == 19 {
			t.Fatal("import did not complete")
		}
	}
	code, body = call(http.MethodPost, "/api/v1/switching/imports/"+imp.ID+"/watch", "cr063-private-watch", map[string]any{
		"allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32"},
	})
	if code != http.StatusForbidden {
		t.Fatalf("certs:write without egress:private queued a private watch: HTTP %d %s", code, body)
	}

	granter := seedScopedTokenSubject(t, h.store, h.tenant, "cr063-private-granter", "certs:read", "certs:write", "egress:private")
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/switching/imports/"+imp.ID+"/watch", granter,
		"cr063-authorized-private-watch", map[string]any{
			"allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32"},
		})
	if code != http.StatusOK {
		t.Fatalf("authorized private watch = HTTP %d %s", code, body)
	}
	before := time.Now().UTC()
	for i := 0; i < 10; i++ {
		if _, err := h.srv.applySwitchingImportsAt(ctx, before); err != nil {
			t.Fatal(err)
		}
		got, err := h.store.GetSwitchingImport(ctx, h.tenant, imp.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.WatchRound == 1 && got.WatchPending == 0 {
			break
		}
		if i == 9 {
			t.Fatal("authorized watch did not finish")
		}
	}
	if recorded, err := h.store.GetSwitchingImport(ctx, h.tenant, imp.ID); err != nil || recorded.WatchGrantBy != "cr063-private-granter" {
		t.Fatalf("projected private grant author = %q (%v)", recorded.WatchGrantBy, err)
	}
	if _, err := h.srv.applySwitchingImportsAt(ctx, before.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	continued, err := h.store.GetSwitchingImport(ctx, h.tenant, imp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if continued.WatchRound != 2 || !continued.WatchAllowPrivate || continued.WatchGrantBy != "cr063-private-granter" {
		t.Fatalf("daily scheduler lost a still-authorized private grant: round=%d private=%t author=%q",
			continued.WatchRound, continued.WatchAllowPrivate, continued.WatchGrantBy)
	}
	if _, err := h.srv.applySwitchingImportsAt(ctx, before.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashAPIToken([]byte(granter))
	if err != nil {
		t.Fatal(err)
	}
	record, err := h.store.LookupAPITokenByHash(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "cr063-access-admin", "access:read", "access:write")
	code, body = doBearer(t, h.ts, http.MethodDelete, "/api/v1/access/api-tokens/"+record.ID, admin,
		"cr063-revoke-granter", nil)
	if code != http.StatusNoContent {
		t.Fatalf("revoke private-egress granter = HTTP %d %s", code, body)
	}
	if _, err := h.srv.applySwitchingImportsAt(ctx, before.Add(50*time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := h.store.GetSwitchingImport(ctx, h.tenant, imp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.WatchRound < 3 || got.WatchAllowPrivate {
		t.Fatalf("daily scheduler reused a revoked private-egress grant: round=%d private=%t", got.WatchRound, got.WatchAllowPrivate)
	}

	// Revocation can also race a round already queued by an authorized user.
	// The worker must replace that pending private round before its first dial.
	secondGranter := seedScopedTokenSubject(t, h.store, h.tenant, "cr063-pending-granter", "certs:read", "certs:write", "egress:private")
	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/switching/imports/"+imp.ID+"/watch", secondGranter,
		"cr063-pending-private-watch", map[string]any{
			"allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32"},
		})
	if code != http.StatusOK {
		t.Fatalf("queue authorized pending watch = HTTP %d %s", code, body)
	}
	secondHash, err := auth.HashAPIToken([]byte(secondGranter))
	if err != nil {
		t.Fatal(err)
	}
	secondRecord, err := h.store.LookupAPITokenByHash(ctx, secondHash)
	if err != nil {
		t.Fatal(err)
	}
	code, body = doBearer(t, h.ts, http.MethodDelete, "/api/v1/access/api-tokens/"+secondRecord.ID, admin,
		"cr063-revoke-pending-granter", nil)
	if code != http.StatusNoContent {
		t.Fatalf("revoke pending watch granter = HTTP %d %s", code, body)
	}
	if _, err := h.srv.applySwitchingImportsAt(ctx, before.Add(51*time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err = h.store.GetSwitchingImport(ctx, h.tenant, imp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.WatchRound < 5 || got.WatchAllowPrivate {
		t.Fatalf("pending watch used its revoked private-egress grant: round=%d private=%t", got.WatchRound, got.WatchAllowPrivate)
	}
}

func TestCR063SwitchingWatchDoesNotPublishRawDialError(t *testing.T) {
	const internalDetail = "CR063_INTERNAL_SERVICE_DETAIL"
	result := observeSwitchingRow(context.Background(), store.SwitchingImportRow{
		Row: 1, Endpoints: []string{"127.0.0.1:443"},
	}, nil, func(_ string, _ string, _ syscall.RawConn) error { return errors.New(internalDetail) })
	if result.Status != store.SwitchingWatchUnreachable {
		t.Fatalf("watch status = %q, want unreachable", result.Status)
	}
	if strings.Contains(result.Detail, internalDetail) || strings.Contains(result.Detail, "127.0.0.1") {
		t.Fatalf("watch detail leaked the raw dial error: %q", result.Detail)
	}
}
