// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
	succapi "trstctl.com/trstctl/internal/succession/api"
	succorch "trstctl.com/trstctl/internal/succession/orchestrator"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

// TestKEMRewrap_ConfiguredOutboxTopicBinds is the AUD-7 regression: the
// operator's pcas.kem.outbox_topic must actually bind. Before the fix the key
// was validated and printed while enqueue AND dispatch both used the hardcoded
// constant — re-pointing the topic changed nothing. This drives the SERVED
// route built by the same factory the attach seam mounts, with a namespaced
// topic, and asserts (a) the enqueued outbox row carries the CONFIGURED
// destination and (b) the licensed dispatcher configured the same way OWNS both
// that destination and the canonical constant — the latter so rows enqueued
// before a topic change are never orphaned.
func TestKEMRewrap_ConfiguredOutboxTopicBinds(t *testing.T) {
	const namespacedTopic = "acme.pcas.kem-rewrap"
	ctx := context.Background()

	base, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("admin open: %v", err)
	}
	if _, err := base.SystemPool().Exec(ctx, "DROP DATABASE IF EXISTS pcas_topic_cfg"); err != nil {
		t.Fatalf("drop db: %v", err)
	}
	if _, err := base.SystemPool().Exec(ctx, "CREATE DATABASE pcas_topic_cfg"); err != nil {
		t.Fatalf("create db: %v", err)
	}
	base.Close()
	cs, err := corestore.Open(ctx, strings.TrimSuffix(testDSN, "/postgres")+"/pcas_topic_cfg")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(cs.Close)
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	outbox := orchestrator.NewOutbox(cs)
	factory := succapi.NewAPIOptionsFactory(succapi.WithOutboxTopics("", "", namespacedTopic))
	licensed, err := factory(editionseam.LicensedAPIOptionsDeps{Store: cs, Outbox: outbox})
	if err != nil {
		t.Fatalf("api options factory: %v", err)
	}
	principal := authz.Principal{TenantID: tenantA, Subject: "op", Grants: []authz.Grant{{Role: pcasRole, Scope: authz.Scope{TenantID: tenantA}}}}
	served := api.New(cs, orchestrator.NewIdempotency(cs), nil, append([]api.Option{
		api.WithRoles(pcasRole),
		api.WithPrincipalResolver(func(*http.Request) (authz.Principal, error) { return principal, nil }),
	}, licensed...)...)

	body := `{"identity_id":"spiffe://d/id","predecessor_handle":"pred","successor_sign_handle":"sig","successor_kem_handle":"kem","signing_algorithm":"ML-DSA-65","kem_algorithm":"ML-KEM-768"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pcas/kem/rewraps", bytes.NewBufferString(body))
	req.Header.Set("Idempotency-Key", "kem-topic-1")
	rr := httptest.NewRecorder()
	served.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST kem rewrap = %d body=%s, want 202", rr.Code, rr.Body.String())
	}

	// (a) The row landed under the CONFIGURED topic, not the constant.
	countAt := func(dest string) int {
		var n int
		err := cs.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT count(*) FROM outbox WHERE tenant_id = current_setting('trstctl.tenant_id')::uuid AND destination = $1`,
				dest).Scan(&n)
		})
		if err != nil {
			t.Fatalf("count outbox rows at %q: %v", dest, err)
		}
		return n
	}
	if got := countAt(namespacedTopic); got != 1 {
		t.Fatalf("outbox rows at configured topic %q = %d, want 1", namespacedTopic, got)
	}
	if got := countAt(succorch.KEMRewrapDestination); got != 0 {
		t.Fatalf("outbox rows at canonical constant = %d, want 0 (the configured topic must bind on enqueue)", got)
	}

	// (b) The dispatcher configured with the SAME topics owns the configured
	// destination — and still owns the canonical constant, so pre-change rows
	// are not orphaned. KEM custody is deliberately absent: a fail-closed
	// substrate error with handled=true is the correct answer; handled=false
	// would dead-letter the row as "unsupported destination" (the AUD-5 shape).
	handler, err := succorch.NewLicensedOutboxFactory(
		succorch.WithBreadthTopics("", "", namespacedTopic))(editionseam.LicensedOutboxDeps{Store: cs})
	if err != nil {
		t.Fatalf("outbox factory: %v", err)
	}
	for _, dest := range []string{namespacedTopic, succorch.KEMRewrapDestination} {
		handled, _ := handler.DeliverLicensed(ctx, orchestrator.Message{TenantID: tenantA, Destination: dest})
		if !handled {
			t.Fatalf("licensed dispatcher does not own destination %q — enqueued rows would dead-letter (AUD-7)", dest)
		}
	}
}
