// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestServedSlackInstallAdmissionAndTenantReplay(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	secondTenant := uuid.NewString()
	if err := h.srv.orch.RegisterTenant(ctx, secondTenant, "Second operating tenant", "slack-install-second-tenant"); err != nil {
		t.Fatal(err)
	}
	teamID := "T0N8TEAM"
	tenants := []string{h.tenant, secondTenant}
	installs := make([]projections.SlackInstalled, 2)
	for i, tenantID := range tenants {
		sealed, err := sealTenantValue(ctx, h.srv.tenantCrypto, h.srv.kek, tenantID,
			[]byte{1, 2, 3, byte(i + 4)}, slackBotTokenAAD(tenantID, teamID))
		if err != nil {
			t.Fatal(err)
		}
		installs[i] = projections.SlackInstalled{
			TeamID: teamID, TeamName: "Shared workspace", BotUserID: "U-BOT", AppID: "A-APP",
			SealedBotToken: sealed, InstalledBy: "operator@example.test",
		}
	}
	before, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	type installResult struct {
		tenantID string
		err      error
	}
	start := make(chan struct{})
	results := make(chan installResult, 2)
	for i, tenantID := range tenants {
		install := installs[i]
		go func() {
			<-start
			results <- installResult{tenantID, h.srv.orch.RecordSlackEvent(ctx, tenantID, projections.EventSlackInstalled, install)}
		}()
	}
	close(start)
	var acceptedTenant, rejectedTenant string
	for range 2 {
		result := <-results
		if result.err == nil {
			acceptedTenant = result.tenantID
			continue
		}
		var pgErr *pgconn.PgError
		if !errors.As(result.err, &pgErr) || pgErr.Code != "23505" {
			t.Fatalf("unexpected install admission error: %v", result.err)
		}
		rejectedTenant = result.tenantID
	}
	if acceptedTenant == "" || rejectedTenant == "" || acceptedTenant == rejectedTenant {
		t.Fatalf("install result accepted=%q rejected=%q", acceptedTenant, rejectedTenant)
	}
	if head, err := h.log.LastSequence(ctx); err != nil || head != before+1 {
		t.Fatalf("install source head = %d, err=%v, want %d", head, err, before+1)
	}

	var rejectedInstall projections.SlackInstalled
	for i, tenantID := range tenants {
		if tenantID == rejectedTenant {
			rejectedInstall = installs[i]
		}
	}
	retainedData, err := json.Marshal(rejectedInstall)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(ctx, events.Event{
		ID: uuid.NewString(), Type: projections.EventSlackInstalled,
		TenantID: rejectedTenant, Data: retainedData,
	}); err != nil {
		t.Fatalf("append retained source: %v", err)
	}
	if err := h.srv.orch.RecordSlackEvent(ctx, acceptedTenant, projections.EventSlackApprovalChannelSet,
		projections.SlackApprovalChannelSet{ChannelID: "C-APPROVALS", ChannelName: "approvals", SetBy: "operator@example.test"}); err != nil {
		t.Fatalf("record accepted tenant channel: %v", err)
	}
	if err := h.srv.proj.ProjectCatchUp(ctx, h.log); err != nil {
		t.Fatalf("catch up retained history: %v", err)
	}
	if checkpoint, err := h.store.ProjectionCheckpoint(ctx); err != nil || checkpoint != before+3 {
		t.Fatalf("projection checkpoint = %d, err=%v, want %d", checkpoint, err, before+3)
	}
	if quarantined, err := h.store.ProjectionTenantQuarantined(ctx, rejectedTenant); err != nil || !quarantined {
		t.Fatalf("rejected tenant quarantine = %t, err=%v", quarantined, err)
	}
	if quarantined, err := h.store.ProjectionTenantQuarantined(ctx, acceptedTenant); err != nil || quarantined {
		t.Fatalf("accepted tenant quarantine = %t, err=%v", quarantined, err)
	}
	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("rebuild retained history: %v", err)
	}
	if install, err := h.store.GetSlackInstall(ctx, acceptedTenant); err != nil || install.ApprovalChannelID != "C-APPROVALS" {
		t.Fatalf("accepted tenant install after rebuild = %+v, err=%v", install, err)
	}
}
