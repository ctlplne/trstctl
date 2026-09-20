//go:build trstctl_dodproof

// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

// TestDODNativeIncidentNotificationProductionAssembly proves the dispatcher and
// both advertised native incident channels through production buildRunDeps ->
// Build. A user-reachable, authenticated served mutation creates the durable
// outbox work; each row owns a separate nonce/PID-bound vendor emulator process.
func TestDODNativeIncidentNotificationProductionAssembly(t *testing.T) {
	only := dodRuntimeSelection(t,
		"notification_channel.dispatch", "notification_channel.pagerduty", "notification_channel.opsgenie",
	)
	if only == "" || only == "notification_channel.dispatch" {
		external := proof.StartCommand(t, "notification_channel.dispatch")
		dodRunNativeNotification(t, "notification_channel.dispatch", "pagerduty", external)
	}
	if only == "" || only == "notification_channel.pagerduty" {
		external := proof.StartCommand(t, "notification_channel.pagerduty")
		dodRunNativeNotification(t, "notification_channel.pagerduty", "pagerduty", external)
	}
	if only == "" || only == "notification_channel.opsgenie" {
		external := proof.StartCommand(t, "notification_channel.opsgenie")
		dodRunNativeNotification(t, "notification_channel.opsgenie", "opsgenie", external)
	}
}

func dodRunNativeNotification(t *testing.T, entryID, channelName string, external *proof.ExternalSubstrate) {
	t.Helper()
	productionEndpoint := dodParentSubstrateLoopbackBridge(t, external.Endpoint())
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "secrets-kek.bin")
	cfg.CA.CertFile = filepath.Join(t.TempDir(), "issuing-ca.pem")
	switch channelName {
	case "pagerduty":
		cfg.Notifications.PagerDuty = config.NotificationPagerDuty{
			Enabled: true, Endpoint: productionEndpoint + "/v2/enqueue",
			RoutingKey: []byte("dod-pagerduty-routing-key"), Timeout: "5s",
			AllowPrivateCIDRs: []string{"127.0.0.0/8"}, AllowInsecureHTTP: true,
		}
	case "opsgenie":
		cfg.Notifications.OpsGenie = config.NotificationOpsGenie{
			Enabled: true, Endpoint: productionEndpoint + "/v2/alerts",
			APIKey: []byte("dod-opsgenie-api-key"), Timeout: "5s",
			AllowPrivateCIDRs: []string{"127.0.0.0/8"}, AllowInsecureHTTP: true,
		}
	default:
		t.Fatalf("unsupported notification channel %q", channelName)
	}

	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatalf("open embedded event log: %v", err)
	}
	runSecrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatalf("load run secrets: %v", err)
	}
	defer runSecrets.Close()
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	signer := dodStartAuthorizedSoftwareSignerProcess(t, t.TempDir())
	deps, err := buildRunDeps(ctx, cfg, st, log, signer, runSecrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build production deps: %v", err)
	}
	defer func() {
		if err := srv.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	}()

	token := dodSeedAPIToken(t, ctx, st, servedTestTenant, "dod-notification-operator", []string{string(authz.NotificationsWrite)})
	request, err := http.NewRequest(
		http.MethodPost,
		"/api/v1/notification-channels/"+channelName+"/test",
		bytes.NewBufferString(`{"subject":"dod.notification.example","detail":"native vendor delivery contract probe","severity":"critical"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Idempotency-Key", "dod-notification-"+entryID)
	request.Header.Set("Content-Type", "application/json")
	session := proof.Start(t, entryID, srv.Handler(), request)
	if session.StatusCode() != http.StatusAccepted || !bytes.Contains(session.ResponseBody(), []byte(`"channel_id":"`+channelName+`"`)) || !bytes.Contains(session.ResponseBody(), []byte(`"status":"queued"`)) {
		t.Fatalf("served channel-test mutation did not queue native %s delivery: status=%d body=%s", channelName, session.StatusCode(), session.ResponseBody())
	}
	if err := srv.Drain(ctx); err != nil {
		t.Fatalf("drain native notification queued by served mutation: %v", err)
	}
	delivery := dodNotificationReadback(t, external.Endpoint())
	contract, err := os.ReadFile("../../tools/dodcensus/contracts/notification-native-v1.json")
	if err != nil {
		t.Fatalf("read notification substrate contract: %v", err)
	}
	executionReceipt := external.StopAndReceipt()
	session.Complete(proof.Notification(proof.NotificationProbe{
		Contract: contract, Acceptance: session.ResponseBody(), Delivery: delivery, ExecutionReceipt: executionReceipt,
	}))
}

// dodSeedAPIToken deliberately lives in this httptest-free proof file. The DoD
// tracer follows same-package helpers and rejects any helper file that imports
// net/http/httptest, even when that helper itself does not use it.
func dodSeedAPIToken(t *testing.T, ctx context.Context, st *store.Store, tenantID, subject string, scopes []string) string {
	t.Helper()
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate API token: %v", err)
	}
	defer secret.Wipe(raw)
	if _, err := st.CreateAPIToken(ctx, store.APITokenRecord{
		TenantID: tenantID, TokenHash: hash, Subject: subject, Scopes: scopes,
	}); err != nil {
		t.Fatalf("seed API token: %v", err)
	}
	return secrettext.String(raw)
}

func dodNotificationReadback(t *testing.T, endpoint string) []byte {
	t.Helper()
	response, err := http.Get(endpoint + "/dod/readback")
	if err != nil {
		t.Fatalf("notification emulator readback: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode != http.StatusOK || len(body) < 16 {
		t.Fatalf("notification readback status=%d bytes=%d err=%v", response.StatusCode, len(body), err)
	}
	return body
}
