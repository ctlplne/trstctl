// SPDX-License-Identifier: BUSL-1.1

package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/notify"
)

type capturingNotifier struct {
	name string
	got  []notify.Alert
	err  error
}

type contextBlockingNotifier struct {
	name    string
	started chan struct{}
}

func (n *contextBlockingNotifier) Name() string { return n.name }
func (n *contextBlockingNotifier) Notify(ctx context.Context, _ notify.Alert) error {
	close(n.started)
	<-ctx.Done()
	return ctx.Err()
}

func (c *capturingNotifier) Name() string { return c.name }
func (c *capturingNotifier) Notify(_ context.Context, a notify.Alert) error {
	c.got = append(c.got, a)
	return c.err
}

type routingResolver struct {
	policy       notify.RoutingPolicy
	gotTenantID  string
	gotPolicyID  string
	resolveCount int
}

type effectiveRoutingResolver struct {
	routingResolver
	policy      notify.RoutingPolicy
	gotSelector notify.RoutingSelector
}

func (r *effectiveRoutingResolver) ResolveEffectiveNotificationPolicy(_ context.Context, tenantID string, selector notify.RoutingSelector) (notify.RoutingPolicy, bool, error) {
	r.gotTenantID = tenantID
	r.gotSelector = selector
	if tenantID != r.policy.TenantID {
		return notify.RoutingPolicy{}, false, nil
	}
	return r.policy, true, nil
}

func (r *routingResolver) ResolveNotificationPolicy(_ context.Context, tenantID, policyID string) (notify.RoutingPolicy, bool, error) {
	r.gotTenantID = tenantID
	r.gotPolicyID = policyID
	r.resolveCount++
	if tenantID != r.policy.TenantID || policyID != r.policy.ID {
		return notify.RoutingPolicy{}, false, nil
	}
	return r.policy, true, nil
}

type memoryThresholdLedger struct {
	sent map[string]bool
}

type memoryDeliveryLedger struct {
	mu       sync.Mutex
	receipts map[string]notify.NotificationDeliveryReceipt
}

func newMemoryDeliveryLedger() *memoryDeliveryLedger {
	return &memoryDeliveryLedger{receipts: make(map[string]notify.NotificationDeliveryReceipt)}
}

func (l *memoryDeliveryLedger) HasNotificationDelivery(_ context.Context, want notify.NotificationDeliveryReceipt) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	got, ok := l.receipts[want.ID]
	if !ok {
		return false, nil
	}
	if got.TenantID != want.TenantID || got.Destination != want.Destination ||
		got.NotificationKeyDigest != want.NotificationKeyDigest || got.PayloadDigest != want.PayloadDigest ||
		got.Channel != want.Channel {
		return false, errors.New("receipt binding differs")
	}
	return true, nil
}

func (l *memoryDeliveryLedger) RecordNotificationDelivery(_ context.Context, rec notify.NotificationDeliveryReceipt) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if got, ok := l.receipts[rec.ID]; ok {
		if got.Destination != rec.Destination || got.NotificationKeyDigest != rec.NotificationKeyDigest ||
			got.PayloadDigest != rec.PayloadDigest || got.Channel != rec.Channel {
			return errors.New("receipt binding differs")
		}
		return nil
	}
	l.receipts[rec.ID] = rec
	return nil
}

func newMemoryThresholdLedger() *memoryThresholdLedger {
	return &memoryThresholdLedger{sent: make(map[string]bool)}
}

func (l *memoryThresholdLedger) HasThresholdNotificationOnChannel(_ context.Context, tenantID, subject string, threshold int, channel string) (bool, error) {
	return l.sent[thresholdKey(tenantID, subject, threshold, channel)], nil
}

func (l *memoryThresholdLedger) RecordThresholdNotificationOnChannel(_ context.Context, rec notify.ThresholdNotificationDelivery) error {
	l.sent[thresholdKey(rec.TenantID, rec.Subject, rec.ThresholdDays, rec.Channel)] = true
	return nil
}

func thresholdKey(tenantID, subject string, threshold int, channel string) string {
	return fmt.Sprintf("%s|%s|%d|%s", tenantID, subject, threshold, strings.ToLower(channel))
}

func TestDispatchFansOut(t *testing.T) {
	a := &capturingNotifier{name: "a"}
	b := &capturingNotifier{name: "b"}
	d := notify.NewDispatcher(a, b)
	payload, _ := json.Marshal(notify.Alert{Kind: notify.KindCertificateExpiry, TenantID: "t1", Subject: "cn=x"})
	if err := d.Dispatch(context.Background(), payload); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if len(a.got) != 1 || len(b.got) != 1 {
		t.Fatalf("fan-out: a=%d b=%d, want 1 each", len(a.got), len(b.got))
	}
}

func TestDispatchAccumulatesErrors(t *testing.T) {
	good := &capturingNotifier{name: "good"}
	bad := &capturingNotifier{name: "bad", err: errors.New("boom")}
	d := notify.NewDispatcher(good, bad)
	payload, _ := json.Marshal(notify.Alert{Kind: notify.KindCertificateExpiry, TenantID: "t1"})
	err := d.Dispatch(context.Background(), payload)
	if err == nil || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("want an error naming the failing channel, got: %v", err)
	}
	if len(good.got) != 1 {
		t.Error("a failing channel suppressed delivery to a healthy one")
	}
}

func TestDispatchMessageReceiptsSkipSuccessfulSiblingOnPartialRetry(t *testing.T) {
	good := &capturingNotifier{name: "good"}
	bad := &capturingNotifier{name: "bad", err: errors.New("temporary failure")}
	d := notify.NewDispatcher(good, bad)
	d.SetDeliveryReceiptLedger(newMemoryDeliveryLedger())
	payload, _ := json.Marshal(notify.Alert{Kind: notify.KindUnexpectedIssuance, TenantID: "t1", Subject: "cn=partial"})
	message := notify.DeliveryMessage{
		TenantID: "t1", Destination: notify.DestinationCTLog,
		IdempotencyKey: "partial-fanout-1", Payload: payload, OutboxID: 41, Attempts: 1,
	}
	if err := d.DispatchMessage(context.Background(), message); err == nil {
		t.Fatal("first partial fan-out unexpectedly succeeded")
	}
	if len(good.got) != 1 || len(bad.got) != 1 {
		t.Fatalf("first fan-out calls good=%d bad=%d, want 1/1", len(good.got), len(bad.got))
	}

	bad.err = nil
	message.Attempts = 2
	if err := d.DispatchMessage(context.Background(), message); err != nil {
		t.Fatalf("retry partial fan-out: %v", err)
	}
	if len(good.got) != 1 || len(bad.got) != 2 {
		t.Fatalf("retry calls good=%d bad=%d, want 1/2 (successful sibling skipped)", len(good.got), len(bad.got))
	}
}

func TestDispatchMessageReceiptSurvivesCrashBeforeOutboxAck(t *testing.T) {
	channel := &capturingNotifier{name: "slack"}
	d := notify.NewDispatcher(channel)
	d.SetDeliveryReceiptLedger(newMemoryDeliveryLedger())
	payload, _ := json.Marshal(notify.Alert{Kind: notify.KindNotificationChannelTest, TenantID: "t1", TargetChannel: "slack"})
	message := notify.DeliveryMessage{
		TenantID: "t1", Destination: notify.DestinationTest,
		IdempotencyKey: "notification.test:crash-replay", Payload: payload, OutboxID: 52, Attempts: 1,
	}
	// The first call represents the worker reaching receiver success and durable
	// receipt projection, then dying before the generic outbox ACK.
	if err := d.DispatchMessage(context.Background(), message); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	message.Attempts = 2
	if err := d.DispatchMessage(context.Background(), message); err != nil {
		t.Fatalf("lease replay: %v", err)
	}
	if len(channel.got) != 1 {
		t.Fatalf("receiver calls after crash replay = %d, want 1", len(channel.got))
	}
}

func TestDispatchMessageReceiptRejectsPayloadDrift(t *testing.T) {
	channel := &capturingNotifier{name: "slack"}
	d := notify.NewDispatcher(channel)
	d.SetDeliveryReceiptLedger(newMemoryDeliveryLedger())
	first, _ := json.Marshal(notify.Alert{Kind: notify.KindUnexpectedIssuance, TenantID: "t1", Subject: "first"})
	message := notify.DeliveryMessage{TenantID: "t1", Destination: notify.DestinationCTLog, IdempotencyKey: "same-key", Payload: first}
	if err := d.DispatchMessage(context.Background(), message); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	changed, _ := json.Marshal(notify.Alert{Kind: notify.KindUnexpectedIssuance, TenantID: "t1", Subject: "changed"})
	message.Payload = changed
	if err := d.DispatchMessage(context.Background(), message); err == nil || !strings.Contains(err.Error(), "receipt") {
		t.Fatalf("changed payload error = %v, want receipt binding conflict", err)
	}
	if len(channel.got) != 1 {
		t.Fatalf("changed payload reached receiver %d times, want 1 total", len(channel.got))
	}
}

func TestDispatchStartsHealthyChannelWhileAnotherChannelIsHung(t *testing.T) {
	hung := &contextBlockingNotifier{name: "hung", started: make(chan struct{})}
	healthy := &capturingNotifier{name: "healthy"}
	d := notify.NewDispatcher(hung, healthy)
	payload, _ := json.Marshal(notify.Alert{Kind: notify.KindCertificateExpiry, TenantID: "t1"})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := d.Dispatch(ctx, payload)
	if err == nil || !strings.Contains(err.Error(), "hung") {
		t.Fatalf("Dispatch error = %v, want the timed-out channel", err)
	}
	select {
	case <-hung.started:
	default:
		t.Fatal("hung channel was not attempted")
	}
	if len(healthy.got) != 1 {
		t.Fatalf("healthy channel calls = %d, want 1 despite the hung peer", len(healthy.got))
	}
}

func TestDispatchRoutesBySeverityPolicy(t *testing.T) {
	email := &capturingNotifier{name: "email"}
	slack := &capturingNotifier{name: "slack"}
	teams := &capturingNotifier{name: "msteams"}
	pager := &capturingNotifier{name: "pagerduty"}
	d := notify.NewDispatcher(email, slack, teams, pager)
	resolver := &routingResolver{policy: notify.RoutingPolicy{
		TenantID: "t1",
		ID:       "expiry-policy",
		ChannelsBySeverity: map[string][]string{
			notify.AlertSeverityCritical: {"pagerduty", "slack", "teams"},
			notify.AlertSeverityLow:      {"email"},
		},
	}}
	d.SetPolicyResolver(resolver)

	payload, _ := json.Marshal(notify.Alert{Kind: notify.KindCertificateExpiry, TenantID: "t1", RoutingPolicyID: "expiry-policy", Severity: notify.AlertSeverityCritical})
	if err := d.Dispatch(context.Background(), payload); err != nil {
		t.Fatalf("Dispatch critical: %v", err)
	}
	if resolver.gotTenantID != "t1" || resolver.gotPolicyID != "expiry-policy" {
		t.Fatalf("resolver scoped to tenant=%q policy=%q, want t1/expiry-policy", resolver.gotTenantID, resolver.gotPolicyID)
	}
	if len(pager.got) != 1 || len(slack.got) != 1 || len(teams.got) != 1 || len(email.got) != 0 {
		t.Fatalf("critical route: email=%d slack=%d teams=%d pager=%d, want only slack+teams+pager", len(email.got), len(slack.got), len(teams.got), len(pager.got))
	}

	payload, _ = json.Marshal(notify.Alert{Kind: notify.KindCertificateExpiry, TenantID: "t1", RoutingPolicyID: "expiry-policy", Severity: notify.AlertSeverityLow})
	if err := d.Dispatch(context.Background(), payload); err != nil {
		t.Fatalf("Dispatch low: %v", err)
	}
	if len(email.got) != 1 || len(slack.got) != 1 || len(teams.got) != 1 || len(pager.got) != 1 {
		t.Fatalf("low route: email=%d slack=%d teams=%d pager=%d, want only email added", len(email.got), len(slack.got), len(teams.got), len(pager.got))
	}

	payload, _ = json.Marshal(notify.Alert{Kind: notify.KindCertificateExpiry, TenantID: "t1", RoutingPolicyID: "expiry-policy", Severity: "operator typo"})
	if err := d.Dispatch(context.Background(), payload); err != nil {
		t.Fatalf("Dispatch unknown severity: %v", err)
	}
	if len(email.got) != 2 || len(slack.got) != 1 || len(teams.got) != 1 || len(pager.got) != 1 {
		t.Fatalf("unknown severity route: email=%d slack=%d teams=%d pager=%d, want safe low-tier fallback", len(email.got), len(slack.got), len(teams.got), len(pager.got))
	}
}

func TestDispatchResolvesEffectivePolicyWhenAlertDoesNotNameOne(t *testing.T) {
	email := &capturingNotifier{name: "email"}
	pager := &capturingNotifier{name: "pagerduty"}
	d := notify.NewDispatcher(email, pager)
	resolver := &effectiveRoutingResolver{policy: notify.RoutingPolicy{
		TenantID: "t1", ID: "asset-route", ScopeKind: "asset", ScopeRef: "certificate/cert-payments",
		ChannelsBySeverity: map[string][]string{notify.AlertSeverityCritical: {"pagerduty"}},
	}}
	d.SetPolicyResolver(resolver)
	payload, _ := json.Marshal(notify.Alert{
		Kind: notify.KindCertificateExpiry, TenantID: "t1", CertificateID: "cert-payments",
		OwnerID: "platform", Severity: notify.AlertSeverityCritical,
	})
	if err := d.Dispatch(context.Background(), payload); err != nil {
		t.Fatalf("Dispatch effective route: %v", err)
	}
	if resolver.gotSelector.Workspace != "certificate-lifecycle" ||
		resolver.gotSelector.OwnerRef != "owner/platform" ||
		resolver.gotSelector.AssetRef != "certificate/cert-payments" {
		t.Fatalf("effective selector = %+v", resolver.gotSelector)
	}
	if len(pager.got) != 1 || len(email.got) != 0 {
		t.Fatalf("effective route: email=%d pagerduty=%d, want only pagerduty", len(email.got), len(pager.got))
	}
}

func TestRenewalFailureRoutesToItsIdentityAndKeepsOneReceiverReceipt(t *testing.T) {
	channel := &capturingNotifier{name: "pagerduty"}
	d := notify.NewDispatcher(channel)
	d.SetDeliveryReceiptLedger(newMemoryDeliveryLedger())
	resolver := &effectiveRoutingResolver{policy: notify.RoutingPolicy{
		TenantID: "t1", ID: "renewal-route", ScopeKind: "owner", ScopeRef: "owner/platform",
		ChannelsBySeverity: map[string][]string{notify.AlertSeverityWarning: {"pagerduty"}},
	}}
	d.SetPolicyResolver(resolver)
	alert := notify.Alert{Kind: notify.KindRenewalFailed, TenantID: "t1", IdentityID: "identity-payments",
		CertificateID: "historical-installed-leaf",
		Subject:       "payments.example.test", OwnerID: "platform", OperationID: "renewal-failure:event-a",
		Severity: notify.AlertSeverityWarning, Detail: "Check retry status."}
	payload, _ := json.Marshal(alert)
	message := notify.DeliveryMessage{TenantID: "t1", Destination: notify.DestinationRenewalFailure,
		IdempotencyKey: "event-a", Payload: payload, OutboxID: 91, Attempts: 1}
	for range 2 {
		if err := d.DispatchMessage(context.Background(), message); err != nil {
			t.Fatal(err)
		}
	}
	if resolver.gotTenantID != "t1" || resolver.gotSelector.Workspace != "certificate-lifecycle" || resolver.gotSelector.OwnerRef != "owner/platform" || resolver.gotSelector.AssetRef != "identity/identity-payments" {
		t.Fatalf("failure alert routing: tenant=%s selector=%+v", resolver.gotTenantID, resolver.gotSelector)
	}
	if len(channel.got) != 1 || !strings.HasPrefix(notify.FormatMessage(alert), "Certificate renewal attempt failed: payments.example.test") {
		t.Fatalf("expected one clearly named failure alert, received %d", len(channel.got))
	}
}

func TestDeliveryReceiptRetainsTheRouteThatActuallySentEachChannel(t *testing.T) {
	email := &capturingNotifier{name: "email"}
	pager := &capturingNotifier{name: "pagerduty", err: errors.New("receiver temporarily unavailable")}
	ledger := newMemoryDeliveryLedger()
	d := notify.NewDispatcher(email, pager)
	d.SetDeliveryReceiptLedger(ledger)
	resolver := &effectiveRoutingResolver{policy: notify.RoutingPolicy{
		TenantID: "t1", ID: "original-policy", ScopeKind: "asset", ScopeRef: "identity/payments",
		DefaultChannels: []string{"email", "pagerduty"},
	}}
	d.SetPolicyResolver(resolver)
	payload, _ := json.Marshal(notify.Alert{Kind: notify.KindRenewalFailed, TenantID: "t1", IdentityID: "payments"})
	message := notify.DeliveryMessage{TenantID: "t1", Destination: notify.DestinationRenewalFailure,
		IdempotencyKey: "failure-a", Payload: payload, OutboxID: 91, Attempts: 1}
	if err := d.DispatchMessage(context.Background(), message); err == nil {
		t.Fatal("expected the failed pager delivery to retain the outbox retry")
	}
	if len(ledger.receipts) != 1 {
		t.Fatalf("receipts = %d, want only the successful email", len(ledger.receipts))
	}
	var first notify.NotificationDeliveryReceipt
	for _, rec := range ledger.receipts {
		first = rec
	}
	if first.Channel != "email" || first.RoutingSource != "inherited_policy" || first.RoutingPolicyID != "original-policy" || first.RoutingPolicyScope != "asset" || len(first.RoutingPolicyDigest) != 64 {
		t.Fatalf("successful channel lacks its dispatch-time routing evidence: %+v", first)
	}
	// Configuration may change while a failed peer retries. Keep the successful
	// receipt unchanged and record the route used by the newly successful peer.
	resolver.policy.ID = "replacement-policy"
	resolver.policy.ScopeKind = "owner"
	resolver.policy.ScopeRef = "owner/platform"
	pager.err = nil
	message.Attempts = 2
	if err := d.DispatchMessage(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	if len(email.got) != 1 || len(pager.got) != 2 || len(ledger.receipts) != 2 {
		t.Fatalf("retry sent email=%d pager=%d receipts=%d", len(email.got), len(pager.got), len(ledger.receipts))
	}
	for _, rec := range ledger.receipts {
		if rec.Channel == "email" && rec != first {
			t.Fatalf("retry rewrote successful route: before=%+v after=%+v", first, rec)
		}
		if rec.Channel == "pagerduty" && (rec.RoutingPolicyID != "replacement-policy" || rec.RoutingPolicyScope != "owner" || rec.RoutingPolicyDigest == first.RoutingPolicyDigest || rec.Attempts != 2) {
			t.Fatalf("retried receiver has incorrect route: %+v", rec)
		}
	}
}

func TestDispatchDedupsThresholdPerSubjectThresholdChannel(t *testing.T) {
	email := &capturingNotifier{name: "email"}
	slack := &capturingNotifier{name: "slack"}
	ledger := newMemoryThresholdLedger()
	d := notify.NewDispatcher(email, slack)
	d.SetThresholdDedupLedger(ledger)

	fourteen := 14
	payload, _ := json.Marshal(notify.Alert{
		Kind: notify.KindCertificateExpiry, TenantID: "t1", Subject: "cn=api",
		ThresholdDays: &fourteen,
	})
	if err := d.Dispatch(context.Background(), payload); err != nil {
		t.Fatalf("Dispatch first threshold: %v", err)
	}
	if len(email.got) != 1 || len(slack.got) != 1 {
		t.Fatalf("first threshold: email=%d slack=%d, want both sent once", len(email.got), len(slack.got))
	}

	if err := d.Dispatch(context.Background(), payload); err != nil {
		t.Fatalf("Dispatch duplicate threshold: %v", err)
	}
	if len(email.got) != 1 || len(slack.got) != 1 {
		t.Fatalf("duplicate threshold resent: email=%d slack=%d, want no new sends", len(email.got), len(slack.got))
	}

	seven := 7
	payload, _ = json.Marshal(notify.Alert{
		Kind: notify.KindCertificateExpiry, TenantID: "t1", Subject: "cn=api",
		ThresholdDays: &seven,
	})
	if err := d.Dispatch(context.Background(), payload); err != nil {
		t.Fatalf("Dispatch new threshold: %v", err)
	}
	if len(email.got) != 2 || len(slack.got) != 2 {
		t.Fatalf("new threshold: email=%d slack=%d, want both sent again", len(email.got), len(slack.got))
	}

	if err := ledger.RecordThresholdNotificationOnChannel(context.Background(), notify.ThresholdNotificationDelivery{
		TenantID: "t1", Subject: "cn=db", ThresholdDays: 30, Channel: "email", SentAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed ledger: %v", err)
	}
	thirty := 30
	payload, _ = json.Marshal(notify.Alert{
		Kind: notify.KindCertificateExpiry, TenantID: "t1", Subject: "cn=db",
		ThresholdDays: &thirty,
	})
	if err := d.Dispatch(context.Background(), payload); err != nil {
		t.Fatalf("Dispatch channel-partial duplicate: %v", err)
	}
	if len(email.got) != 2 || len(slack.got) != 3 {
		t.Fatalf("channel-partial duplicate: email=%d slack=%d, want only slack sent", len(email.got), len(slack.got))
	}
}

func TestDispatchRejectsMalformed(t *testing.T) {
	d := notify.NewDispatcher(&capturingNotifier{name: "a"})
	if err := d.Dispatch(context.Background(), []byte("not json")); err == nil {
		t.Fatal("Dispatch accepted a malformed payload")
	}
}

func TestDispatchRejectsUnknownRequestedTestChannel(t *testing.T) {
	d := notify.NewDispatcher(&capturingNotifier{name: "pagerduty"})
	payload, _ := json.Marshal(notify.Alert{
		Kind:          notify.KindNotificationChannelTest,
		TenantID:      "t1",
		TargetChannel: "opsgenie",
	})
	err := d.Dispatch(context.Background(), payload)
	if err == nil || !strings.Contains(err.Error(), `channel "opsgenie" is not configured`) {
		t.Fatalf("unknown requested channel was ACKed, want a retryable configuration error: %v", err)
	}
}

func TestDispatchRejectsMissingPolicyChannel(t *testing.T) {
	d := notify.NewDispatcher(&capturingNotifier{name: "pagerduty"})
	d.SetDefaultRoutingPolicy(notify.RoutingPolicy{
		ChannelsBySeverity: map[string][]string{notify.AlertSeverityCritical: {"pagerduty", "opsgenie"}},
	})
	payload, _ := json.Marshal(notify.Alert{
		Kind: notify.KindUnexpectedIssuance, TenantID: "t1", Severity: notify.AlertSeverityCritical,
	})
	err := d.Dispatch(context.Background(), payload)
	if err == nil || !strings.Contains(err.Error(), "opsgenie") {
		t.Fatalf("partially configured route was ACKed, want missing-channel error: %v", err)
	}
}

func TestConformCatchesBadNotifier(t *testing.T) {
	if err := notify.Conform(context.Background(), &capturingNotifier{name: "ok"}); err != nil {
		t.Errorf("Conform rejected a good notifier: %v", err)
	}
	if err := notify.Conform(context.Background(), &capturingNotifier{name: "bad", err: errors.New("x")}); err == nil {
		t.Error("Conform passed a notifier that errors")
	}
}

func TestFormatMessage(t *testing.T) {
	msg := notify.FormatMessage(notify.Alert{Kind: notify.KindCertificateExpiry, Subject: "cn=example.com"})
	if !strings.Contains(msg, "expiring") || !strings.Contains(msg, "example.com") {
		t.Errorf("unexpected message: %q", msg)
	}
}
