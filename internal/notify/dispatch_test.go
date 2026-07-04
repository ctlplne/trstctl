// SPDX-License-Identifier: MPL-2.0

package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/notify"
)

type capturingNotifier struct {
	name string
	got  []notify.Alert
	err  error
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
