package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

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
