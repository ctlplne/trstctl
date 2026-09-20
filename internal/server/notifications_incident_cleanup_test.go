// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
)

type closeProbeNotificationChannel struct {
	closed atomic.Int32
}

func TestIncidentNotificationConstructionConsumesInlineCredentialCopies(t *testing.T) {
	pagerDutyKey := []byte("pagerduty-inline-key")
	opsGenieKey := []byte("opsgenie-inline-key")
	channels, err := incidentNotificationChannelsFromConfig(config.Notifications{
		PagerDuty: config.NotificationPagerDuty{
			Enabled: true, Endpoint: "http://127.0.0.1:1/v2/enqueue", RoutingKey: pagerDutyKey,
			AllowPrivateCIDRs: []string{"127.0.0.0/8"}, AllowInsecureHTTP: true,
		},
		OpsGenie: config.NotificationOpsGenie{
			Enabled: true, Endpoint: "http://127.0.0.1:1/v2/alerts", APIKey: opsGenieKey,
			AllowPrivateCIDRs: []string{"127.0.0.0/8"}, AllowInsecureHTTP: true,
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeNotificationChannels(channels)
	if !bytes.Equal(pagerDutyKey, make([]byte, len(pagerDutyKey))) || !bytes.Equal(opsGenieKey, make([]byte, len(opsGenieKey))) {
		t.Fatal("incident notification construction retained a dumpable inline credential copy")
	}
}

func (*closeProbeNotificationChannel) Name() string { return "close-probe" }

func (*closeProbeNotificationChannel) Notify(context.Context, notify.Alert) error { return nil }

func (c *closeProbeNotificationChannel) Close() { c.closed.Add(1) }

func TestNotificationOwnershipClosesCoreExactlyOnceWhenIncidentConstructionFails(t *testing.T) {
	core := &closeProbeNotificationChannel{}
	_, _, err := completeRunNotificationChannels([]notify.Notifier{core}, func() ([]notify.Notifier, error) {
		return nil, errors.New("incident constructor failed")
	})
	if err == nil {
		t.Fatal("completeRunNotificationChannels succeeded after incident constructor failure")
	}
	if got := core.closed.Load(); got != 1 {
		t.Fatalf("core notifier close count = %d, want exactly 1", got)
	}
}
