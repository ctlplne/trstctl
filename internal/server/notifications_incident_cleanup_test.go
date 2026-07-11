// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
)

type closeProbeNotificationChannel struct {
	closed bool
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

func (c *closeProbeNotificationChannel) Close() { c.closed = true }

func TestNotificationChannelOwnershipClosesAfterPostConstructionFailure(t *testing.T) {
	failed := &closeProbeNotificationChannel{}
	closeNotificationChannelsOnError([]notify.Notifier{failed}, errors.New("later constructor failed"))
	if !failed.closed {
		t.Fatal("post-construction failure did not close the owned notification channel")
	}

	transferred := &closeProbeNotificationChannel{}
	closeNotificationChannelsOnError([]notify.Notifier{transferred}, nil)
	if transferred.closed {
		t.Fatal("successful Deps transfer prematurely closed the notification channel")
	}
}
