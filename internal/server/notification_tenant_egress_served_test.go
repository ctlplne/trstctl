// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedTenantWebhookNeedsItsOwnOperatorPrivateGrant(t *testing.T) {
	for _, granted := range []bool{false, true} {
		t.Run(map[bool]string{false: "no grant", true: "granted"}[granted], func(t *testing.T) {
			h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
				if granted {
					d.NotificationTenantEgress = []config.TenantPrivateEgress{{TenantID: servedTestTenant, CIDRs: []string{"10.40.0.0/16"}}}
				}
			})
			tok := seedScopedToken(t, h.store, h.tenant, "notifications:read", "notifications:write")
			create := func(key, endpoint string, extra map[string]any) (int, []byte) {
				t.Helper()
				body := map[string]any{"id": "webhook", "channel_type": "webhook", "endpoint_url": endpoint, "enabled": true}
				for k, v := range extra {
					body[k] = v
				}
				return secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-channels", tok, key, body)
			}
			status, body := create("private-channel", "https://10.40.0.9/hook", nil)
			if granted {
				if status != http.StatusCreated {
					t.Fatalf("operator-granted endpoint = %d %s", status, body)
				}
			} else if status != http.StatusBadRequest || !strings.Contains(string(body), "operator") {
				t.Fatalf("ungranted endpoint = %d %s; want refusal naming the operator grant", status, body)
			}
			status, body = create("tenant-cannot-grant", "https://10.41.0.9/hook", map[string]any{"allow_private_cidrs": []string{"10.0.0.0/8"}})
			if status != http.StatusBadRequest {
				t.Fatalf("tenant-authored grant = %d %s", status, body)
			}
			for _, endpoint := range []string{"https://10.41.0.9/hook", "http://10.40.0.9/hook", "https://127.0.0.1/hook", "https://169.254.169.254/hook", "https://[fd00:ec2::254]/hook"} {
				status, body = create("denied-"+endpoint, endpoint, nil)
				if status != http.StatusBadRequest {
					t.Fatalf("tenant override %s = %d %s", endpoint, status, body)
				}
			}
		})
	}
}
