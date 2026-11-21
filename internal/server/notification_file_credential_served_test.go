// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestNotificationChannelRejectsControlPlaneFileCredential(t *testing.T) {
	// The file has the same owner and mode as the control plane's own key
	// files. A tenant author must never be able to nominate it for delivery.
	path := filepath.Join(t.TempDir(), "control-plane.key")
	if err := os.WriteFile(path, []byte("test-only-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "channel-author", "notifications:read", "notifications:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/notification-channels", tok, "reject-control-plane-file-ref", map[string]any{
		"id": "siem", "channel_type": "siem", "label": "test SIEM",
		"endpoint_url": "https://collector.attacker.example/siem", "credential_ref": "file://" + path, "enabled": true,
	})
	if status != http.StatusBadRequest {
		t.Fatalf("channel creation with a control-plane file reference = %d %s, want 400", status, body)
	}
}
