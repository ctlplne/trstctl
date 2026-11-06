// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDesktopIntentRequiresReviewedRouteAndVersionedExecutor(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"session_id": "desktop-session", "target_id": "desktop-target", "target_type": "rdp", "required_agent_id": "gateway", "expires_at": time.Now().Add(time.Minute), "ticket_digest": TicketDigest("public-fixture-ticket"), "credential_ref": CredentialRef("desktop-session"), "desktop": map[string]any{"address": "desktop.example:3389", "certificate_sha256": "abababababababababababababababababababababababababababababababab", "width": 800, "height": 600}})
	if err != nil {
		t.Fatal(err)
	}
	var intent SessionIntent
	if err = json.Unmarshal(raw, &intent); err != nil {
		t.Fatal(err)
	}
	if err = ValidateSessionIntent(intent); err != nil {
		t.Fatal(err)
	}
	if !MatchesSessionJob("access.gateway.session.desktop.v1", intent) {
		t.Fatal("desktop did not require its versioned native executor")
	}
	if MatchesSessionJob(KindSession, intent) {
		t.Fatal("legacy gateway could claim a desktop session")
	}
}

func TestDesktopJobsAreNotClaimedWithoutConfiguredNativeHelper(t *testing.T) {
	for _, path := range []string{"", "/installed/native-helper"} {
		g := &Gateway{cfg: Config{DesktopHelper: path}}
		found := false
		for _, kind := range g.claimableKinds() {
			found = found || kind == KindSessionDesktop
		}
		if found != (path != "") {
			t.Fatal("native job capability did not match helper configuration")
		}
	}
}

func TestADDesktopCannotUseLegacyNativeExecutor(t *testing.T) {
	raw := []byte(`{"session_id":"ad-session","target_id":"ad-target","target_type":"rdp","required_agent_id":"gateway","expires_at":"2090-01-01T00:00:00Z","ticket_digest":"digest","credential_ref":"credential","desktop":{"address":"desktop.example:3389","certificate_sha256":"abababababababababababababababababababababababababababababababab","width":800,"height":600,"account_kind":"active_directory","accounts":[{"reference":"CN=approved,DC=example,DC=test","username":"approved"}]}}`)
	var intent SessionIntent
	if json.Unmarshal(raw, &intent) != nil {
		t.Fatal("invalid fixture")
	}
	intent.TicketDigest = TicketDigest("public-ad-fixture-ticket")
	intent.CredentialRef = CredentialRef(intent.SessionID)
	intent.ExpiresAt = time.Now().Add(time.Minute)
	if err := ValidateSessionIntent(intent); err != nil {
		t.Fatal("invalid AD session fixture:", err)
	}
	if MatchesSessionJob(KindSessionDesktop, intent) || KindForIntent(intent) != "access.gateway.session.desktop.ad.v1" {
		t.Fatal("a legacy desktop executor can bypass the AD account binding")
	}
}
