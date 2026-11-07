// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/infratest"
	"trstctl.com/trstctl/internal/events"
)

// TestServedBreakGlassEmergencyCheckoutA272: an Okta, an Entra ID and a
// Google Workspace super administrator are vaulted as breakglass targets. A
// breakglass account has no sessions and no reviewed check-out; only a named
// emergency responder — not a token minted for them — releases it, at once:
// every approver gets a notice on the approval channels, the credential is
// shown once (the password, and for Okta the current code of its TOTP seed,
// never the seed), the record lists who holds its hardware keys, and a second
// release is refused. Checking it in rotates the password at the identity
// provider; the audit log records the grant and the release without the
// credential; another approver closes the post-incident review.
func TestServedBreakGlassEmergencyCheckoutA272(t *testing.T) {
	ctx := context.Background()
	tenant := uuid.NewString()
	okta := infratest.StartOkta("okta-api-token-1")
	t.Cleanup(okta.Close)
	entra := infratest.StartEntra("app-client-1", "app-secret-1")
	t.Cleanup(entra.Close)
	google, err := infratest.StartGoogle("rotator@corp-iam.iam.gserviceaccount.com", "admin@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(google.Close)
	for _, p := range []*infratest.IdP{okta, entra, google} {
		p.AddUser("breakglass@corp.example", "initial-password-1!", true)
	}
	seed := []byte("trstctl-a272-totp-seed")
	seedRef := writeServedCredentialFile(t, "a272-bg-seed", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed))
	holders := []string{"alice@corp.example — YubiKey 5C NFC, serial 23517", "bob@corp.example — YubiKey 5 NFC, serial 99120"}
	idp := func(id, typ, role string) config.DynamicSecretProviderConfig {
		return config.DynamicSecretProviderConfig{TenantID: tenant, ID: id, Type: typ, AllowInsecureLoopback: true, MaxTTL: "1h", AllowStaticRotation: true,
			AllowedRoles: []string{role}, RoleBindings: map[string]string{role: "breakglass@corp.example"}}
	}
	oktaCfg := idp("okta-org", "okta-user", "bg/okta")
	oktaCfg.Endpoint, oktaCfg.APIKeyRef = okta.URL(), writeServedCredentialFile(t, "a272-bg-okta-token", "okta-api-token-1")
	oktaCfg.TOTPProviders = map[string]string{"bg/okta": "okta-bg-totp"}
	oktaCfg.HardwareKeyHolders = map[string][]string{"bg/okta": holders}
	entraCfg := idp("entra-tenant", "entra-user", "bg/entra")
	entraCfg.Endpoint, entraCfg.AuthorityHost, entraCfg.AzureTenant, entraCfg.ClientID = entra.URL(), entra.URL(), "corp-tenant", "app-client-1"
	entraCfg.ClientSecretRef = writeServedCredentialFile(t, "a272-bg-entra-secret", "app-secret-1")
	googleCfg := idp("workspace", "google-workspace-user", "bg/google")
	googleCfg.Endpoint, googleCfg.AuthorityHost = google.URL(), google.URL()+"/token"
	googleCfg.ServiceAccount, googleCfg.AdminUser = "rotator@corp-iam.iam.gserviceaccount.com", "admin@corp.example"
	googleCfg.PrivateKeyRef = writeServedCredentialFile(t, "a272-bg-google-key", string(google.ServiceAccountKeyPEM()))
	totpCfg := config.DynamicSecretProviderConfig{TenantID: tenant, ID: "okta-bg-totp", Type: "totp", SeedRef: seedRef, MaxTTL: "30s",
		AllowedRoles: []string{"bg/okta"}}
	configs := []config.DynamicSecretProviderConfig{oktaCfg, entraCfg, googleCfg, totpCfg}
	if err = config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the providers as configured: %v", err)
	}
	dangling := oktaCfg
	dangling.TOTPProviders = map[string]string{"bg/okta": "no-such-totp"}
	if config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: []config.DynamicSecretProviderConfig{dangling, totpCfg}}, true) == nil {
		t.Fatal("a TOTP reference to no totp provider was accepted")
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newRoleHarnessWithDeps(t, nil, nil, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{tenant: registry.ForTenant(tenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: time.Second,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	sh := h.servedHarness
	registerServedTenantID(t, sh, tenant, "A272 break-glass accounts")
	admin := seedScopedTokenSubject(t, sh.store, tenant, "a272-admin", "access:read", "access:write", "access:targets.write", "secrets:read", "secrets:write")
	responder := seedScopedTokenSubject(t, sh.store, tenant, "oncall@ops.example", "access:read", "access:sessions.open")
	bystander := seedScopedTokenSubject(t, sh.store, tenant, "dev@ops.example", "access:read", "access:sessions.open")
	reviewer := seedScopedTokenSubject(t, sh.store, tenant, "a272-reviewer", "access:read", "access:approve")
	if status, body := secretsReqKey(t, sh, http.MethodPut, "/api/v1/access/emergency/responders", admin, "a272-responders",
		map[string]any{"subjects": []string{"oncall@ops.example"}}); status != http.StatusOK {
		t.Fatalf("name the responder = %d %s", status, body)
	}

	type account struct {
		target, provider, secret string
		idp                      *infratest.IdP
		totp                     bool
	}
	accounts := []account{
		{"okta-bg", "okta-org", "bg/okta", okta, true},
		{"entra-bg", "entra-tenant", "bg/entra", entra, false},
		{"google-bg", "workspace", "bg/google", google, false},
	}
	for _, a := range accounts {
		value, _ := json.Marshal(map[string]string{"username": "breakglass@corp.example", "password": "initial-password-1!"})
		if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/secrets/store", admin, "a272-bg-seed-"+a.target,
			map[string]any{"name": a.secret, "value": string(value)}); status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("seed %s: %d %s", a.secret, status, body)
		}
		status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/targets", admin, "a272-bg-register-"+a.target,
			map[string]any{"id": a.target, "target_type": "breakglass", "provider_id": a.provider, "account_secret": a.secret})
		if status != http.StatusCreated {
			t.Fatalf("register %s = %d %s", a.target, status, body)
		}
	}
	if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/targets", admin, "a272-bg-wrong-provider",
		map[string]any{"id": "totp-bg", "target_type": "breakglass", "provider_id": "okta-bg-totp", "account_secret": "bg/okta"}); status == http.StatusCreated {
		t.Fatalf("a breakglass target on a non-administrator provider was registered: %s", body)
	}
	status, body := secretsReq(t, sh, http.MethodGet, "/api/v1/access/targets/breakglass/okta-bg", admin, nil)
	var target struct {
		HardwareKeyHolders []string `json:"hardware_key_holders"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &target) != nil || !slices.Equal(target.HardwareKeyHolders, holders) {
		t.Fatalf("the break-glass target's hardware key record = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/checkouts", responder, "a272-bg-reviewed",
		map[string]any{"request_id": uuid.NewString(), "target_type": "breakglass", "target_id": "okta-bg", "reason": "IdP outage", "ttl_seconds": 120}); status == http.StatusAccepted ||
		!strings.Contains(string(body), "only through emergency access") {
		t.Fatalf("a reviewed check-out of a break-glass account = %d %s", status, body)
	}
	release := func(token, key, target string) (int, []byte, string) {
		id := uuid.NewString()
		status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/emergency-checkouts", token, key,
			map[string]any{"request_id": id, "target_type": "breakglass", "target_id": target, "reason": "SSO outage locked every admin out", "ttl_seconds": 600})
		return status, body, id
	}
	if status, _, _ := release(bystander, "a272-bg-bystander", "okta-bg"); status != http.StatusForbidden {
		t.Fatalf("a requester who is not a named responder released a break-glass account: %d", status)
	}

	var leaks [][]byte
	for _, a := range accounts {
		status, body, id := release(responder, "a272-bg-release-"+a.target, a.target)
		var released struct {
			Checkout struct {
				RequestID string `json:"request_id"`
				Status    string `json:"status"`
				Emergency bool   `json:"emergency"`
			} `json:"checkout"`
			Credential         string   `json:"credential"`
			HardwareKeyHolders []string `json:"hardware_key_holders"`
			Emergency          struct {
				Responder string `json:"responder"`
				Review    struct {
					Status string `json:"status"`
				} `json:"review"`
			} `json:"emergency"`
		}
		var credential struct {
			Username       string `json:"username"`
			Password       string `json:"password"`
			TOTPCode       string `json:"totp_code"`
			TOTPValidUntil string `json:"totp_valid_until"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &released) != nil || json.Unmarshal([]byte(released.Credential), &credential) != nil ||
			released.Checkout.Status != "revealed" || !released.Checkout.Emergency || released.Emergency.Responder != "oncall@ops.example" ||
			released.Emergency.Review.Status != "pending" || credential.Password != "initial-password-1!" {
			t.Fatalf("release %s = %d %s", a.target, status, body)
		}
		if a.totp {
			now := time.Now().Unix()
			var matched bool
			for _, step := range []int64{now / 30, now/30 - 1} {
				want, _ := crypto.HOTP(seed, uint64(step), 6, "SHA1") // #nosec G115 -- a positive clock step in a test (CWE-190)
				matched = matched || credential.TOTPCode == string(want)
			}
			if !matched || credential.TOTPValidUntil == "" || !slices.Equal(released.HardwareKeyHolders, holders) || strings.Contains(string(body), "trstctl-a272-totp-seed") {
				t.Fatalf("%s: the release's TOTP code or hardware key record = %s", a.target, body)
			}
		} else if credential.TOTPCode != "" {
			t.Fatalf("%s: a TOTP code for an account with no seed", a.target)
		}
		// Every approver is notified; the notice names no credential.
		var notice string
		if err := sh.store.SystemPool().QueryRow(ctx, `SELECT convert_from(payload, 'UTF8') FROM outbox
			WHERE tenant_id = $1 AND destination = 'notification.approval' AND idempotency_key = $2`, tenant, "emergency-access:"+id).Scan(&notice); err != nil {
			t.Fatalf("%s: no approval-channel notice: %v", a.target, err)
		}
		if !strings.Contains(notice, "oncall@ops.example") || !strings.Contains(notice, "breakglass/"+a.target) || strings.Contains(notice, "initial-password-1!") {
			t.Fatalf("%s: notice = %s", a.target, notice)
		}
		// Shown once: the same release again is refused.
		again, _ := json.Marshal(map[string]any{"request_id": id, "target_type": "breakglass", "target_id": a.target, "reason": "again", "ttl_seconds": 600})
		var againBody map[string]any
		_ = json.Unmarshal(again, &againBody)
		if status, _ := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/emergency-checkouts", responder, "a272-bg-again-"+a.target, againBody); status == http.StatusCreated {
			t.Fatalf("%s: a second release of the same check-out was allowed", a.target)
		}
		status, body = secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/checkouts/"+id+"/checkin", responder, "a272-bg-checkin-"+a.target, nil)
		var checkedIn struct {
			Status            string `json:"status"`
			RotationCommandID string `json:"rotation_command_id"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &checkedIn) != nil || checkedIn.Status != "checked_in" || checkedIn.RotationCommandID == "" {
			t.Fatalf("%s: check in = %d %s", a.target, status, body)
		}
		var view staticRotationCommandView
		for deadline := time.Now().Add(90 * time.Second); ; {
			staticRotationDueFor(t, sh, tenant)
			sh.srv.dispatchOnce(ctx)
			status, body = secretsReq(t, sh, http.MethodGet, "/api/v1/secrets/rotations/"+checkedIn.RotationCommandID, admin, nil)
			if status != http.StatusOK || json.Unmarshal(body, &view) != nil {
				t.Fatalf("%s: read the rotation: %d %s", a.target, status, body)
			}
			if view.Terminal {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: the check-in rotation did not finish: %s", a.target, body)
			}
			time.Sleep(50 * time.Millisecond)
		}
		if view.Phase != "completed" || string(a.idp.Password("breakglass@corp.example")) == "initial-password-1!" {
			t.Fatalf("%s: the released password was not retired: %+v", a.target, view)
		}
		if a.idp.Locked("breakglass@corp.example") {
			t.Fatalf("%s: the account locked out", a.target)
		}
		leaks = append(leaks, a.idp.Password("breakglass@corp.example"))
		// The post-incident review: someone else with access:approve.
		if status, body := secretsReqKey(t, sh, http.MethodPost, "/api/v1/access/emergency-sessions/"+id+"/review", reviewer, "a272-bg-review-"+a.target,
			map[string]any{"outcome": "justified", "notes": "SSO outage; credential rotated at check-in"}); status != http.StatusOK || !strings.Contains(string(body), `"status":"reviewed"`) {
			t.Fatalf("%s: post-incident review = %d %s", a.target, status, body)
		}
		_ = released.Checkout.RequestID
	}
	leaks = append(leaks, []byte("initial-password-1!"), seed, []byte(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)))
	var released, granted int
	if err = sh.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID != tenant {
			return nil
		}
		switch event.Type {
		case "pam.checkout.emergency_released":
			released++
		case "pam.emergency.opened":
			granted++
		}
		for _, s := range leaks {
			if bytes.Contains(event.Data, s) {
				t.Fatalf("a break-glass credential or seed reached event %s", event.Type)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if released != 3 || granted != 3 {
		t.Fatalf("the audit log records %d releases and %d grants, want 3 each", released, granted)
	}
}
