// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// a239OathtoolImage is the lab image the A239 runner builds: the pinned
// debian:bookworm-slim base plus Debian's oathtool package (the runner logs its
// version), so the codes are checked by a stock implementation.
const a239OathtoolImage = "trstctl-lab-oathtool:a239"

// A239 against a stock verifier: the TOTP provider, configured as the binary
// configures it, issues a lease whose code oathtool accepts for the time step
// the lease names and rejects one step later; the code can't be renewed, and
// revoking the lease is recorded without any upstream call.
func TestServedDynamicTOTPLeaseVerifiesWithOathtoolA239(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := exec.Command("docker", "image", "inspect", a239OathtoolImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the lab image %s is not present locally (runners build it): %v\n%s", a239OathtoolImage, err, out)
	}
	// #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
	const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "ops-totp", Type: "totp", SeedRef: writeServedCredentialFile(t, "totp-seed", seed),
		Digits: 6, Period: "30s", AllowedRoles: []string{"operator"}, MaxTTL: "30s",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "A239 TOTP tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a239-totp-lease-1",
		map[string]any{"provider": "ops-totp", "role": "operator", "ttl_seconds": 30})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("issue: %d %s", status, body)
	}
	var lease dynamicLeaseView
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("decode the lease: %v %s", err, body)
	}
	var credential struct {
		Code          string    `json:"code"`
		ValidUntil    time.Time `json:"valid_until"`
		PeriodSeconds int64     `json:"period_seconds"`
	}
	if err := json.Unmarshal([]byte(lease.Credential), &credential); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9]{6}$`).MatchString(credential.Code) || credential.PeriodSeconds != 30 ||
		credential.ValidUntil.Unix()%30 != 0 || !credential.ValidUntil.After(lease.IssuedAt.Add(-time.Second)) ||
		credential.ValidUntil.After(lease.IssuedAt.Add(31*time.Second)) {
		t.Fatalf("credential %+v for a lease issued at %s", credential, lease.IssuedAt)
	}

	// oathtool, given the instant inside the code's step and the next step's
	// first second, accepts the code only in its own step (window 0).
	oathtool := func(at int64, args ...string) (string, error) {
		command := append([]string{"run", "--rm", "--network", "none", a239OathtoolImage, "oathtool", "--totp", "--base32", "--digits=6",
			"--time-step-size=30s", "--window=0", "--now=@" + strconv.FormatInt(at, 10)}, args...)
		out, err := exec.Command("docker", command...).CombinedOutput() // #nosec G204 -- fixed lab image, arguments built by the test (CWE-78)
		return strings.TrimSpace(string(out)), err
	}
	inStep := credential.ValidUntil.Unix() - 1
	if out, err := oathtool(inStep, seed); err != nil || out != credential.Code {
		t.Fatalf("oathtool computes %q for its step, the lease carried %q (%v)", out, credential.Code, err)
	}
	if out, err := oathtool(inStep, seed, credential.Code); err != nil {
		t.Fatalf("oathtool refused the leased code inside its step: %v %s", err, out)
	}
	if out, err := oathtool(credential.ValidUntil.Unix(), seed, credential.Code); err == nil {
		t.Fatalf("oathtool accepted the leased code after valid_until: %s", out)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/renew", tok, map[string]any{"extend_seconds": 10})
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "can't be renewed") {
		t.Fatalf("a one-time code was renewed: %d %s", status, body)
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke: %d %s", status, body)
	}
	t.Logf("A239_TOTP_OK lease=%s valid_until=%s", lease.ID, credential.ValidUntil.Format(time.RFC3339))
}
