// SPDX-License-Identifier: BUSL-1.1

package validity

import (
	"context"
	"strings"
	"testing"
)

// P14-L2: an agent hands the checker one static credential as it found it —
// a bare token or an Authorization value — and the checker calls the
// provider whose token it is, when that provider is enabled; any other value
// calls nothing.
func TestCheckCredentialTakesABareOrBearerTokenP14L2(t *testing.T) {
	providers, srv := newTokenProviders(t)
	c := New(Config{Providers: []string{ProviderGitHub, ProviderSlack},
		Endpoints: map[string]string{ProviderGitHub: srv.URL, ProviderGitLab: srv.URL, ProviderSlack: srv.URL},
		Allowlist: []string{srv.URL}, Client: srv.Client(), Rates: map[string]float64{ProviderGitHub: 100, ProviderSlack: 100}})
	for _, tc := range []struct {
		value, provider, state, has string
	}{
		{liveGitHub, ProviderGitHub, StateValid, "user p14l1-ci"},
		{"Bearer " + deadGitHub, ProviderGitHub, StateInvalid, "Bad credentials"},
		{"  token " + liveGitHub + "\n", ProviderGitHub, StateValid, "user p14l1-ci"},
		{"Bearer " + deadSlack, ProviderSlack, StateInvalid, "token_revoked"},
	} {
		provider, state, detail, ok := c.CheckCredential(context.Background(), []byte(tc.value))
		if !ok || provider != tc.provider || state != tc.state || !strings.Contains(detail, tc.has) || strings.Contains(detail, strings.TrimSpace(tc.value)) {
			t.Fatalf("%.12s… = %s %s %q %v", tc.value, provider, state, detail, ok)
		}
	}
	providers.mu.Lock()
	before := len(providers.calls)
	providers.mu.Unlock()
	// GitLab is not enabled; a password, a token with text around it and an
	// AWS key ID are not tokens a provider here checks.
	for _, value := range []string{liveGitLab, "hunter2hunter2", "x" + liveGitHub, liveGitHub + " and more", "AKIA" + "P14ACTIVE0000001"} {
		if provider, state, _, ok := c.CheckCredential(context.Background(), []byte(value)); ok {
			t.Fatalf("%.12s… was checked: %s %s", value, provider, state)
		}
	}
	providers.mu.Lock()
	defer providers.mu.Unlock()
	if len(providers.calls) != before {
		t.Fatalf("values no enabled check covers made %d calls", len(providers.calls)-before)
	}
}
