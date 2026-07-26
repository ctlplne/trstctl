// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
)

func fetchSSHFleet(t *testing.T, handler http.Handler, authenticated bool) (int, api.SSHFleetInventory) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ssh/fleet", nil)
	if authenticated {
		req.Header.Set("X-Tenant-ID", connectorTenantA)
		req.Header.Set("X-Roles", "admin")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var body api.SSHFleetInventory
	if rec.Code == http.StatusOK {
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return rec.Code, body
}

// B-2: the SSH surface covered the credentials trstctl issues and nothing
// about the ones it does not. These pin the roll-up an operator acts on:
// which hosts still carry standing key access, and how much of it.
func TestSSHFleetInventoryRollsUpStandingKeyAccess(t *testing.T) {
	observed := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithSSHFleet(func(_ context.Context, tenantID string) ([]api.SSHFleetHost, error) {
			if tenantID != connectorTenantA {
				t.Errorf("provider called with tenant %q", tenantID)
			}
			return []api.SSHFleetHost{
				{
					Location: "db-01:22", Keys: 4, StandingKeys: 3, OrphanedKeys: 1,
					KeyTypes: []string{"ssh-ed25519", "ssh-rsa"}, Sources: []string{"agent"},
					FirstObserved: observed, LastObserved: observed.Add(48 * time.Hour),
				},
				{Location: "web-07:22", Keys: 1, StandingKeys: 0, OrphanedKeys: 0, KeyTypes: []string{"ssh-ed25519"}},
			}, nil
		}),
	)

	code, body := fetchSSHFleet(t, handler, true)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if body.HostCount != 2 || body.KeyCount != 5 || body.StandingKeyCount != 3 || body.OrphanedKeyCount != 1 {
		t.Fatalf("rollup = %+v", body)
	}
	// The whole point: every host here is outside the CA, and the response
	// states it rather than leaving the reader to infer it.
	if body.HostsNotUnderCA != 2 {
		t.Fatalf("hosts_not_under_ca = %d, want 2", body.HostsNotUnderCA)
	}
	for _, host := range body.Hosts {
		if host.UnderCA {
			t.Fatalf("host %s claims to be under the CA", host.Location)
		}
	}
	if body.Hosts[0].Location != "db-01:22" || body.Hosts[0].StandingKeys != 3 {
		t.Fatalf("worst host = %+v, want db-01:22 first", body.Hosts[0])
	}
	if !body.Hosts[0].LastObserved.After(body.Hosts[0].FirstObserved) {
		t.Fatal("observation window did not survive the round trip")
	}
}

// An empty estate is a real answer, and the collections must serialize as []
// rather than null so a client can iterate without a nil check.
func TestSSHFleetInventoryEmptyEstate(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithSSHFleet(func(context.Context, string) ([]api.SSHFleetHost, error) { return nil, nil }),
	)

	code, body := fetchSSHFleet(t, handler, true)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if body.Hosts == nil || body.HostCount != 0 || body.HostsNotUnderCA != 0 {
		t.Fatalf("empty estate = %+v", body)
	}
}

func TestSSHFleetInventoryUnwiredAnswersEmpty(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())
	code, body := fetchSSHFleet(t, handler, true)
	if code != http.StatusOK || body.Hosts == nil {
		t.Fatalf("unwired status = %d body = %+v", code, body)
	}
}

func TestSSHFleetInventorySurfacesProviderFailure(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithSSHFleet(func(context.Context, string) ([]api.SSHFleetHost, error) {
			return nil, errors.New("inventory unavailable")
		}),
	)

	code, _ := fetchSSHFleet(t, handler, true)
	if code == http.StatusOK {
		t.Fatal("a failing inventory read reported success")
	}
}

func TestSSHFleetInventoryRequiresAuthenticatedTenant(t *testing.T) {
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithSSHFleet(func(context.Context, string) ([]api.SSHFleetHost, error) {
			return []api.SSHFleetHost{{Location: "db-01:22", Keys: 1}}, nil
		}),
	)

	code, _ := fetchSSHFleet(t, handler, false)
	if code == http.StatusOK {
		t.Fatal("unauthenticated caller received the SSH fleet inventory")
	}
}
