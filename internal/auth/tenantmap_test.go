package auth

import (
	"errors"
	"testing"
)

// TestTenantMapperResolvesPerUser is the TENANT-004 unit proof: distinct users
// resolve to distinct tenants (by subject, by tenant claim, by group, by the
// claim-is-tenant mode), and an unmapped user is rejected with ErrNoTenant rather
// than collapsing to one tenant. This is the per-user → tenant mapping that
// replaces the single DefaultTenant.
func TestTenantMapperResolvesPerUser(t *testing.T) {
	const (
		tenantA = "11111111-1111-1111-1111-111111111111"
		tenantB = "22222222-2222-2222-2222-222222222222"
		tenantC = "33333333-3333-3333-3333-333333333333"
	)
	m := TenantMapper{
		Mappings: []TenantMapping{
			{Subject: "alice", TenantID: tenantA, Roles: []string{"admin"}},
			{Claim: "acme-corp", TenantID: tenantB},
			{Group: "platform-eng", TenantID: tenantC, Roles: []string{"operator"}},
		},
		DefaultRoles: []string{"viewer"},
	}

	cases := []struct {
		name       string
		claims     Claims
		wantTenant string
		wantRoles  []string
		wantErr    bool
	}{
		{"subject mapping wins", Claims{Subject: "alice", Tenant: "acme-corp"}, tenantA, []string{"admin"}, false},
		{"tenant-claim mapping", Claims{Subject: "bob", Tenant: "acme-corp"}, tenantB, []string{"viewer"}, false},
		{"group mapping", Claims{Subject: "carol", Groups: []string{"x", "platform-eng"}}, tenantC, []string{"operator"}, false},
		{"unmapped user is rejected (fail closed)", Claims{Subject: "mallory", Tenant: "evil-corp"}, "", nil, true},
		{"no-tenant login rejected", Claims{Subject: "nobody"}, "", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotT, gotR, err := m.ResolveTenant(tc.claims)
			if tc.wantErr {
				if !errors.Is(err, ErrNoTenant) {
					t.Fatalf("err = %v, want ErrNoTenant", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotT != tc.wantTenant {
				t.Errorf("tenant = %q, want %q", gotT, tc.wantTenant)
			}
			if !equalStrings(gotR, tc.wantRoles) {
				t.Errorf("roles = %v, want %v", gotR, tc.wantRoles)
			}
		})
	}
}

// TestTenantMapperClaimIsTenant: in claim-is-tenant mode the tenant-claim value is
// used directly as the tenant id (the IdP stamps the trustctl tenant into the
// token), but an empty claim still fails closed.
func TestTenantMapperClaimIsTenant(t *testing.T) {
	m := TenantMapper{ClaimIsTenant: true, DefaultRoles: []string{"viewer"}}
	gotT, gotR, err := m.ResolveTenant(Claims{Subject: "u", Tenant: "tenant-xyz"})
	if err != nil {
		t.Fatalf("claim-is-tenant resolve: %v", err)
	}
	if gotT != "tenant-xyz" || !equalStrings(gotR, []string{"viewer"}) {
		t.Fatalf("got (%q,%v), want (tenant-xyz,[viewer])", gotT, gotR)
	}
	if _, _, err := m.ResolveTenant(Claims{Subject: "u"}); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("empty tenant claim must fail closed, got %v", err)
	}
}

// TestTenantMapperDefaultIsOptIn: the legacy single-tenant default applies ONLY
// when AllowDefault is set; otherwise an unmapped user is rejected. This is the
// multi-tenant fail-closed posture.
func TestTenantMapperDefaultIsOptIn(t *testing.T) {
	withDefault := TenantMapper{DefaultTenant: "t-default", DefaultRoles: []string{"viewer"}, AllowDefault: true}
	if gotT, _, err := withDefault.ResolveTenant(Claims{Subject: "u"}); err != nil || gotT != "t-default" {
		t.Fatalf("opt-in default: got (%q,%v), want (t-default,nil)", gotT, err)
	}
	noDefault := TenantMapper{DefaultTenant: "t-default", AllowDefault: false}
	if _, _, err := noDefault.ResolveTenant(Claims{Subject: "u"}); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("default-off must fail closed, got %v", err)
	}
}

// TestTenantMapperValidate rejects a mapper that could never resolve a tenant or
// has malformed mappings (the misconfiguration guard).
func TestTenantMapperValidate(t *testing.T) {
	if err := (TenantMapper{}).Validate(); err == nil {
		t.Error("empty mapper with no default must be invalid (every login would fail closed)")
	}
	if err := (TenantMapper{Mappings: []TenantMapping{{Subject: "a", Claim: "b", TenantID: "t"}}}).Validate(); err == nil {
		t.Error("a mapping with two match keys must be invalid")
	}
	if err := (TenantMapper{Mappings: []TenantMapping{{Subject: "a"}}}).Validate(); err == nil {
		t.Error("a mapping with no tenant_id must be invalid")
	}
	if err := (TenantMapper{ClaimIsTenant: true}).Validate(); err != nil {
		t.Errorf("claim-is-tenant mode is a valid resolution path: %v", err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
