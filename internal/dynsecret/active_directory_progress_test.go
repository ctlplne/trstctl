// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"os"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestNativeADResetProgressReadA267(t *testing.T) {
	if os.Getenv("TRSTCTL_AD_PROGRESS_LAB") != "1" {
		t.Skip("owned native AD progress lab not requested")
	}
	admin, e := os.ReadFile("/run/ad-admin-password")
	if e != nil {
		t.Fatal(e)
	}
	defer secret.Wipe(admin)
	ca, e := os.ReadFile("/run/ad-ca.pem")
	if e != nil {
		t.Fatal(e)
	}
	const dn = "CN=a267-prepared,OU=TrstctlA263,DC=a263,DC=test"
	backend, e := NewLDAPBackend(LDAPConfig{DirectoryMode: "active_directory", Addr: "ad263:636", TLSServerName: "ad263", TLSCAPEM: ca, BindDN: "CN=Administrator,CN=Users,DC=a263,DC=test", BindPassword: admin, UsersDN: "OU=TrstctlA263,DC=a263,DC=test", RoleGroups: map[string]string{"directory/prepared": dn}})
	if e != nil {
		t.Fatal(e)
	}
	defer backend.Close()
	identity, e := backend.inspectADResetIdentity(t.Context(), dn, backend.adRoute())
	if e != nil || identity.KeyVersion < 1 || identity.DCInvocationID == "" || identity.NativeAddress == "" || identity.Name != "a267-prepared" {
		t.Fatal("native version/DC progress identity unavailable", e)
	}
	route := backend.adRoute()
	route.Address = identity.NativeAddress
	same, e := backend.inspectADResetIdentity(t.Context(), dn, route)
	if e != nil || same != identity {
		t.Fatal("literal-address read changed the exact native object/DC authority", e)
	}
	t.Log("A267_AD_PROGRESS_READ_OK: native account version, DC invocation, literal verified route and default non-emulated version heuristic; read-only proof")
}

func TestADResetProgressSelectsOneFrozenGenerationA267(t *testing.T) {
	p := adPreparationFixture()
	p.Version = 2
	p.KeyVersion = 48
	p.DCInvocationID = strings.Repeat("c", 32)
	p.NativeAddress = "127.0.0.1:636"
	initial := adNativeResetIdentity{adNativeIdentity: adNativeIdentity{Name: p.Name, GUID: p.GUID, SID: p.SID, PasswordSetAt: p.PasswordSetAt}, KeyVersion: p.KeyVersion, DCInvocationID: p.DCInvocationID, NativeAddress: p.NativeAddress}
	for offset := uint64(0); offset <= 4; offset++ {
		current := initial
		current.KeyVersion += offset
		if offset > 0 {
			current.PasswordSetAt = "2"
		}
		position, e := p.resetPosition(current)
		if e != nil || uint64(position) != offset {
			t.Fatal("native attribute version selected another reset generation", offset, e)
		}
	}
	for _, mutate := range []func(*adNativeResetIdentity){
		func(v *adNativeResetIdentity) { v.KeyVersion-- }, func(v *adNativeResetIdentity) { v.KeyVersion += 5 },
		func(v *adNativeResetIdentity) { v.DCInvocationID = strings.Repeat("d", 32) },
		func(v *adNativeResetIdentity) { v.NativeAddress = "127.0.0.2:636" },
		func(v *adNativeResetIdentity) { v.GUID = strings.Repeat("e", 32) },
		func(v *adNativeResetIdentity) { v.SID = "foreign" }, func(v *adNativeResetIdentity) { v.Name = "foreign" },
		func(v *adNativeResetIdentity) { v.PasswordSetAt = "2" },
	} {
		current := initial
		mutate(&current)
		if _, e := p.resetPosition(current); e == nil {
			t.Fatal("foreign, unexplained or stale native progress selected a credential")
		}
	}
}
