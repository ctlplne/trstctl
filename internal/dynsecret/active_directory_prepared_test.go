// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func adPreparationFixture() adStaticPreparation {
	return adStaticPreparation{Version: 1, Role: "service", OperationID: "owned-operation", Predecessor: "CN=service,OU=services,DC=example,DC=test", ProviderBinding: strings.Repeat("a", 64), DN: "CN=service,OU=services,DC=example,DC=test", Name: "service", GUID: strings.Repeat("b", 32), SID: "010100000000000515000000", PasswordSetAt: "1", Password: []byte("Owned1!prepared-password")}
}
func TestADPreparationParserAndBindingA267(t *testing.T) {
	good := adPreparationFixture()
	raw, err := json.Marshal(good) // #nosec G117 -- synthetic byte-backed parser fixture, wiped and never logged (CWE-200)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(raw)
	p, err := decodeADStaticPreparation(raw)
	if err != nil {
		t.Fatal(err)
	}
	p.destroy()
	for name, mutate := range map[string]func(*adStaticPreparation){"version": func(p *adStaticPreparation) { p.Version = 2 }, "missing operation": func(p *adStaticPreparation) { p.OperationID = "" }, "binding": func(p *adStaticPreparation) { p.ProviderBinding = "not-a-configuration-hash" }, "native GUID": func(p *adStaticPreparation) { p.GUID = "foreign" }, "native SID": func(p *adStaticPreparation) { p.SID = "not-hex" }, "missing stamp": func(p *adStaticPreparation) { p.PasswordSetAt = "" }, "short credential": func(p *adStaticPreparation) { p.Password = []byte("short") }} {
		t.Run(name, func(t *testing.T) {
			candidate := adPreparationFixture()
			mutate(&candidate)
			raw, err := json.Marshal(candidate) // #nosec G117 -- synthetic rejected credential fixture, wiped and never logged (CWE-200)
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Wipe(raw)
			if parsed, e := decodeADStaticPreparation(raw); e == nil {
				parsed.destroy()
				t.Fatal("malformed preparation accepted")
			}
		})
	}
	cfg := LDAPConfig{DirectoryMode: "active_directory", Addr: "127.0.0.1:1", TLSServerName: "owned.test", BindDN: "CN=admin,DC=example,DC=test", BindPassword: []byte("owned-test-administrator"), UsersDN: "OU=services,DC=example,DC=test", RoleGroups: map[string]string{"service": good.DN}}
	backend, err := NewLDAPBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	for _, req := range []GenerateRequest{{Role: "foreign", LeaseID: good.OperationID, Static: true, Predecessor: good.DN}, {Role: good.Role, LeaseID: "different-operation", Static: true, Predecessor: good.DN}, {Role: good.Role, LeaseID: good.OperationID, Static: false, Predecessor: good.DN}, {Role: good.Role, LeaseID: good.OperationID, Static: true, Predecessor: "foreign"}} {
		if _, _, err := backend.GenerateStaticPrepared(t.Context(), req, raw, good.ProviderBinding); err == nil || !strings.Contains(err.Error(), "preparation differs") {
			t.Fatalf("changed authority reached native IO: %v", err)
		}
	}
	req := GenerateRequest{Role: good.Role, LeaseID: good.OperationID, Static: true, Predecessor: good.DN}
	if _, _, err := backend.GenerateStaticPrepared(t.Context(), req, raw, strings.Repeat("c", 64)); err == nil || !strings.Contains(err.Error(), "preparation differs") {
		t.Fatal("changed provider binding reached native IO")
	}
}
func FuzzADStaticPreparationA267(f *testing.F) {
	raw, err := json.Marshal(adPreparationFixture()) // #nosec G117 -- synthetic byte-backed fuzz/parser seed, never logged (CWE-200)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"version":1,"password":"owned"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		value, _ := decodeADStaticPreparation(raw)
		value.destroy()
	})
}

func TestADPreparationRejectsAmbiguousJSONA267(t *testing.T) {
	raw, err := json.Marshal(adPreparationFixture()) // #nosec G117 -- synthetic byte-backed fuzz/parser seed, never logged (CWE-200)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(raw)
	for _, candidate := range [][]byte{
		bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"Version":1`), 1),
		bytes.Replace(raw, []byte(`"password":`), []byte(`"pass\u0077ord":`), 1),
	} {
		value, err := decodeADStaticPreparation(candidate)
		value.destroy()
		secret.Wipe(candidate)
		if err == nil {
			t.Fatal("ambiguous or alternate-spelling preparation key accepted")
		}
	}
}

func TestADPreparationRetainsEveryResetGenerationA267(t *testing.T) {
	p := adPreparationFixture()
	p.Version = 2
	p.KeyVersion = 48
	p.DCInvocationID = strings.Repeat("c", 32)
	p.NativeAddress = "127.0.0.1:636"
	p.ForwardIntermediate = []byte("Owned1!forward-intermediate")
	p.InverseIntermediate = []byte("Owned1!inverse-intermediate")
	raw, e := marshalADStaticPreparation(p)
	if e != nil {
		t.Fatal(e)
	}
	defer secret.Wipe(raw)
	parsed, e := decodeADStaticPreparation(raw)
	if e != nil {
		t.Fatal("complete durable reset preparation refused", e)
	}
	final, forward, inverse := parsed.Password, parsed.ForwardIntermediate, parsed.InverseIntermediate
	if !bytes.Equal(final, p.Password) || !bytes.Equal(forward, p.ForwardIntermediate) || !bytes.Equal(inverse, p.InverseIntermediate) || parsed.KeyVersion != 48 || parsed.DCInvocationID != p.DCInvocationID {
		t.Fatal("sealed reset preparation lost a generation or native authority")
	}
	parsed.destroy()
	for _, held := range [][]byte{final, forward, inverse} {
		for _, v := range held {
			if v != 0 {
				t.Fatal("destroyed preparation retained reset material")
			}
		}
	}
	for _, mutate := range []func(*adStaticPreparation){
		func(v *adStaticPreparation) { v.ForwardIntermediate = nil },
		func(v *adStaticPreparation) { v.InverseIntermediate = v.Password },
		func(v *adStaticPreparation) { v.KeyVersion = 0 },
		func(v *adStaticPreparation) { v.KeyVersion = 1<<32 - 3 },
		func(v *adStaticPreparation) { v.DCInvocationID = "foreign" },
		func(v *adStaticPreparation) { v.NativeAddress = "unreviewed.test:636" },
	} {
		candidate := p
		mutate(&candidate)
		wire, e := marshalADStaticPreparation(candidate)
		if e != nil {
			continue
		}
		value, e := decodeADStaticPreparation(wire)
		value.destroy()
		secret.Wipe(wire)
		if e == nil {
			t.Fatal("incomplete, aliased or unbound reset generations accepted")
		}
	}
}
