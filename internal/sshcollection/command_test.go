// SPDX-License-Identifier: BUSL-1.1

package sshcollection

import (
	"encoding/json"
	"strings"
	"testing"
)

func collectionConfig() Config {
	return Config{Enabled: true, Segment: "owned", RelayAgentID: "a2270000-0000-4000-8000-000000000001", AllowLoopback: true, Hosts: []Host{{Address: "127.0.0.1:2222", Username: "trstctl_observe", HostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), CredentialRef: "secret://ssh/reader"}}} // #nosec G101 -- public host pin, restricted account and vault-reference fixtures contain no credential value (CWE-798).
}
func TestCollectionRequiresExplicitScopePinAndVaultReference(t *testing.T) {
	for name, change := range map[string]func(*Config){"off": func(c *Config) { c.Enabled = false }, "no-relay": func(c *Config) { c.RelayAgentID = "" }, "no-pin": func(c *Config) { c.Hosts[0].HostKeyFingerprint = "" }, "root": func(c *Config) { c.Hosts[0].Username = "root" }, "shell": func(c *Config) { c.Hosts[0].Username = "reader; command" }, "url-target": func(c *Config) { c.Hosts[0].Address = "user@host:22" }, "raw-key": func(c *Config) { c.Hosts[0].CredentialRef = "-----BEGIN PRIVATE KEY-----" }, "no-segment": func(c *Config) { c.Segment = "" }} {
		t.Run(name, func(t *testing.T) {
			c := collectionConfig()
			change(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("unbound agentless collection authority accepted")
			}
		})
	}
	c := collectionConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{`"command":"tenant shell"`, `"public_file":"/private/key"`, `"private_key":"inline"`} {
		bad := strings.TrimSuffix(string(raw), "}") + "," + extra + "}"
		if _, err := DecodeConfig([]byte(bad)); err == nil {
			t.Fatal("remote command/path or inline material entered source config")
		}
	}
	if _, err := DecodeConfig(append(raw, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing source command accepted")
	}
}
func TestCollectionCommandBindsHostIdentityCredentialAndRelay(t *testing.T) {
	c := collectionConfig().Resolve()
	c.ID = "a2270000-0000-4000-8000-000000000002"
	c.SourceID = "a2270000-0000-4000-8000-000000000003"
	want, err := c.Digest()
	if err != nil {
		t.Fatal(err)
	}
	other := c
	other.Hosts = append([]Host(nil), c.Hosts...)
	other.Hosts[0].CredentialRef = "secret://other/reader"
	got, err := other.Digest()
	if err != nil || got == want {
		t.Fatal("credential selection is not bound")
	}
	other = c
	other.RequiredAgentID = "a2270000-0000-4000-8000-000000000004"
	got, err = other.Digest()
	if err != nil || got == want {
		t.Fatal("selected relay is not bound")
	}
	if refs := c.CredentialRefs(); len(refs) != 1 || refs[0] != c.Hosts[0].CredentialRef {
		t.Fatal("credential reference set differs from command")
	}
}
