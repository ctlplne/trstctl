// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func changeSetFixture() ChangeSet {
	disabled := false
	return ChangeSet{
		Name:     "onboard payments",
		Profiles: []BaselineProfile{{Name: "payments-web", Spec: json.RawMessage(`{"max_validity":"720h","allowed_protocols":["acme"]}`)}},
		DeploymentTargets: []BaselineDeploymentTarget{{Key: "payments-lb", Name: "payments-lb", Connector: "f5",
			Config: json.RawMessage(`{"address_ref":"payments-lb"}`), Enabled: &disabled}},
		Members: []BaselineMember{{Subject: "dev@payments.example", Roles: []string{"viewer", "auditor"}}},
		Owners:  []ChangeOwner{{Key: "payments", Kind: "team", Name: "Payments", ApplicationID: "app-42", Environment: "production"}},
	}
}

// A248: the digest is the intent. The same objects written in another order,
// with roles in another order, under another name, digest the same; a changed
// object does not.
func TestChangeSetDigestIsTheIntent(t *testing.T) {
	a := changeSetFixture()
	b := changeSetFixture()
	b.Name, b.Description = "drafted by the assistant", "the same request"
	b.Members[0].Roles = []string{"auditor", "viewer"}
	b.Profiles[0].Spec = json.RawMessage(`{"allowed_protocols":["acme"], "max_validity":"720h"}`)
	b.Owners = append([]ChangeOwner{{Key: "billing", Kind: "team", Name: "Billing"}}, b.Owners...)
	a.Owners = append(a.Owners, ChangeOwner{Key: "billing", Kind: "team", Name: "Billing"})
	if ChangeSetDigest(a) != ChangeSetDigest(b) {
		t.Fatalf("the same intent digests differently: %s vs %s", ChangeSetDigest(a), ChangeSetDigest(b))
	}
	b.Profiles[0].Spec = json.RawMessage(`{"allowed_protocols":["acme"],"max_validity":"24h"}`)
	if ChangeSetDigest(a) == ChangeSetDigest(b) {
		t.Fatal("a changed profile kept the digest")
	}
}

// A248: a change set carries references and metadata, never secret values. A
// field named for a secret, a private key, a token or a password-bearing
// connection string anywhere in it is refused by path; a reference to a stored
// secret, a certificate chain and digests pass.
func TestChangeSetSecretValuesAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(*ChangeSet)
		path  string
		shape string
	}{
		{"password field", func(cs *ChangeSet) {
			cs.DeploymentTargets[0].Config = json.RawMessage(`{"address_ref":"payments-lb","password":"hunter2"}`)
		}, "change set.deployment_targets[0].config.password", "a field for a secret value"},
		{"private key in a spec", func(cs *ChangeSet) {
			cs.Profiles[0].Spec = json.RawMessage(`{"note":"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"}`)
		}, "change set.profiles[0].spec.note", "a private key"},
		{"token in an owner field", func(cs *ChangeSet) {
			cs.Owners[0].Service = "trst_" + strings.Repeat("A", 32)
		}, "change set.owners[0].service", "a trstctl API token"},
		{"connection string", func(cs *ChangeSet) {
			cs.DeploymentTargets[0].Config = json.RawMessage(`{"address_ref":"payments-lb","endpoint":"postgres://app:s3cret@db.internal/payments"}`)
		}, "change set.deployment_targets[0].config.endpoint", "a connection string with a password"},
	} {
		cs := changeSetFixture()
		tc.edit(&cs)
		path, shape := changeSetSecret(cs)
		if path != tc.path || shape != tc.shape {
			t.Fatalf("%s: found %q holding %q; want %q holding %q", tc.name, path, shape, tc.path, tc.shape)
		}
	}
	cs := changeSetFixture()
	cs.Issuers = []BaselineIssuer{{Key: "ca", Name: "Payments CA", Kind: "x509_ca",
		Chain: []string{"-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ2Vy" + strings.Repeat("dGlmaWNhdGU", 8) + "\n-----END CERTIFICATE-----\n"}}}
	cs.Profiles[0].Spec = json.RawMessage(`{"pinned_spki_sha256":"` + strings.Repeat("ab", 32) + `"}`)
	if path, shape := changeSetSecret(cs); path != "" {
		t.Fatalf("a certificate chain, a digest and a credential reference were refused at %s (%s)", path, shape)
	}
}

// A248: a change set names each object exactly; a pattern anywhere a name, key,
// subject or role goes is over-broad.
func TestChangeSetPatternsAreOverBroad(t *testing.T) {
	for _, edit := range []func(*ChangeSet){
		func(cs *ChangeSet) { cs.Members[0].Subject = "*@payments.example" },
		func(cs *ChangeSet) { cs.Members[0].Roles = []string{"*"} },
		func(cs *ChangeSet) { cs.Profiles[0].Name = "payments-?" },
		func(cs *ChangeSet) { cs.Owners[0].Key = "team[0-9]" },
	} {
		cs := changeSetFixture()
		edit(&cs)
		if field, _ := broadChangeName(cs); field == "" {
			t.Fatalf("a pattern was taken as one object: %+v", cs)
		}
	}
	if field, value := broadChangeName(changeSetFixture()); field != "" {
		t.Fatalf("exact names were refused: %s %q", field, value)
	}
}
