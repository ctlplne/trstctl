// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

type kafkaACLKey struct {
	principal, op, kind, name string
	prefix                    bool
}

// fakeKafka keeps SCRAM credentials and ACLs the way a broker does: an upsert
// replaces a password, an existing ACL binding is unchanged by a second create.
type fakeKafka struct {
	scram    map[string]string
	acls     map[kafkaACLKey]bool
	calls    []string
	failACLs bool
	opened   int
	closed   int
}

func (f *fakeKafka) UpsertSCRAM(_ context.Context, user string, password []byte) error {
	f.calls = append(f.calls, "upsert "+user)
	f.scram[user] = string(password)
	return nil
}

func (f *fakeKafka) CreateACLs(_ context.Context, acls kafkaACLs) error {
	f.calls = append(f.calls, "create-acls "+acls.Principal)
	if f.failACLs {
		return errors.New("CLUSTER_AUTHORIZATION_FAILED")
	}
	for _, op := range acls.Operations {
		for kind, names := range acls.Names {
			for _, name := range names {
				f.acls[kafkaACLKey{acls.Principal, op, kind, name, acls.Prefix}] = true
			}
		}
	}
	return nil
}

func (f *fakeKafka) DeleteACLs(_ context.Context, principal string) error {
	f.calls = append(f.calls, "delete-acls "+principal)
	for key := range f.acls {
		if key.principal == principal {
			delete(f.acls, key)
		}
	}
	return nil
}

func (f *fakeKafka) DeleteSCRAM(_ context.Context, user string) error {
	f.calls = append(f.calls, "delete-scram "+user)
	delete(f.scram, user)
	return nil
}

func (f *fakeKafka) Close() { f.closed++ }

func newFakeKafkaBackend(t *testing.T, fake *fakeKafka) *KafkaBackend {
	t.Helper()
	b, err := NewKafkaBackend(KafkaConfig{
		Addr: "127.0.0.1:9092", AllowPlaintext: true, AdminUser: "lab_admin", AdminPassword: []byte("lab-admin-password"),
		RoleBindings: map[string]string{
			"consumer": "read,describe on topic:orders; read on group:orders-app",
			"logs":     "write,describe on topic:logs-*",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	b.connect = func(context.Context) (kafkaAdmin, error) {
		fake.opened++
		return fake, nil
	}
	t.Cleanup(b.Close)
	return b
}

func TestKafkaLeaseIsASCRAMUserWithOnlyItsRoleACLsA239(t *testing.T) {
	fake := &fakeKafka{scram: map[string]string{}, acls: map[kafkaACLKey]bool{}}
	b := newFakeKafkaBackend(t, fake)
	req := GenerateRequest{Role: "consumer", LeaseID: "lease-0001"}
	user, credential, err := b.CreateCredential(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct{ Username, Password, Mechanism string }
	if err := json.Unmarshal(credential, &got); err != nil || got.Username != user || len(got.Password) != 48 || got.Mechanism != "SCRAM-SHA-512" {
		t.Fatalf("credential %+v (%v)", got, err)
	}
	principal := "User:" + user
	want := map[kafkaACLKey]bool{
		{principal, "read", "topic", "orders", false}: true, {principal, "describe", "topic", "orders", false}: true,
		{principal, "read", "group", "orders-app", false}: true,
	}
	if fake.scram[user] != got.Password || !mapsEqual(fake.acls, want) {
		t.Fatalf("cluster after issue: scram %v, acls %v", fake.scram, fake.acls)
	}
	// A retry of the same lease replaces the password; it adds no user and no ACL.
	again, credential2, err := b.CreateCredential(context.Background(), req)
	var got2 struct{ Password string }
	_ = json.Unmarshal(credential2, &got2)
	if err != nil || again != user || len(fake.scram) != 1 || fake.scram[user] != got2.Password || got2.Password == got.Password || !mapsEqual(fake.acls, want) {
		t.Fatalf("retry: %q (%v); scram %v, acls %v", again, err, fake.scram, fake.acls)
	}
	logs, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "logs", LeaseID: "lease-0002"})
	if err != nil || !fake.acls[kafkaACLKey{"User:" + logs, "write", "topic", "logs-", true}] || fake.acls[kafkaACLKey{"User:" + logs, "write", "topic", "logs-", false}] {
		t.Fatalf("prefixed grant: %v, acls %v", err, fake.acls)
	}
	fake.calls = nil
	if err := b.Revoke(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	// The ACLs go first: an open connection is refused from its next request.
	if !slices.Equal(fake.calls, []string{"delete-acls " + principal, "delete-scram " + user}) || fake.scram[user] != "" {
		t.Fatalf("revocation calls %v", fake.calls)
	}
	for key := range fake.acls {
		if key.principal == principal {
			t.Fatalf("ACL left after revocation: %+v", key)
		}
	}
	if err := b.Revoke(context.Background(), user); err != nil {
		t.Fatalf("a second revocation of a removed user: %v", err)
	}
	for _, foreign := range []string{"admin", "lab_admin", "app_reader_1", "trstctl/../x", "User:trstctl_x"} {
		if err := b.Revoke(context.Background(), foreign); err == nil {
			t.Errorf("revoked %q, a user this provider did not create", foreign)
		}
	}
	if fake.opened != fake.closed {
		t.Fatalf("admin clients opened %d, closed %d", fake.opened, fake.closed)
	}
}

func TestKafkaFailedACLsRemoveTheNewUserA239(t *testing.T) {
	fake := &fakeKafka{scram: map[string]string{}, acls: map[kafkaACLKey]bool{}, failACLs: true}
	b := newFakeKafkaBackend(t, fake)
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "consumer", LeaseID: "lease-0003"}); err == nil {
		t.Fatal("issued with failed ACLs")
	}
	if len(fake.scram) != 0 || len(fake.acls) != 0 {
		t.Fatalf("left behind: scram %v, acls %v", fake.scram, fake.acls)
	}
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "admin", LeaseID: "lease-0004"}); err == nil {
		t.Fatal("issued an unbound role")
	}
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "consumer", LeaseID: "lease-0005", Static: true}); err == nil {
		t.Fatal("served a static credential")
	}
}

func TestKafkaGrantGrammarA239(t *testing.T) {
	clauses, err := ParseKafkaGrant("read,describe on topic:orders, group:orders-app; write on topic:logs-*, transactional_id:etl")
	if err != nil || len(clauses) != 2 || !slices.Equal(clauses[0].Operations, []string{"read", "describe"}) ||
		clauses[0].Resources[1] != (KafkaResource{Type: "group", Name: "orders-app"}) ||
		clauses[1].Resources[0] != (KafkaResource{Type: "topic", Name: "logs-", Prefix: true}) {
		t.Fatalf("clauses %+v (%v)", clauses, err)
	}
	for _, bad := range []string{
		"read", "read on ", "read on topic:", "read on topic:*", "all on topic:orders", "read on cluster:kafka-cluster",
		"read on topic:or ders", "read on orders", "read on topic:orders;", "read on topic:orders\nwrite on topic:x",
	} {
		if _, err := ParseKafkaGrant(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestKafkaTransportA239(t *testing.T) {
	base := KafkaConfig{Addr: "kafka.example:9093", AdminUser: "admin", AdminPassword: []byte("pw"),
		RoleBindings: map[string]string{"r": "read on topic:orders"}}
	b, err := NewKafkaBackend(base)
	if err != nil || !b.tls || b.serverName != "" {
		t.Fatalf("TLS by default: %v", err)
	}
	b.Close()
	for name, mutate := range map[string]func(*KafkaConfig){
		"plaintext to a name":      func(c *KafkaConfig) { c.AllowPlaintext = true },
		"plaintext to a public IP": func(c *KafkaConfig) { c.Addr, c.AllowPlaintext = "203.0.113.7:9092", true },
		"plaintext with TLS":       func(c *KafkaConfig) { c.Addr, c.AllowPlaintext, c.TLSServerName = "10.0.0.5:9092", true, "kafka" },
		"IP without a TLS name":    func(c *KafkaConfig) { c.Addr = "10.0.0.5:9093" },
		"no port":                  func(c *KafkaConfig) { c.Addr = "kafka.example" },
		"no administrator":         func(c *KafkaConfig) { c.AdminUser = "" },
		"no password":              func(c *KafkaConfig) { c.AdminPassword = nil },
		"no roles":                 func(c *KafkaConfig) { c.RoleBindings = nil },
		"bad grant":                func(c *KafkaConfig) { c.RoleBindings = map[string]string{"r": "read on topic:*"} },
	} {
		c := base
		mutate(&c)
		if b, err := NewKafkaBackend(c); err == nil {
			b.Close()
			t.Errorf("%s: accepted", name)
		}
	}
	// A plaintext provider never follows a broker's advertised address off
	// loopback or private IPs.
	c := base
	c.Addr, c.AllowPlaintext = "127.0.0.1:9092", true
	b, err = NewKafkaBackend(c)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.dialBroker(context.Background(), "tcp", "203.0.113.7:9092"); err == nil {
		t.Fatal("dialed plaintext to a public address")
	}
}

func mapsEqual[K comparable](a, b map[K]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
