// SPDX-License-Identifier: MPL-2.0

package traefik_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/traefik"
)

var (
	certA = []byte("-----BEGIN CERTIFICATE-----\ntraefik-cert-a\n-----END CERTIFICATE-----\n")
	keyA  = []byte("-----BEGIN PRIVATE KEY-----\ntraefik-key-a\n-----END PRIVATE KEY-----\n")
	certB = []byte("-----BEGIN CERTIFICATE-----\ntraefik-cert-b\n-----END CERTIFICATE-----\n")
	keyB  = []byte("-----BEGIN PRIVATE KEY-----\ntraefik-key-b\n-----END PRIVATE KEY-----\n")
)

func TestDeployWritesIdempotently(t *testing.T) {
	base := connector.NewMemoryOps()
	ops := &countingOps{MemoryOps: base}
	c := traefik.New("/etc/traefik/certs/site.pem", "/etc/traefik/certs/site.key")
	dep := connector.NewDeployment("edge", certA, keyA)

	if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
		t.Fatalf("first Deploy: %v", err)
	}
	assertFile(t, base, "/etc/traefik/certs/site.pem", certA)
	assertFile(t, base, "/etc/traefik/certs/site.key", keyA)
	if ops.writes != 2 {
		t.Fatalf("first deploy writes = %d, want cert+key", ops.writes)
	}

	if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
		t.Fatalf("second Deploy: %v", err)
	}
	if ops.writes != 2 {
		t.Fatalf("idempotent deploy writes = %d, want still 2", ops.writes)
	}
}

func TestDeployRollsBackWhenKeyWriteFails(t *testing.T) {
	base := connector.NewMemoryOps()
	if err := base.WriteFile("/etc/traefik/certs/site.pem", certA); err != nil {
		t.Fatal(err)
	}
	if err := base.WriteFile("/etc/traefik/certs/site.key", keyA); err != nil {
		t.Fatal(err)
	}
	ops := &failWriteOps{
		MemoryOps: base,
		failPath:  "/etc/traefik/certs/site.key",
		err:       errors.New("disk full"),
	}
	c := traefik.New("/etc/traefik/certs/site.pem", "/etc/traefik/certs/site.key")

	_, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("edge", certB, keyB))
	if err == nil {
		t.Fatal("Deploy succeeded; want key-write failure")
	}
	if !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("Deploy error = %q, want rollback context", err)
	}
	assertFile(t, base, "/etc/traefik/certs/site.pem", certA)
	assertFile(t, base, "/etc/traefik/certs/site.key", keyA)
}

type countingOps struct {
	*connector.MemoryOps
	writes int
}

func (c *countingOps) WriteFile(path string, data []byte) error {
	c.writes++
	return c.MemoryOps.WriteFile(path, data)
}

type failWriteOps struct {
	*connector.MemoryOps
	failPath string
	err      error
}

func (f *failWriteOps) WriteFile(path string, data []byte) error {
	if path == f.failPath {
		return f.err
	}
	return f.MemoryOps.WriteFile(path, data)
}

func assertFile(t *testing.T, ops *connector.MemoryOps, path string, want []byte) {
	t.Helper()
	got, ok := ops.File(path)
	if !ok {
		t.Fatalf("%s was not written", path)
	}
	if string(got) != string(want) {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}
