package projections_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/javakeystore"
	"trstctl.com/trstctl/internal/crypto/pfx"
	"trstctl.com/trstctl/internal/orchestrator"
)

const (
	jksKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguSjwYXld9WA6+GXM
uiBvryiQ90RZx9HA7kPBwGKEmiihRANCAAT7FkWuZX/8pAX39mA+sX9aNoBwwLiF
tC/tbv9HKUb/KCNxLa7F0pZJwVIPsHXaVwTardDEh0MnPgh0j3ulaa0G
-----END PRIVATE KEY-----
`
	jksCertPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIUcx0QtLdtk6up3COWRwqCyBvODsYwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNa2V5c3RvcmUudGVzdDAeFw0yNjA1MzAxNTQwMjdaFw0zNjA1
MjcxNTQwMjdaMBgxFjAUBgNVBAMMDWtleXN0b3JlLnRlc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAT7FkWuZX/8pAX39mA+sX9aNoBwwLiFtC/tbv9HKUb/KCNx
La7F0pZJwVIPsHXaVwTardDEh0MnPgh0j3ulaa0Go1MwUTAdBgNVHQ4EFgQUxCW/
Ky+OGKi2+qs6KAJc8H3T6cgwHwYDVR0jBBgwFoAUxCW/Ky+OGKi2+qs6KAJc8H3T
6cgwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAsEewyxjXXOdT
Z574YJ/lLHBNf0zuGD0O54dwWStiBj0CIDtTvKZum/bUwvzvfEkaP9M9LonMANo4
4fmuDJ38Fgsy
-----END CERTIFICATE-----
`
)

// TestJavaKeystoreDeploysRenewedCertViaOutbox is the S5.13.2 AN-6 acceptance: a
// renewed credential is written into a Java keystore file through the outbox, and
// redelivery is idempotent (byte-identical).
func TestJavaKeystoreDeploysRenewedCertViaOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	ob := orchestrator.NewOutbox(s)

	const ksPath = "/etc/app/keystore.p12"
	ops := connector.NewMemoryOps() // the host filesystem, in memory
	reg := connector.NewRegistry(func(string) connector.Ops { return ops })
	reg.Register(javakeystore.New(ksPath, "changeit", "server"))

	payload, err := connector.EncodeDeploy("java-keystore", connector.NewDeployment("app", []byte(jksCertPEM), []byte(jksKeyPEM)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, e := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: tenantA, Destination: "connector.deploy", IdempotencyKey: "javakeystore-1", Payload: payload,
		})
		return e
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	handler := orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
		return reg.Handle(ctx, m.Payload)
	})
	if n, err := ob.Dispatch(ctx, handler); err != nil || n != 1 {
		t.Fatalf("Dispatch n=%d err=%v, want 1", n, err)
	}

	blob, ok := ops.File(ksPath)
	if !ok {
		t.Fatalf("keystore not written after outbox delivery")
	}
	_, gotCert, err := pfx.Decode(blob, "changeit")
	if err != nil {
		t.Fatalf("written keystore does not decode: %v", err)
	}
	wantDER, _ := pem.Decode([]byte(jksCertPEM))
	gotDER, _ := pem.Decode(gotCert)
	if !bytes.Equal(gotDER.Bytes, wantDER.Bytes) {
		t.Fatal("keystore does not contain the renewed certificate")
	}

	if err := reg.Handle(ctx, payload); err != nil {
		t.Fatalf("redeliver: %v", err)
	}
	blob2, _ := ops.File(ksPath)
	if !bytes.Equal(blob, blob2) {
		t.Error("redelivery changed the keystore bytes (not idempotent)")
	}
}
