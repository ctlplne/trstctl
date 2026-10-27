// SPDX-License-Identifier: BUSL-1.1

package delegation_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/signing"
)

const (
	issuingCATenantA = "18100000-0000-4000-8000-00000000000a"
	issuingCATenantB = "18100000-0000-4000-8000-00000000000b"
)

// TestTenantIssuingCAOverUDS publishes each tenant's agent issuing CA over the
// signer transport: tenants get different CA keys, a tenant's key survives a
// signer restart through the sealed key store, and a request without a tenant
// is refused.
func TestTenantIssuingCAOverUDS(t *testing.T) {
	keystore := t.TempDir()
	kek, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x5c}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kek.Destroy)

	boot := func(t *testing.T) (*signing.Client, func()) {
		t.Helper()
		op := delegation.NewSignerIssuanceKeyOp(delegation.SignerConfig{SignerID: "trstctl-signer"})
		srv, err := signing.NewPersistentServer(signing.NewKeyStore(keystore, kek), signing.WithIssuanceKeyOp(op))
		if err != nil {
			t.Fatalf("NewPersistentServer: %v", err)
		}
		dir, err := os.MkdirTemp("", "agidca")
		if err != nil {
			t.Fatal(err)
		}
		socket := filepath.Join(dir, "s.sock")
		ctx, cancel := context.WithCancel(context.Background())
		served := make(chan error, 1)
		go func() {
			served <- signing.ServeServerWithOptions(ctx, socket, srv, signing.ServeOptions{
				AllowInsecureDevNonLinux: runtime.GOOS != "linux",
			})
		}()
		client, err := signing.DialReady(ctx, socket, 10*time.Second)
		if err != nil {
			cancel()
			t.Fatalf("DialReady: %v", err)
		}
		return client, func() {
			_ = client.Close()
			cancel()
			<-served
			_ = os.RemoveAll(dir)
		}
	}

	ctx := context.Background()
	client, stop := boot(t)
	firstA, err := client.AgentIssuingCA(ctx, issuingCATenantA)
	if err != nil {
		stop()
		t.Fatalf("AgentIssuingCA tenant A: %v", err)
	}
	againA, err := client.AgentIssuingCA(ctx, issuingCATenantA)
	if err != nil || !bytes.Equal(againA, firstA) {
		stop()
		t.Fatalf("a second read of tenant A's CA differs: %v", err)
	}
	firstB, err := client.AgentIssuingCA(ctx, issuingCATenantB)
	if err != nil {
		stop()
		t.Fatalf("AgentIssuingCA tenant B: %v", err)
	}
	if bytes.Equal(spkiOf(t, firstA), spkiOf(t, firstB)) {
		stop()
		t.Fatal("two tenants share one agent issuing CA key")
	}
	facts, err := crypto.CertificateFactsFromDER(firstA)
	if err != nil || !strings.Contains(facts.SubjectDN, issuingCATenantA) {
		stop()
		t.Fatalf("tenant A's CA subject = %q, %v", facts.SubjectDN, err)
	}
	_, err = client.AgentIssuingCA(ctx, "")
	if status.Code(err) != codes.InvalidArgument {
		stop()
		t.Fatalf("a request without a tenant: %v", err)
	}
	stop()

	client, stop = boot(t)
	defer stop()
	restartedA, err := client.AgentIssuingCA(ctx, issuingCATenantA)
	if err != nil {
		t.Fatalf("AgentIssuingCA after restart: %v", err)
	}
	if !bytes.Equal(spkiOf(t, restartedA), spkiOf(t, firstA)) {
		t.Fatal("tenant A's issuing CA key changed across a signer restart")
	}
}

// TestTenantIssuingCARenewsOverSameKey re-issues a tenant's CA certificate over
// the same key once it nears expiry, and not before.
func TestTenantIssuingCARenewsOverSameKey(t *testing.T) {
	now := time.Now()
	op := delegation.NewIssuanceKeyOp(delegation.IssuanceKeyOpConfig{Clock: func() time.Time { return now }})
	_ = signing.NewServer(signing.WithIssuanceKeyOp(op))

	first, err := op.IssuingCACertificate(issuingCATenantA)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * 24 * time.Hour)
	if same, err := op.IssuingCACertificate(issuingCATenantA); err != nil || !bytes.Equal(same, first) {
		t.Fatalf("the CA certificate was re-issued 60 days before expiry: %v", err)
	}
	now = now.Add(31 * 24 * time.Hour)
	renewed, err := op.IssuingCACertificate(issuingCATenantA)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(renewed, first) {
		t.Fatal("the CA certificate was not re-issued 29 days before expiry")
	}
	if !bytes.Equal(spkiOf(t, renewed), spkiOf(t, first)) {
		t.Fatal("re-issuing the CA certificate changed its key")
	}
	if _, err := op.IssuingCACertificate(""); err == nil {
		t.Fatal("a tenantless issuing CA was bootstrapped")
	}
}

func spkiOf(t *testing.T, certDER []byte) []byte {
	t.Helper()
	spki, err := crypto.CertificateSubjectPublicKeyInfo(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return spki
}
