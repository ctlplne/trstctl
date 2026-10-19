// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A signer may append an issued-leaf event and then lose its reply. A failed
// claim must not make the host generate a second subject key on the next claim:
// that leaves the first signed certificate active with no serving workload.
func TestOrdinaryHostRenewalReclaimKeepsSealedCSRAndKey(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	state, err := relay.NewHostRollbackStore(stateDir, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
	intent := relay.DeployIntent{
		Connector: "nginx", Target: "host-a", TargetID: "target-a",
		IdentityID: "identity-a", SubjectCommonName: "host.example.test",
		SubjectDNSNames: []string{"host.example.test"},
		TargetConfig:    renewTargetConfig(t, certPath, keyPath),
	}
	ch := &renewChannel{signErr: errors.New("signed but reply was lost")}
	ch.jobs = []relay.Job{renewJob(t, intent)}
	profile := connector.LocalOpsConfig{AllowedRoots: []string{root}}
	if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(t.Context(), ch, http.DefaultClient, profile, nil, nil, state, 1, 60); err != nil {
		t.Fatal(err)
	}
	if len(ch.signed) != 1 || len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed {
		t.Fatalf("first ambiguous claim: signatures=%d reports=%+v", len(ch.signed), ch.reports)
	}
	first := bytes.Clone(ch.signed[0])
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(stateDir, entry.Name())) // #nosec G304 -- test-owned directory
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, first) || bytes.Contains(raw, []byte("PRIVATE KEY")) {
			t.Fatal("pending host key or CSR was stored in plaintext")
		}
	}
	// Simulate a process restart and the same durable job's next claim.
	state, err = relay.NewHostRollbackStore(stateDir, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	ch.jobs[0].Attempt = 2
	if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(context.Background(), ch, http.DefaultClient, profile, nil, nil, state, 1, 60); err != nil {
		t.Fatal(err)
	}
	if len(ch.signed) != 2 || !bytes.Equal(first, ch.signed[1]) {
		t.Fatal("reclaimed job generated a second CSR after ambiguous signing")
	}
}

func TestHostRenewPendingFirstWriterAndExactClear(t *testing.T) {
	root := t.TempDir()
	a, err := relay.NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := relay.NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	binding := strings.Repeat("a", 64)
	csr, key := []byte("public CSR"), []byte("host private key")
	if err := a.RecordHostRenewKey("apache", "target-a", 71, binding, csr, key); err != nil {
		t.Fatal(err)
	}
	if err := b.RecordHostRenewKey("apache", "target-a", 72, binding, csr, key); !errors.Is(err, relay.ErrHostRollbackStateMismatch) {
		t.Fatalf("different job replaced the first host key: %v", err)
	}
	if err := b.RecordHostRenewKey("apache", "target-a", 71, binding, csr, key); err != nil {
		t.Fatalf("exact retry was refused: %v", err)
	}
	if _, err := b.LoadHostRenewPending("apache", "target-a", 71, strings.Repeat("b", 64)); !errors.Is(err, relay.ErrHostRollbackStateMismatch) {
		t.Fatalf("changed reviewed job reached retained key: %v", err)
	}
	if err := a.RecordHostRenewCertificate("apache", "target-a", 71, binding, []byte("signed public leaf"), []byte("public chain"), strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if err := b.RecordHostRenewCertificate("apache", "target-a", 71, binding, []byte("different leaf"), nil, strings.Repeat("d", 64)); !errors.Is(err, relay.ErrHostRollbackStateMismatch) {
		t.Fatalf("second certificate replaced the first: %v", err)
	}
	pending, err := b.LoadHostRenewPending("apache", "target-a", 71, binding)
	if err != nil || pending == nil || !bytes.Equal(pending.CSRDER, csr) || !bytes.Equal(pending.KeyPEM, key) ||
		!bytes.Equal(pending.CertPEM, []byte("signed public leaf")) || pending.Fingerprint != strings.Repeat("c", 64) {
		t.Fatalf("restart changed exact pending material: pending=%v error=%v", pending != nil, err)
	}
	secret.Wipe(pending.CSRDER)
	secret.Wipe(pending.KeyPEM)
	secret.Wipe(pending.CertPEM)
	secret.Wipe(pending.ChainPEM)
	if err := b.ClearHostRenewPending("apache", "target-a", 71, binding, strings.Repeat("d", 64)); !errors.Is(err, relay.ErrHostRollbackStateMismatch) {
		t.Fatalf("wrong fingerprint cleared pending material: %v", err)
	}
	if err := b.ClearHostRenewPending("apache", "target-a", 71, binding, strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	pending, err = a.LoadHostRenewPending("apache", "target-a", 71, binding)
	if err != nil || pending != nil {
		t.Fatalf("accepted report left a retained pending key: present=%v error=%v", pending != nil, err)
	}
}

func TestReclaimedHostJobWithoutPendingKeyFailsBeforeSigning(t *testing.T) {
	root := t.TempDir()
	state, err := relay.NewHostRollbackStore(filepath.Join(root, "state"), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	ch := &renewChannel{signErr: errors.New("signing must not be reached")}
	job := renewJob(t, relay.DeployIntent{
		Connector: "nginx", Target: "host-a", TargetID: "target-a",
		IdentityID: "identity-a", SubjectCommonName: "host.example.test",
		TargetConfig: renewTargetConfig(t, filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")),
	})
	job.Attempt = 2
	ch.jobs = []relay.Job{job}
	if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(t.Context(), ch, http.DefaultClient,
		connector.LocalOpsConfig{AllowedRoots: []string{root}}, nil, nil, state, 1, 60); err != nil {
		t.Fatal(err)
	}
	if ch.signCalls != 0 || len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed {
		t.Fatalf("missing pending key generated or signed: calls=%d reports=%+v", ch.signCalls, ch.reports)
	}
}
