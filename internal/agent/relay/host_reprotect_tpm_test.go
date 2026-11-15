// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
)

// TestTPMHeldCAReprotectionIsRefusedBeforeAnyTPMWorkTPMO1L1: a CA
// re-protection of a TPM-held host key runs through this host's TPM, so it is
// refused, before the predecessor is pinned or any CSR is made, when this host
// cannot do that: its profile names no host_key_tpm, the connector converts
// the key, the key is not ECDSA P-256, or the agent's channel cannot send the
// TPM's attestation. A key custody no agent provides is refused the same way.
func TestTPMHeldCAReprotectionIsRefusedBeforeAnyTPMWorkTPMO1L1(t *testing.T) {
	dev := &softwareHostKeyTPM{}
	restore := relay.SetHostKeyTPMForTest(dev, func(int64, []byte, []byte) ([]byte, error) {
		t.Error("an attestation was asked for")
		return nil, errors.New("unexpected")
	})
	defer restore()
	for _, tc := range []struct {
		name     string
		withTPM  bool
		plain    bool
		mutate   func(*relay.DeployIntent)
		wantText string
	}{
		{"no TPM in the host profile", false, false, nil, "names no host_key_tpm"},
		{"a connector that converts the key", true, false, func(i *relay.DeployIntent) { i.Connector = "apache" }, "installed only for nginx"},
		{"a key the TPM cannot hold", true, false, func(i *relay.DeployIntent) { i.SubjectKeyAlgorithm = "RSA-2048" }, "ECDSA P-256"},
		{"a channel that cannot send an attestation", true, true, nil, "cannot send a TPM key attestation"},
		{"a custody no agent provides", true, false, func(i *relay.DeployIntent) { i.KeyCustody = "hsm" }, "which this agent does not provide"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			intent := tpmRenewIntent(t, dir, "nginx")
			intent.VerifyAddress, intent.VerifyServerName = "127.0.0.1:1", "web.example.test"
			intent.IdentityID, intent.PredecessorCertificateID = "identity-tpm-o1-l1", "certificate-tpm-o1-l1"
			intent.IssuingAuthoritySource, intent.IssuingAuthorityID = "private", "ca-tpm-o1-l1-successor"
			intent.ReprotectJobID, intent.ReprotectTTLSeconds = "vdec-tpm-o1-l1", 3600
			intent.ReprotectPredecessorFingerprint = "sha256:" + strings.Repeat("ab", 32)
			intent.ReprotectPredecessorSPKISHA256 = strings.Repeat("cd", 32)
			if tc.mutate != nil {
				tc.mutate(&intent)
			}
			var ch relay.Channel
			var signCalls func() int
			var reports func() []report
			if tc.plain {
				plain := &renewChannel{certPEM: []byte("ISSUED-LEAF\n"), fpr: "sha256:issued"}
				plain.jobs = []relay.Job{renewJob(t, intent)}
				ch, signCalls, reports = plain, func() int { return plain.signCalls }, func() []report { return plain.reports }
			} else {
				attested := &attestedRenewChannel{renewChannel: renewChannel{certPEM: []byte("ISSUED-LEAF\n"), fpr: "sha256:issued"}}
				attested.jobs = []relay.Job{renewJob(t, intent)}
				ch, signCalls, reports = attested, func() int { return attested.signCalls }, func() []report { return attested.reports }
			}
			rollback, err := relay.NewHostRollbackStore(filepath.Join(t.TempDir(), "ledger"), "tenant-tpm-o1-l1")
			if err != nil {
				t.Fatal(err)
			}
			before := dev.created
			if _, err := relay.RunOnceWithSelfUpgradeAndHostRollback(context.Background(), ch, http.DefaultClient,
				tpmRenewProfile(t, dir, tc.withTPM), nil, nil, rollback, 4, 60); err != nil {
				t.Fatalf("RunOnceWithSelfUpgradeAndHostRollback: %v", err)
			}
			got := reports()
			if len(got) != 1 || got[0].outcome != relay.OutcomeFailed || !strings.Contains(got[0].detail, tc.wantText) {
				t.Fatalf("reports = %+v, want a failure naming %q", got, tc.wantText)
			}
			if dev.created != before || signCalls() != 0 {
				t.Fatalf("the TPM made %d keys and %d CSRs were signed before the refusal", dev.created-before, signCalls())
			}
		})
	}
}
