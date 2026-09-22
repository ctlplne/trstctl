// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/pqc"
)

func TestServedHostPQCRequestRejectsSubstitutionAndReplaysLostSignature(t *testing.T) {
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{agentJobKindEndpointRenew}, func(d *Deps) {
		d.LicensedCSRParser = pqc.ParsePureMLDSACSR
		d.LicensedCSRInspector = pqc.InspectHybridCSR
		d.LicensedLeafSigner = pqc.SignLicensedLeafFromCSRWithProfile
		d.PreparedSubjectLeafSigner = pqc.SignPQCLeafFromCSRWithPreparation
	})
	ctx := t.Context()
	seedRenewalJob(t, ctx, h, "host-pqc-retry", []string{"api.example.test"})
	// Set up the exact reviewed job before it is claimed. This fixture uses
	// the real claim, mTLS RPC, database and persistent signer transport.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		var payload []byte
		if err := tx.QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE`, h.tenant, "host-pqc-retry").Scan(&payload); err != nil {
			return err
		}
		var intent RelayDeployIntent
		if err := json.Unmarshal(payload, &intent); err != nil {
			return err
		}
		intent.SubjectKeyAlgorithm = string(pqc.MLDSA65)
		payload, err := json.Marshal(intent)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE outbox SET payload=$3 WHERE tenant_id=$1 AND idempotency_key=$2`, h.tenant, "host-pqc-retry", payload)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	job := claimOneRenewal(t, ctx, h)
	classical, err := crypto.GenerateHostSubjectKey("api.example.test", []string{"api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer classical.Destroy()
	if _, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: classical.CSRDER}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("reviewed PQC job accepted classical substitution: %v", err)
	}
	d := h.srv.obHandler.(*issuanceDispatcher)
	original := d.issue
	var issued [][]byte
	var issuedMu sync.Mutex
	snapshot := func() [][]byte {
		issuedMu.Lock()
		defer issuedMu.Unlock()
		return append([][]byte(nil), issued...)
	}
	d.issue = func(ctx context.Context, csr []byte, ttl time.Duration, profile crypto.LeafProfile) (crypto.IssuedLeaf, error) {
		leaf, err := original(ctx, csr, ttl, profile)
		if err != nil {
			return leaf, err
		}
		issuedMu.Lock()
		issued = append(issued, bytes.Clone(leaf.DER))
		lost := len(issued) == 1
		issuedMu.Unlock()
		if lost {
			return crypto.IssuedLeaf{}, errors.New("test lost result after signer completed")
		}
		return leaf, nil
	}
	tmpl := crypto.CertificateRequestTemplate{CommonName: "api.example.test", DNSNames: []string{"api.example.test"}}
	key, err := pqc.GenerateHostMLDSASubjectKey(tmpl, pqc.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	req := &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER}
	if _, err := h.client.SignJobCSR(ctx, req); err == nil {
		t.Fatal("injected lost result did not fail")
	}
	response, err := h.client.SignJobCSR(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	saved := snapshot()
	if len(saved) != 2 || !bytes.Equal(saved[0], saved[1]) {
		t.Fatal("host CSR retry minted a different certificate")
	}
	cert, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, response.Fingerprint)
	if err != nil || cert.KeyOrigin != "host_agent" || cert.KeyAlgorithm != string(pqc.MLDSA65) || !bytes.Equal(cert.CertificateDER, saved[0]) {
		t.Fatalf("host custody or exact certificate not recorded: %v", err)
	}
	other, err := pqc.GenerateHostMLDSASubjectKey(tmpl, pqc.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	if _, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: other.CSRDER}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("same claim signed another key: %v", err)
	}
	if len(snapshot()) != 2 {
		t.Fatal("refused request reached signer")
	}
}
