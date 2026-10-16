// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession/orchestrator"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

func TestRecoveryWorkerRefusesMissingOrChangedPolicyBeforeSigner(t *testing.T) {
	ctx := context.Background()
	cs, err := corestore.Open(ctx, testDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cs.Close)
	cs.WithExtraMigrations(pcasstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	worker := orchestrator.NewBreadthWorker(cs, nil)
	const id = "spiffe://d/worker-policy-fence"
	root, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{
		"identity_id": id, "trust_root_der": root.Public().DER,
		"authorization": map[string]any{},
	}
	message := func() coreorch.Message {
		payload, marshalErr := json.Marshal(map[string]any{"request_id": "qa-worker-policy-fence", "request": request})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return coreorch.Message{TenantID: tenantA, Destination: orchestrator.RecoveryRequestDestination, Payload: payload}
	}
	if err := worker.Deliver(ctx, message()); err == nil || !strings.Contains(err.Error(), "recovery policy") {
		t.Fatalf("missing policy delivery = %v, want refusal before signer", err)
	}
	approver, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	roster, err := json.Marshal([]map[string]any{{"ID": "custodian-1", "PubDER": approver.Public().DER}})
	if err != nil {
		t.Fatal(err)
	}
	if err := pcasstore.New(cs).UpsertRecoveryPolicy(ctx, tenantA, pcasstore.RecoveryPolicy{
		IdentityID: id, Threshold: 1, RosterJSON: roster, TrustRootDER: root.Public().DER,
	}); err != nil {
		t.Fatal(err)
	}
	// The queued request still names root A; the operator changed the policy to
	// root B before delivery. The worker must reject the stale payload.
	if err := pcasstore.New(cs).UpsertRecoveryPolicy(ctx, tenantA, pcasstore.RecoveryPolicy{
		IdentityID: id, Threshold: 1, RosterJSON: roster, TrustRootDER: otherRoot.Public().DER,
	}); err != nil {
		t.Fatal(err)
	}
	if err := worker.Deliver(ctx, message()); err == nil || !strings.Contains(err.Error(), "trust root") {
		t.Fatalf("changed-root delivery = %v, want refusal before signer", err)
	}
}
