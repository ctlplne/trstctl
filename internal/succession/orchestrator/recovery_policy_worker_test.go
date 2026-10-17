// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	succapi "trstctl.com/trstctl/internal/succession/api"
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
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	svc := succapi.NewService(cs, log, nil)
	worker := orchestrator.NewBreadthWorker(cs, nil, nil)
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
		"epoch": 1, "successor_handle": succession.TenantKeyHandle(tenantA, id, 1),
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
	if _, err := svc.ConfigureRecoveryPolicy(ctx, tenantA, succapi.RecoveryPolicyRequest{
		IdentityID: id, Threshold: 1, Roster: roster, TrustRootDER: root.Public().DER,
	}); err != nil {
		t.Fatal(err)
	}
	// The queued request still names root A; the operator changed the policy to
	// root B before delivery. The worker must reject the stale payload.
	if _, err := svc.ConfigureRecoveryPolicy(ctx, tenantA, succapi.RecoveryPolicyRequest{
		IdentityID: id, Threshold: 1, Roster: roster, TrustRootDER: otherRoot.Public().DER,
	}); err != nil {
		t.Fatal(err)
	}
	if err := worker.Deliver(ctx, message()); err == nil || !strings.Contains(err.Error(), "trust root") {
		t.Fatalf("changed-root delivery = %v, want refusal before signer", err)
	}
}
