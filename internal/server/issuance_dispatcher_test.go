// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/gcpcm"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestIssuanceDispatcherRenewalMintsSuccessorAndSupersedesPredecessor(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()

	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "renewal-owner", "")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "renew.served.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}

	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "initial issue"); err != nil {
		t.Fatalf("transition to issued: %v", err)
	}
	dispatchOutbox(t, h, 1)

	certs := dispatcherCertificates(t, h)
	if len(certs) != 1 {
		t.Fatalf("after initial issue certificates = %d, want 1", len(certs))
	}
	old := certs[0]
	if old.Status != "active" {
		t.Fatalf("initial cert status = %q, want active", old.Status)
	}

	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateDeployed, "deployed"); err != nil {
		t.Fatalf("transition to deployed: %v", err)
	}
	dispatchOutbox(t, h, 1) // connector.deploy is explicitly acknowledged when no plugin owns it.

	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateRenewing, "operator renewal"); err != nil {
		t.Fatalf("transition to renewing: %v", err)
	}
	renew := pendingOutboxByDestination(t, h, "ca.renew")
	msg := orchestrator.Message{
		TenantID: h.tenant, Destination: renew.Destination,
		Payload: renew.Payload, IdempotencyKey: renew.IdempotencyKey,
	}

	dispatchOutbox(t, h, 1)
	if err := h.handler.Deliver(ctx, msg); err != nil {
		t.Fatalf("idempotent ca.renew redelivery: %v", err)
	}

	certs = dispatcherCertificates(t, h)
	if len(certs) != 2 {
		t.Fatalf("after renewal certificates = %d, want exactly 2 (predecessor + successor)", len(certs))
	}
	var gotOld, successor store.Certificate
	for _, c := range certs {
		if c.ID == old.ID {
			gotOld = c
		}
		if c.ReplacesID != nil && *c.ReplacesID == old.ID {
			successor = c
		}
	}
	if gotOld.ID == "" {
		t.Fatal("predecessor certificate disappeared from inventory")
	}
	if gotOld.Status != "superseded" || gotOld.RenewedAt == nil {
		t.Fatalf("predecessor status=%q renewed_at=%v, want superseded with renewal timestamp", gotOld.Status, gotOld.RenewedAt)
	}
	if successor.ID == "" {
		t.Fatal("renewal did not record a successor linked with replaces_id")
	}
	if successor.Status != "active" {
		t.Fatalf("successor status = %q, want active", successor.Status)
	}
	if successor.Serial == "" || successor.Serial == old.Serial {
		t.Fatalf("successor serial = %q, predecessor serial = %q; renewal must mint a distinct cert", successor.Serial, old.Serial)
	}
	if _, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), successor.Serial); err != nil {
		t.Fatalf("lookup successor issued-cert row: %v", err)
	} else if !found {
		t.Fatal("successor serial was not bridged into ca_issued_certs for OCSP/CRL")
	}
	state, err := h.orch.State(ctx, h.tenant, ident.ID)
	if err != nil {
		t.Fatalf("identity state: %v", err)
	}
	if state != orchestrator.StateDeployed {
		t.Fatalf("identity state after renewal = %q, want deployed", state)
	}
}

func TestIssuanceDispatcherRecoversRecordedCertificateBeforeRetryingSigner(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()

	baseIssue := h.handler.issue
	signCalls := 0
	h.handler.issue = func(ctx context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error) {
		signCalls++
		return baseIssue(ctx, csrDER, ttl, leafProfile)
	}

	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "correct-001-owner", "")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "correct-001.served.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "issue with crash gap"); err != nil {
		t.Fatalf("transition to issued: %v", err)
	}
	issue := pendingOutboxByDestination(t, h, "ca.issue")
	msg := orchestrator.Message{
		TenantID: h.tenant, Destination: issue.Destination,
		Payload: issue.Payload, IdempotencyKey: issue.IdempotencyKey,
	}

	injected := errors.New("crash after certificate.recorded before idempotency completion")
	failOnce := true
	h.handler.afterIssueSideEffects = func(context.Context) error {
		if !failOnce {
			return nil
		}
		failOnce = false
		return injected
	}
	if err := h.handler.Deliver(ctx, msg); !errors.Is(err, injected) {
		t.Fatalf("first delivery error = %v, want injected crash gap", err)
	}
	idemKey := "issue:" + msg.IdempotencyKey
	deleteCertificatesByIssuanceKey(t, h, idemKey)

	h.handler.afterIssueSideEffects = nil
	if err := h.handler.Deliver(ctx, msg); err != nil {
		t.Fatalf("retry delivery: %v", err)
	}
	if signCalls != 1 {
		t.Fatalf("signer calls = %d, want 1; retry must recover recorded certificate before signing", signCalls)
	}
	certs, err := h.store.ListCertificatesByIssuanceIdempotencyKey(ctx, h.tenant, idemKey)
	if err != nil {
		t.Fatalf("list recovered certificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("recovered certificates = %d, want 1", len(certs))
	}
	if certs[0].IssuanceIdempotencyKey != idemKey {
		t.Fatalf("issuance idempotency key = %q, want %q", certs[0].IssuanceIdempotencyKey, idemKey)
	}
	if len(certs[0].CertificateDER) == 0 {
		t.Fatal("recovered certificate has no DER; protocol retries could not return the original certificate")
	}
	if _, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), certs[0].Serial); err != nil {
		t.Fatalf("lookup recovered issued-cert row: %v", err)
	} else if !found {
		t.Fatal("recovered certificate serial was not projected into ca_issued_certs")
	}
}

func TestIssuanceDispatcherFailsUnsupportedFirstPartyDestination(t *testing.T) {
	d := &issuanceDispatcher{}
	for _, destination := range []string{"ca.rotate", "connector.unimplemented", "future.vendor.command"} {
		err := d.Deliver(context.Background(), orchestrator.Message{Destination: destination})
		if err == nil || !strings.Contains(err.Error(), "unsupported first-party outbox destination") {
			t.Fatalf("unsupported %s destination error = %v, want fail-closed error", destination, err)
		}
	}
	for _, destination := range []string{"notification.expiry", "transparency.rekor", "managedkey.command"} {
		if err := d.Deliver(context.Background(), orchestrator.Message{Destination: destination}); err == nil {
			t.Fatalf("missing handler for %s silently acknowledged the row", destination)
		}
	}
}

func TestIssuanceDispatcherMissingFirstPartyHandlersLeaveOutboxRowsPending(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()
	destinations := []string{"notification.expiry", "transparency.rekor", "managedkey.command"}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		for i, destination := range destinations {
			if _, err := h.outbox.Enqueue(ctx, tx, orchestrator.Entry{
				TenantID: h.tenant, Destination: destination,
				IdempotencyKey: fmt.Sprintf("missing-handler-%d", i), Payload: []byte(`{}`),
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("enqueue first-party rows: %v", err)
	}
	if n, err := h.outbox.Dispatch(ctx, h.handler); err != nil || n != len(destinations) {
		t.Fatalf("Dispatch = (%d, %v), want (%d, nil)", n, err, len(destinations))
	}
	pending, err := h.outbox.Pending(ctx, h.tenant)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	got := make(map[string]orchestrator.Record, len(pending))
	for _, row := range pending {
		got[row.Destination] = row
	}
	for _, destination := range destinations {
		row, ok := got[destination]
		if !ok {
			t.Errorf("%s row was acknowledged despite its missing handler", destination)
			continue
		}
		if row.Status != "pending" || row.Attempts != 1 || row.LastError == "" {
			t.Errorf("%s row = %+v, want pending attempt with visible error", destination, row)
		}
	}
}

type connectorReplayProbe struct {
	name   string
	calls  int
	deploy func(call int) error
}

func (p *connectorReplayProbe) Name() string { return p.name }

func (p *connectorReplayProbe) Capabilities() pluginhost.Grant { return pluginhost.NewGrant() }

func (p *connectorReplayProbe) Deploy(context.Context, connector.Sandbox, connector.Deployment) error {
	p.calls++
	if p.deploy != nil {
		return p.deploy(p.calls)
	}
	return nil
}

type connectorPluginProbe struct {
	owned  map[string]bool
	calls  int
	deploy func(call int) (bool, error)
}

type gcpcmAmbiguousReceiverOps struct {
	patches int
	applied bool
}

func (o *gcpcmAmbiguousReceiverOps) Send(string, []byte) error {
	return errors.New("unexpected raw send")
}

func (o *gcpcmAmbiguousReceiverOps) WriteFile(string, []byte) error {
	return errors.New("unexpected file write")
}

func (o *gcpcmAmbiguousReceiverOps) Exec(string, []string) error {
	return errors.New("unexpected process execution")
}

func (o *gcpcmAmbiguousReceiverOps) Request(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPatch {
		return nil, fmt.Errorf("unexpected GCP request %s %s", req.Method, req.URL)
	}
	o.patches++
	o.applied = true
	return nil, errors.New("receiver applied PATCH but response was lost")
}

func (p *connectorPluginProbe) Has(name string) bool { return p != nil && p.owned[name] }

func (p *connectorPluginProbe) Deploy(context.Context, string, connector.DeployPayload) (bool, error) {
	p.calls++
	if p.deploy != nil {
		return p.deploy(p.calls)
	}
	return true, nil
}

func connectorDeployTestMessage(t *testing.T, connectorName, key string) orchestrator.Message {
	t.Helper()
	payload, err := connector.EncodeDeploy(connectorName, connector.NewDeployment(
		"edge/test", []byte("test certificate"), []byte("test private key"),
	))
	if err != nil {
		t.Fatalf("EncodeDeploy: %v", err)
	}
	return orchestrator.Message{
		ID: 41, TenantID: "11111111-1111-1111-1111-111111111111",
		Destination: "connector.deploy", IdempotencyKey: key, Payload: payload, Attempts: 1,
	}
}

func TestConnectorReplaySafetyControlsAmbiguousFailureRetry(t *testing.T) {
	ambiguous := errors.New("receiver response was lost after mutation")
	t.Run("unsafe receiver is never replayed", func(t *testing.T) {
		probe := &connectorReplayProbe{name: "unsafe", deploy: func(int) error { return ambiguous }}
		registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewMemoryOps() })
		registry.Register(probe)
		d := &issuanceDispatcher{idem: orchestrator.NewMemoryIdempotency(), connectorRegistry: registry}
		message := connectorDeployTestMessage(t, probe.name, "unsafe-crash")

		if err := d.Deliver(context.Background(), message); !errors.Is(err, orchestrator.ErrEffectIndeterminate) {
			t.Fatalf("first ambiguous failure = %v, want ErrEffectIndeterminate", err)
		}
		if err := d.Deliver(context.Background(), message); !errors.Is(err, orchestrator.ErrEffectIndeterminate) {
			t.Fatalf("unsafe retry = %v, want ErrEffectIndeterminate", err)
		}
		if probe.calls != 1 {
			t.Fatalf("unsafe receiver calls = %d, want 1", probe.calls)
		}
	})

	t.Run("reconciled receiver may retry", func(t *testing.T) {
		probe := &connectorReplayProbe{name: "safe", deploy: func(call int) error {
			if call == 1 {
				return ambiguous
			}
			return nil
		}}
		registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewMemoryOps() })
		registry.RegisterWithReplaySafety(probe, connector.ReplaySafetyReconciled)
		d := &issuanceDispatcher{idem: orchestrator.NewMemoryIdempotency(), connectorRegistry: registry}
		message := connectorDeployTestMessage(t, probe.name, "safe-crash")

		if err := d.Deliver(context.Background(), message); !errors.Is(err, ambiguous) {
			t.Fatalf("first replay-safe failure = %v, want receiver error", err)
		}
		if err := d.Deliver(context.Background(), message); err != nil {
			t.Fatalf("replay-safe retry: %v", err)
		}
		if probe.calls != 2 {
			t.Fatalf("replay-safe receiver calls = %d, want 2", probe.calls)
		}
	})
}

func TestGCPConnectorAmbiguousAppliedPatchIsNeverBlindlyRetried(t *testing.T) {
	provider := gcpcm.StaticToken([]byte("gcp-replay-token"))
	if destroyer, ok := provider.(interface{ Destroy() }); ok {
		t.Cleanup(destroyer.Destroy)
	}
	conn := gcpcm.New("replay-project", "global", provider,
		gcpcm.WithEndpoint("https://gcp-replay.test"), gcpcm.WithPollInterval(0))
	if got := nativeConnectorReplaySafety(conn.Name()); got != connector.ReplaySafetyAtMostOnce {
		t.Fatalf("GCP replay safety = %v, want at-most-once", got)
	}

	receiver := &gcpcmAmbiguousReceiverOps{}
	registry := connector.NewRegistry(func(string) connector.Ops { return receiver })
	registry.RegisterWithReplaySafety(conn, nativeConnectorReplaySafety(conn.Name()))
	dispatcher := &issuanceDispatcher{idem: orchestrator.NewMemoryIdempotency(), connectorRegistry: registry}
	message := connectorDeployTestMessage(t, conn.Name(), "gcpcm-applied-crash")

	for attempt := 1; attempt <= 2; attempt++ {
		if err := dispatcher.Deliver(context.Background(), message); !errors.Is(err, orchestrator.ErrEffectIndeterminate) {
			t.Fatalf("attempt %d = %v, want ErrEffectIndeterminate", attempt, err)
		}
	}
	if !receiver.applied || receiver.patches != 1 {
		t.Fatalf("GCP ambiguous receiver applied=%v PATCHes=%d, want one applied mutation and no blind retry", receiver.applied, receiver.patches)
	}
}

func TestSignedConnectorPluginDefaultsToAtMostOnce(t *testing.T) {
	ambiguous := errors.New("signed plugin returned after an ambiguous receiver mutation")
	plugin := &connectorPluginProbe{
		owned:  map[string]bool{"third-party": true},
		deploy: func(int) (bool, error) { return true, ambiguous },
	}
	d := &issuanceDispatcher{idem: orchestrator.NewMemoryIdempotency(), plugins: plugin}
	message := connectorDeployTestMessage(t, "third-party", "plugin-crash")
	for attempt := 1; attempt <= 2; attempt++ {
		if err := d.Deliver(context.Background(), message); !errors.Is(err, orchestrator.ErrEffectIndeterminate) {
			t.Fatalf("attempt %d = %v, want ErrEffectIndeterminate", attempt, err)
		}
	}
	if plugin.calls != 1 {
		t.Fatalf("signed plugin calls = %d, want 1 without an enforced replay contract", plugin.calls)
	}
}

func TestConnectorDeployRoutingFailuresRemainPendingAndNeverRecordUnrouted(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()
	plugin := &connectorPluginProbe{
		owned:  map[string]bool{"declined": true},
		deploy: func(int) (bool, error) { return false, nil },
	}
	h.handler.plugins = plugin

	type deployCase struct {
		connector string
		key       string
		reason    string
	}
	cases := []deployCase{
		{connector: "", key: "missing-connector", reason: "missing_connector"},
		{connector: "not-loaded", key: "missing-plugin", reason: "plugin_not_loaded"},
		{connector: "declined", key: "declined-plugin", reason: "plugin_declined"},
	}
	ids := make(map[string]int64, len(cases))
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		for _, tc := range cases {
			message := connectorDeployTestMessage(t, tc.connector, tc.key)
			id, err := h.outbox.Enqueue(ctx, tx, orchestrator.Entry{
				TenantID: h.tenant, Destination: message.Destination,
				IdempotencyKey: tc.key, Payload: message.Payload,
			})
			if err != nil {
				return err
			}
			ids[tc.key] = id
		}
		return nil
	}); err != nil {
		t.Fatalf("enqueue connector routes: %v", err)
	}
	if n, err := h.outbox.Dispatch(ctx, h.handler); err != nil || n != len(cases) {
		t.Fatalf("Dispatch = (%d, %v), want (%d, nil)", n, err, len(cases))
	}
	pending, err := h.outbox.Pending(ctx, h.tenant)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != len(cases) {
		t.Fatalf("pending connector rows = %d, want %d: %+v", len(pending), len(cases), pending)
	}
	for _, tc := range cases {
		id := ids[tc.key]
		receiptID := evidenceID("connector-delivery", h.tenant, tc.key, id)
		receipt, err := h.store.GetConnectorDeliveryReceipt(ctx, h.tenant, receiptID)
		if err != nil {
			t.Fatalf("GetConnectorDeliveryReceipt(%s): %v", tc.key, err)
		}
		if receipt.Status != "failed" || receipt.Reason != tc.reason {
			t.Errorf("%s receipt = %+v, want failed/%s", tc.key, receipt, tc.reason)
		}
		if receipt.Status == "unrouted" || receipt.Reason == "unrouted" {
			t.Errorf("%s was recorded as an acknowledged unrouted deployment: %+v", tc.key, receipt)
		}
	}
}

func TestConnectorFailureReceiptRedactsCredentialEchoFromReceiverError(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()
	const sentinel = "DO-NOT-PERSIST-PRIVATE-KEY-SENTINEL"
	probe := &connectorReplayProbe{name: "hostile", deploy: func(int) error {
		return fmt.Errorf("upstream echoed credential %s", sentinel)
	}}
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewMemoryOps() })
	registry.Register(probe)
	h.handler.connectorRegistry = registry
	privateKey := []byte("-----BEGIN PRIVATE KEY-----\n" + sentinel + "\n-----END PRIVATE KEY-----")
	payload, err := connector.EncodeDeploy(probe.name, connector.NewDeployment("hostile-target", []byte("hostile-cert"), privateKey))
	if err != nil {
		t.Fatal(err)
	}
	var outboxID int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		outboxID, err = h.outbox.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: h.tenant, Destination: "connector.deploy",
			IdempotencyKey: "hostile-error", Payload: payload,
		})
		return err
	}); err != nil {
		t.Fatalf("enqueue hostile connector: %v", err)
	}
	if n, err := h.outbox.Dispatch(ctx, h.handler); err != nil || n != 1 {
		t.Fatalf("Dispatch = (%d, %v), want (1, nil)", n, err)
	}
	receiptID := evidenceID("connector-delivery", h.tenant, "hostile-error", outboxID)
	receipt, err := h.store.GetConnectorDeliveryReceipt(ctx, h.tenant, receiptID)
	if err != nil {
		t.Fatalf("GetConnectorDeliveryReceipt: %v", err)
	}
	if receipt.Status != "failed" || receipt.Reason != "native_delivery_failed" ||
		strings.Contains(receipt.Reason, sentinel) || strings.Contains(receipt.Detail, sentinel) {
		t.Fatalf("hostile error leaked into receipt: %+v", receipt)
	}
	found := false
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.Type != projections.EventConnectorDeliveryRecorded || !bytes.Contains(event.Data, []byte(receiptID)) {
			return nil
		}
		found = true
		if bytes.Contains(event.Data, []byte(sentinel)) || bytes.Contains(event.Data, privateKey) {
			t.Fatalf("credential echo leaked into connector delivery event: %s", event.Data)
		}
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if !found {
		t.Fatal("connector failure did not emit its delivery receipt event")
	}
}

func TestAtMostOnceConnectorRecoversCrashAfterCommittedDeliveryReceipt(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()
	probe := &connectorReplayProbe{name: "unsafe-success"}
	registry := connector.NewRegistry(func(string) connector.Ops { return connector.NewMemoryOps() })
	registry.Register(probe)
	h.handler.connectorRegistry = registry
	h.handler.afterDeploySideEffects = func(context.Context) error {
		return errors.New("crash after connector receipt commit")
	}
	outbox := orchestrator.NewOutbox(h.store,
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
		orchestrator.WithRetryJitter(func(time.Duration) time.Duration { return 0 }),
	)
	message := connectorDeployTestMessage(t, probe.name, "receipt-recovery")
	var outboxID int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		var err error
		outboxID, err = outbox.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: h.tenant, Destination: message.Destination,
			IdempotencyKey: message.IdempotencyKey, Payload: message.Payload,
		})
		return err
	}); err != nil {
		t.Fatalf("enqueue connector: %v", err)
	}
	if n, err := outbox.Dispatch(ctx, h.handler); err != nil || n != 1 {
		t.Fatalf("first Dispatch = (%d, %v), want (1, nil)", n, err)
	}
	if probe.calls != 1 {
		t.Fatalf("receiver calls after crash = %d, want 1", probe.calls)
	}
	receiptID := evidenceID("connector-delivery", h.tenant, message.IdempotencyKey, outboxID)
	if receipt, err := h.store.GetConnectorDeliveryReceipt(ctx, h.tenant, receiptID); err != nil {
		t.Fatalf("delivery receipt did not commit before crash: %v", err)
	} else if receipt.Status != "delivered" {
		t.Fatalf("delivery receipt status = %q, want delivered", receipt.Status)
	}
	if n, err := outbox.Dispatch(ctx, h.handler); err != nil || n != 1 {
		t.Fatalf("recovery Dispatch = (%d, %v), want (1, nil)", n, err)
	}
	if probe.calls != 1 {
		t.Fatalf("receipt recovery repeated unsafe receiver: calls=%d", probe.calls)
	}
	if pending, err := outbox.Pending(ctx, h.tenant); err != nil {
		t.Fatalf("Pending: %v", err)
	} else if len(pending) != 0 {
		t.Fatalf("reconciled connector row remained pending: %+v", pending)
	}
}

func TestIssuanceDispatcherServedProfileControlsLeafEKUs(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()
	storeServerTestProfile(t, h.store, h.tenant, "tls-server", profile.CertificateProfile{
		Name: "tls-server", AllowedEKUs: []string{"serverAuth"}, MaxValidity: profile.Duration(365 * 24 * time.Hour), AllowedProtocols: []string{"api"},
	})

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "API EKU CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	var issuedEKUs []string
	h.handler.defaultProfile = "tls-server"
	h.handler.issue = func(_ context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error) {
		leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, ttl, leafProfile)
		if err != nil {
			return nil, err
		}
		info, err := certinfo.Inspect(leafDER)
		if err != nil {
			return nil, err
		}
		issuedEKUs = info.ExtKeyUsages
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), nil
	}

	if _, err := h.handler.mintServedLeaf(ctx, h.tenant, "owner-1", "api.eku.test", []string{"api.eku.test"}); err != nil {
		t.Fatalf("mint served leaf: %v", err)
	}
	if !sameStrings(issuedEKUs, []string{"serverAuth"}) {
		t.Fatalf("issued EKUs = %v, want exactly [serverAuth]", issuedEKUs)
	}
}

func TestIssuanceDispatcherRejectsExcludedCSRRequestedEKUBeforeSigning(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()
	storeServerTestProfile(t, h.store, h.tenant, "tls-server", profile.CertificateProfile{
		Name: "tls-server", AllowedEKUs: []string{"serverAuth"}, MaxValidity: profile.Duration(24 * time.Hour), AllowedProtocols: []string{"api"},
	})

	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "client-only.eku.test", DNSNames: []string{"client-only.eku.test"}, RequestedEKUs: []string{"clientAuth"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	h.handler.defaultProfile = "tls-server"
	h.handler.issue = func(context.Context, []byte, time.Duration, crypto.LeafProfile) ([]byte, error) {
		t.Fatal("signing must not be reached for an excluded EKU")
		return nil, nil
	}

	_, err = h.handler.enforceProfile(ctx, h.tenant, csrDER, []string{"client-only.eku.test"}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), `extended key usage "clientAuth"`) {
		t.Fatalf("enforceProfile error = %v, want excluded clientAuth before signing", err)
	}
}

func TestServedProfileRejectsIPSANBeforeSigning(t *testing.T) {
	prof := profile.CertificateProfile{
		Name:               "dns-only",
		AllowedEKUs:        []string{"serverAuth"},
		MaxValidity:        profile.Duration(24 * time.Hour),
		AllowedProtocols:   []string{"api"},
		AllowedDNSSuffixes: []string{"served.test"},
	}

	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName:  "api.served.test",
		DNSNames:    []string{"api.served.test"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.10")},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	info, err := crypto.InspectCSR(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	requestedEKUs := intendedProfileEKUs(info.RequestedEKUs, prof.AllowedEKUs)
	preq := profile.Request{
		KeyAlgorithm:   info.KeyAlgorithm,
		KeyBits:        info.KeyBits,
		RequestedEKUs:  requestedEKUs,
		TTL:            time.Hour,
		DNSNames:       profileDNSNames(info, []string{"api.served.test"}),
		IPAddresses:    info.IPAddresses,
		EmailAddresses: info.EmailAddresses,
		URIs:           info.URIs,
		Protocol:       "api",
	}
	if err := prof.Validate(preq); err == nil || !strings.Contains(err.Error(), "IP SAN") {
		t.Fatalf("served profile request error = %v, want DNS-only profile to reject IP SAN", err)
	}

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Served SAN Test CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafProfile := leafProfileForCertificateProfile(crypto.LeafProfile{}, prof, requestedEKUs)
	_, err = crypto.SignLeafFromCSRWithProfile(caDER, failOnSignSigner{t: t, inner: caKey}, csrDER, time.Hour, leafProfile)
	if err == nil || !crypto.IsLeafProfileViolation(err) || !strings.Contains(err.Error(), "IP SAN") {
		t.Fatalf("SignLeafFromCSRWithProfile error = %v, want IP SAN profile rejection before signing", err)
	}
}

type failOnSignSigner struct {
	t     *testing.T
	inner crypto.DigestSigner
}

func (s failOnSignSigner) Public() crypto.PublicKey    { return s.inner.Public() }
func (s failOnSignSigner) Algorithm() crypto.Algorithm { return s.inner.Algorithm() }
func (s failOnSignSigner) SignDigest([]byte, crypto.SignOptions) ([]byte, error) {
	s.t.Fatal("signing must not be reached for an IP SAN outside the DNS-only profile")
	return nil, errors.New("signing reached")
}

func TestServedProfileBindsSANPoliciesToLeafProfile(t *testing.T) {
	leaf := leafProfileForCertificateProfile(crypto.LeafProfile{}, profile.CertificateProfile{
		Name:                "san-policy",
		AllowedDNSSuffixes:  []string{"served.test"},
		AllowedIPCIDRs:      []string{"10.0.0.0/24"},
		AllowedEmailDomains: []string{"served.test"},
		AllowedURIPrefixes:  []string{"spiffe://served.test/ns/prod/"},
	}, []string{"serverAuth"})

	if !sameStrings(leaf.PermittedDNSSuffixes, []string{"served.test"}) {
		t.Fatalf("PermittedDNSSuffixes = %v", leaf.PermittedDNSSuffixes)
	}
	if !sameStrings(leaf.PermittedIPCIDRs, []string{"10.0.0.0/24"}) {
		t.Fatalf("PermittedIPCIDRs = %v", leaf.PermittedIPCIDRs)
	}
	if !sameStrings(leaf.PermittedEmailDomains, []string{"served.test"}) {
		t.Fatalf("PermittedEmailDomains = %v", leaf.PermittedEmailDomains)
	}
	if !sameStrings(leaf.PermittedURIPrefixes, []string{"spiffe://served.test/ns/prod/"}) {
		t.Fatalf("PermittedURIPrefixes = %v", leaf.PermittedURIPrefixes)
	}
}

func TestProtocolIssuerServedProfileControlsAndRejectsLeafEKUs(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()
	storeServerTestProfile(t, h.store, h.tenant, "tls-server", profile.CertificateProfile{
		Name: "tls-server", AllowedEKUs: []string{"serverAuth"}, MaxValidity: profile.Duration(24 * time.Hour), AllowedProtocols: []string{"acme"},
	})

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Protocol EKU CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var issuedEKUs []string
	called := 0
	issuer := &protocolIssuer{
		issue: func(_ context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error) {
			called++
			leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, ttl, leafProfile)
			if err != nil {
				return nil, err
			}
			info, err := certinfo.Inspect(leafDER)
			if err != nil {
				return nil, err
			}
			issuedEKUs = info.ExtKeyUsages
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), nil
		},
		orch: h.orch, idem: orchestrator.NewIdempotency(h.store), store: h.store, log: h.log, caID: IssuingCAID(), defaultProfile: "tls-server",
	}

	serverCSR := serverTestCSR(t, "proto.eku.test", nil)
	if _, err := issuer.IssueProtocolLeaf(ctx, h.tenant, "acme", "eku-positive", serverCSR, time.Hour); err != nil {
		t.Fatalf("protocol issue: %v", err)
	}
	if called != 1 {
		t.Fatalf("signing calls = %d, want 1", called)
	}
	if !sameStrings(issuedEKUs, []string{"serverAuth"}) {
		t.Fatalf("protocol issued EKUs = %v, want exactly [serverAuth]", issuedEKUs)
	}

	for _, protocolName := range []string{"acme", "est", "scep", "cmp", "ssh", "spiffe"} {
		t.Run("deny before signing/"+protocolName, func(t *testing.T) {
			profileName := "tls-server-" + protocolName
			storeServerTestProfile(t, h.store, h.tenant, profileName, profile.CertificateProfile{
				Name: profileName, AllowedEKUs: []string{"serverAuth"}, MaxValidity: profile.Duration(24 * time.Hour), AllowedProtocols: []string{protocolName},
			})
			issuer.defaultProfile = profileName
			before := called
			clientCSR := serverTestCSR(t, "client-only."+protocolName+".proto.test", []string{"clientAuth"})
			if _, err := issuer.IssueProtocolLeaf(ctx, h.tenant, protocolName, "eku-negative-"+protocolName, clientCSR, time.Hour); err == nil || !strings.Contains(err.Error(), `extended key usage "clientAuth"`) {
				t.Fatalf("protocol %s excluded EKU error = %v, want clientAuth profile rejection", protocolName, err)
			}
			if called != before {
				t.Fatalf("protocol %s reached signing after rejected CSR: calls %d -> %d", protocolName, before, called)
			}
		})
	}
}

func TestProtocolIssuerRecoversRecordedDERBeforeRetryingSigner(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := context.Background()

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Protocol Crash Gap CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	var firstDER []byte
	signCalls := 0
	issuer := &protocolIssuer{
		issue: func(_ context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error) {
			signCalls++
			leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, ttl, leafProfile)
			if err != nil {
				return nil, err
			}
			if firstDER == nil {
				firstDER = append([]byte(nil), leafDER...)
			}
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), nil
		},
		orch: h.orch, idem: orchestrator.NewIdempotency(h.store), store: h.store, log: h.log, caID: IssuingCAID(),
	}

	injected := errors.New("crash after protocol certificate.recorded before idempotency completion")
	failOnce := true
	issuer.afterIssueSideEffects = func(context.Context) error {
		if !failOnce {
			return nil
		}
		failOnce = false
		return injected
	}

	csrDER := serverTestCSR(t, "correct-001.protocol.test", nil)
	if _, err := issuer.IssueProtocolLeaf(ctx, h.tenant, "acme", "correct-001-protocol", csrDER, time.Hour); !errors.Is(err, injected) {
		t.Fatalf("first protocol issue error = %v, want injected crash gap", err)
	}
	idemKey := "protocol-issue:correct-001-protocol"
	deleteCertificatesByIssuanceKey(t, h, idemKey)

	issuer.afterIssueSideEffects = nil
	raw, err := issuer.IssueProtocolLeaf(ctx, h.tenant, "acme", "correct-001-protocol", csrDER, time.Hour)
	if err != nil {
		t.Fatalf("retry protocol issue: %v", err)
	}
	if signCalls != 1 {
		t.Fatalf("protocol signer calls = %d, want 1; retry must not mint another leaf", signCalls)
	}
	if !bytes.Equal(raw, firstDER) {
		t.Fatal("protocol retry did not return the DER from the first recorded certificate")
	}
}

type issuanceDispatcherHarness struct {
	store   *store.Store
	log     *events.Log
	outbox  *orchestrator.Outbox
	orch    *orchestrator.Orchestrator
	handler *issuanceDispatcher
	tenant  string
}

func newIssuanceDispatcherHarness(t *testing.T) *issuanceDispatcherHarness {
	t.Helper()
	if testing.Short() {
		t.Skip("starts embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Test Issuance Dispatcher CA", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("self-signed CA: %v", err)
	}

	outbox := orchestrator.NewOutbox(st)
	idem := orchestrator.NewIdempotency(st)
	orch := orchestrator.NewOrchestrator(log, st, outbox)
	handler := &issuanceDispatcher{
		issue: func(_ context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error) {
			leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, ttl, leafProfile)
			if err != nil {
				return nil, err
			}
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), nil
		},
		orch: orch, idem: idem, store: st, log: log,
	}
	h := &issuanceDispatcherHarness{
		store: st, log: log, outbox: outbox, orch: orch, handler: handler,
		tenant: "11111111-1111-1111-1111-111111111111",
	}
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: h.tenant, Name: "dispatcher-renewal"}); err != nil {
		t.Fatalf("upsert tenant: %v", err)
	}
	return h
}

func storeServerTestProfile(t *testing.T, s *store.Store, tenant, name string, p profile.CertificateProfile) {
	t.Helper()
	spec, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProfileVersion(context.Background(), store.ProfileRecord{
		TenantID: tenant, Name: name, Spec: spec, CreatedBy: "test",
	}); err != nil {
		t.Fatalf("CreateProfileVersion: %v", err)
	}
}

func serverTestCSR(t *testing.T, cn string, requestedEKUs []string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: cn, DNSNames: []string{cn}, RequestedEKUs: requestedEKUs,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csrDER
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func dispatchOutbox(t *testing.T, h *issuanceDispatcherHarness, want int) {
	t.Helper()
	n, err := h.outbox.Dispatch(context.Background(), h.handler)
	if err != nil {
		t.Fatalf("dispatch outbox: %v", err)
	}
	if n != want {
		t.Fatalf("dispatched %d outbox rows, want %d", n, want)
	}
}

func pendingOutboxByDestination(t *testing.T, h *issuanceDispatcherHarness, dest string) orchestrator.Record {
	t.Helper()
	pending, err := h.outbox.Pending(context.Background(), h.tenant)
	if err != nil {
		t.Fatalf("pending outbox: %v", err)
	}
	for _, r := range pending {
		if r.Destination == dest {
			return r
		}
	}
	t.Fatalf("no pending %s outbox row in %+v", dest, pending)
	return orchestrator.Record{}
}

func dispatcherCertificates(t *testing.T, h *issuanceDispatcherHarness) []store.Certificate {
	t.Helper()
	certs, err := h.store.ListCertificatesPage(context.Background(), h.tenant, store.ZeroUUID, nil, 100, nil)
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	return certs
}

func deleteCertificatesByIssuanceKey(t *testing.T, h *issuanceDispatcherHarness, key string) {
	t.Helper()
	if _, err := h.store.SystemPool().Exec(context.Background(),
		`DELETE FROM certificates WHERE tenant_id = $1 AND issuance_idempotency_key = $2`,
		h.tenant, key); err != nil {
		t.Fatalf("delete certificate read-model row for %s: %v", key, err)
	}
	if _, err := h.store.SystemPool().Exec(context.Background(),
		`DELETE FROM ca_issued_certs WHERE tenant_id = $1`, h.tenant); err != nil {
		t.Fatalf("delete issued-cert read-model rows for %s: %v", key, err)
	}
}
