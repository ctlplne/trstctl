// SPDX-License-Identifier: BUSL-1.1

package acme_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"trstctl.com/trstctl/internal/crypto/acmekey"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// A50/A53/A54 at the protocol layer: a policy update narrows a configured
// credential at runtime, a rotation registers a successor whose MAC key is
// read through the secret resolver, both are recorded in the state log and
// survive a restart through replay, and a restart that cannot resolve the
// successor's reference leaves it registered but unavailable (fail closed,
// mount still starts) rather than silently dropping or widening it.
func TestEABPolicyUpdateAndRotationSurviveRestart(t *testing.T) {
	ctx := context.Background()
	log := openACMEStateLog(t)
	const tenant = "eab-rotation"
	configuredKey := bytes.Repeat([]byte{0x61}, 32)
	successorKey := bytes.Repeat([]byte{0x62}, 32)
	const successorRef = "secret://acme/eab/payments-2" // #nosec G101 -- fabricated fixture reference, not secret material (CWE-798)
	secrets := map[string][]byte{successorRef: successorKey}
	resolver := func(_ context.Context, ref string) ([]byte, error) {
		if v, ok := secrets[ref]; ok {
			return append([]byte(nil), v...), nil
		}
		return nil, errors.New("no such secret")
	}
	build := func(resolve func(context.Context, string) ([]byte, error)) *acmesrv.Server {
		t.Helper()
		srv := acmesrv.New(mustBuiltin(t), acmesrv.AcceptAll{})
		if resolve != nil {
			srv = srv.WithEABSecretResolver(resolve)
		}
		srv, err := srv.WithExternalAccountBindings(true, []acmesrv.ExternalAccountBindingKey{{
			KeyID: "payments", HMACKey: configuredKey,
			Policy: acmesrv.EABPolicy{AllowedIdentifiers: []string{"*.example.test"}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		srv, err = srv.WithStateLog(ctx, tenant, log)
		if err != nil {
			t.Fatal(err)
		}
		return srv
	}
	srv := build(resolver)
	var handler atomic.Pointer[acmesrv.Server]
	handler.Store(srv)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.Load().ServeHTTP(w, r) }))
	t.Cleanup(ts.Close)
	register := func(kid string, key []byte) (*xacme.Client, error) {
		client, err := acmekey.NewClient(ts.URL + "/directory")
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Register(ctx, &xacme.Account{ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: kid, Key: key}}, xacme.AcceptTOS)
		return client, err
	}

	// A53: the policy update narrows the scope and adds a quota at runtime.
	status, ok, err := srv.UpdateEABPolicy(ctx, "payments", acmesrv.EABPolicyUpdate{
		AllowedIdentifiers: []string{"*.payments.example.test"}, MaxOrders: 2, NotAfter: time.Now().Add(time.Hour),
	})
	if err != nil || !ok {
		t.Fatalf("update policy: ok=%v err=%v", ok, err)
	}
	if len(status.AllowedIdentifiers) != 1 || status.MaxOrders != 2 || status.NotAfter == nil {
		t.Fatalf("policy update did not land: %+v", status)
	}
	if _, ok, err := srv.UpdateEABPolicy(ctx, "nobody", acmesrv.EABPolicyUpdate{}); ok || err != nil {
		t.Fatalf("unknown credential: ok=%v err=%v, want not found and no error", ok, err)
	}
	payments, err := register("payments", configuredKey)
	if err != nil {
		t.Fatalf("register under the configured credential: %v", err)
	}
	if _, err := payments.AuthorizeOrder(ctx, xacme.DomainIDs("api.billing.example.test")); err == nil || !strings.Contains(err.Error(), "billing.example.test") {
		t.Fatalf("an identifier outside the narrowed scope = %v, want a refusal naming it", err)
	}
	if _, err := payments.AuthorizeOrder(ctx, xacme.DomainIDs("api.payments.example.test")); err != nil {
		t.Fatalf("an identifier inside the narrowed scope: %v", err)
	}

	// A50/A54: rotation registers the successor from its reference, with the
	// predecessor's (updated) policy; the response names the reference and
	// nothing resembling the key.
	rotated, ok, err := srv.RotateEABCredential(ctx, "payments", "payments-2", successorRef)
	if err != nil || !ok {
		t.Fatalf("rotate: ok=%v err=%v", ok, err)
	}
	if rotated.KeyID != "payments-2" || rotated.State != "active" || rotated.HMACKeyRef != successorRef || len(rotated.AllowedIdentifiers) != 1 || rotated.MaxOrders != 2 {
		t.Fatalf("successor status = %+v, want active with the predecessor's policy and the reference", rotated)
	}
	if _, _, err := srv.RotateEABCredential(ctx, "payments", "payments-2", successorRef); err == nil {
		t.Fatal("rotating onto an existing key id must be refused")
	}
	if _, _, err := srv.RotateEABCredential(ctx, "payments", "payments-3", "secret://acme/eab/missing"); err == nil || !strings.Contains(err.Error(), "resolve") {
		t.Fatalf("an unresolvable reference = %v, want a resolve failure and no registration", err)
	}
	if _, ok, _ := srv.RotateEABCredential(ctx, "nobody", "payments-4", successorRef); ok {
		t.Fatal("rotating an unknown predecessor must report not found")
	}
	successor, err := register("payments-2", successorKey)
	if err != nil {
		t.Fatalf("register under the successor: %v", err)
	}
	if _, err := successor.AuthorizeOrder(ctx, xacme.DomainIDs("api.payments.example.test")); err != nil {
		t.Fatalf("order under the successor: %v", err)
	}
	if _, err := register("payments-2", configuredKey); err == nil {
		t.Fatal("the predecessor's key must not bind under the successor's kid")
	}
	// The predecessor keeps working until the operator disables it.
	if _, err := register("payments", configuredKey); err != nil {
		t.Fatalf("predecessor after rotation: %v", err)
	}
	if _, ok, err := srv.SetEABDisabled(ctx, "payments", true); !ok || err != nil {
		t.Fatalf("disable predecessor: ok=%v err=%v", ok, err)
	}
	if _, err := register("payments", configuredKey); err == nil {
		t.Fatal("a disabled predecessor must refuse new accounts")
	}

	// Restart with the resolver: the narrowed policy and the successor are
	// rebuilt from the state log, the successor's key resolved again.
	restarted := build(resolver)
	handler.Store(restarted)
	var successorAfter, predecessorAfter *acmesrv.EABCredentialStatus
	for _, cred := range restarted.EABCredentials() {
		cred := cred
		switch cred.KeyID {
		case "payments-2":
			successorAfter = &cred
		case "payments":
			predecessorAfter = &cred
		}
	}
	if successorAfter == nil || successorAfter.State != "active" || successorAfter.HMACKeyRef != successorRef {
		t.Fatalf("successor after restart = %+v, want active from the replayed reference", successorAfter)
	}
	if predecessorAfter == nil || len(predecessorAfter.AllowedIdentifiers) != 1 || predecessorAfter.AllowedIdentifiers[0] != "*.payments.example.test" || predecessorAfter.MaxOrders != 2 {
		t.Fatalf("predecessor policy after restart = %+v, want the replayed narrowed policy", predecessorAfter)
	}
	if predecessorAfter.State != "disabled" || !predecessorAfter.DisabledByOperator {
		t.Fatalf("disabled predecessor after restart = %+v, want the replayed operator kill switch", predecessorAfter)
	}
	if predecessorAfter.OrdersCreated != 1 || successorAfter.OrdersCreated != 1 {
		t.Fatalf("order quotas reset after restart: predecessor=%+v successor=%+v", predecessorAfter, successorAfter)
	}
	if predecessorAfter.AccountsBound != 2 || successorAfter.AccountsBound != 1 {
		t.Fatalf("account bindings reset after restart: predecessor=%+v successor=%+v", predecessorAfter, successorAfter)
	}
	if _, err := register("payments", configuredKey); err == nil {
		t.Fatal("a credential disabled before restart must still refuse new accounts")
	}
	successorAfterRestart, err := register("payments-2", successorKey)
	if err != nil {
		t.Fatalf("register under the successor after restart: %v", err)
	}
	if _, err := successorAfterRestart.AuthorizeOrder(ctx, xacme.DomainIDs("post-restart.payments.example.test")); err != nil {
		t.Fatalf("one remaining successor order after restart: %v", err)
	}
	if _, err := successorAfterRestart.AuthorizeOrder(ctx, xacme.DomainIDs("over-quota.payments.example.test")); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("successor quota after restart = %v, want a quota refusal", err)
	}

	// Restart without the secret: the successor is listed as unavailable and
	// admits nothing; the mount still started.
	delete(secrets, successorRef)
	degraded := build(resolver)
	handler.Store(degraded)
	var unavailable *acmesrv.EABCredentialStatus
	for _, cred := range degraded.EABCredentials() {
		cred := cred
		if cred.KeyID == "payments-2" {
			unavailable = &cred
		}
	}
	if unavailable == nil || unavailable.State != "unavailable" {
		t.Fatalf("successor with an unresolvable reference = %+v, want unavailable", unavailable)
	}
	if _, err := register("payments-2", successorKey); err == nil {
		t.Fatal("an unavailable credential must refuse new accounts")
	}
}

// Two live ACME mounts share the event log. Each read catches up before it
// reports or uses the operator's decision, including an enable after disable.
func TestEABDisableReachesOtherReplica(t *testing.T) {
	ctx := t.Context()
	log := openACMEStateLog(t)
	build := func() *acmesrv.Server {
		t.Helper()
		srv := acmesrv.New(mustBuiltin(t), acmesrv.AcceptAll{})
		var err error
		srv, err = srv.WithExternalAccountBindings(true, []acmesrv.ExternalAccountBindingKey{{
			KeyID: "shared", HMACKey: bytes.Repeat([]byte{0x63}, 32),
		}})
		if err != nil {
			t.Fatal(err)
		}
		srv = srv.WithStateScope(func(context.Context) (acmesrv.StateScope, error) {
			return acmesrv.StateScope{Identity: "shared-registration", FirstSequence: 1}, nil
		})
		srv, err = srv.WithStateLog(ctx, "eab-replica", log)
		if err != nil {
			t.Fatal(err)
		}
		return srv
	}
	first, second := build(), build()
	if _, ok, err := first.SetEABDisabled(ctx, "shared", true); !ok || err != nil {
		t.Fatalf("disable on first replica: ok=%v err=%v", ok, err)
	}
	statuses, err := second.EABCredentialsContext(ctx)
	if err != nil || len(statuses) != 1 || !statuses[0].DisabledByOperator {
		t.Fatalf("second replica did not catch up to disable: statuses=%+v err=%v", statuses, err)
	}
	if _, ok, err := second.SetEABDisabled(ctx, "shared", false); !ok || err != nil {
		t.Fatalf("enable on second replica: ok=%v err=%v", ok, err)
	}
	statuses, err = first.EABCredentialsContext(ctx)
	if err != nil || len(statuses) != 1 || statuses[0].DisabledByOperator {
		t.Fatalf("first replica did not catch up to enable: statuses=%+v err=%v", statuses, err)
	}
}
