// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/app"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/pfx"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

// The real host runtime crosses served mTLS for claims, management credentials,
// signing and signed results. The file is independently decoded after each
// generation. Listener activation is a separate installed Tomcat qualification.
func TestServedHostKeystoreIssuanceAndRenewalRedeemOnlyManagementCredential(t *testing.T) {
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{agentJobKindEndpointRenew, "connector.rollback"}, func(d *Deps) {
		d.DefaultProfile = "host-keystore"
	})
	ctx := t.Context()
	registration := app.New(h.log, h.store, nil)
	t.Cleanup(registration.Close)
	if err := registration.RegisterTenant(ctx, h.tenant, "host-keystore", "host-keystore-registration"); err != nil {
		t.Fatal(err)
	}
	const referenceName = "host-keystore-access"
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, referenceName, []byte(canaryPassword))
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, referenceName, sealed)
	token := seedScopedToken(t, h.store, h.tenant, "owners:write", "connectors:write", "certs:issue", "profiles:write", "identities:write")
	post := func(path string, body any, want int) map[string]json.RawMessage {
		t.Helper()
		code, raw := secretsReq(t, h.servedHarness, http.MethodPost, path, token, body)
		if code != want {
			t.Fatalf("POST %s: HTTP%d %s", path, code, raw)
		}
		var result map[string]json.RawMessage
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	text := func(raw json.RawMessage) string {
		t.Helper()
		var result string
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	post("/api/v1/profiles", map[string]any{"name": "host-keystore", "spec": map[string]any{
		"max_validity": "12m", "allowed_protocols": []string{"api"}, "allowed_dns_suffixes": []string{"keystore.test"},
	}}, http.StatusCreated)
	owner := text(post("/api/v1/owners", map[string]any{"kind": "workload", "name": "Java service"}, http.StatusCreated)["id"])
	dir := t.TempDir()
	path := filepath.Join(dir, "server.p12")
	target := text(post("/api/v1/connectors/targets", map[string]any{
		"name": "host-java", "connector": "java-keystore", "enabled": true,
		"config": map[string]any{"executor": "agent", "required_agent_id": registeredRoleAgentID(t, h),
			"keystore_path": path, "keystore_password_ref": "secret://" + referenceName, "format": "pkcs12", "alias": "payments"},
	}, http.StatusCreated)["id"])
	request := map[string]any{"owner_id": owner, "identity_name": "java.keystore.test", "target_id": target,
		"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}, "reason": "prove host credential handoff"}
	request["preview_fingerprint"] = text(post("/api/v1/lifecycle/endpoint-bindings/preview", request, http.StatusOK)["request_fingerprint"])
	enrolled := post("/api/v1/lifecycle/endpoint-bindings", request, http.StatusCreated)
	var identity struct{ ID string }
	if err := json.Unmarshal(enrolled["identity"], &identity); err != nil {
		t.Fatal(err)
	}
	previous := ""
	firstFingerprint := ""
	rollbackState, err := agentrelay.NewHostRollbackStore(filepath.Join(dir, "rollback"), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for generation := 0; generation < 2; generation++ {
		kind := "ca.issue"
		if generation > 0 {
			code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/identities/"+identity.ID+"/transitions", token,
				fmt.Sprintf("java-renewal-%d", generation), map[string]any{"to": "renewing", "reason": "prove repeated keystore handoff"})
			if code != http.StatusOK {
				t.Fatalf("renew: HTTP%d %s", code, body)
			}
			kind = "ca.renew"
		}
		if _, err := h.srv.outbox.DispatchOneScoped(ctx, h.srv.obHandler, orchestrator.DestinationScope{IncludePrefixes: []string{kind}}); err != nil {
			t.Fatal(err)
		}
		channel := &servedHostKeystoreChannel{servedHostRelayChannel: servedHostRelayChannel{client: h.client, identity: h.identity}}
		executed, err := agentrelay.RunOnceWithSelfUpgradeAndHostRollback(ctx, channel, http.DefaultClient, connector.LocalOpsConfig{AllowedRoots: []string{dir}}, nil, nil, rollbackState, 1, 120)
		if err != nil || executed != 1 || !channel.lastAccepted {
			t.Fatalf("generation%d runtime=%d err=%v report=%s/%s accepted=%v reportErr=%v", generation, executed, err, channel.lastOutcome, channel.lastDetail, channel.lastAccepted, channel.lastReportErr)
		}
		if len(channel.redeemedWire) != 1 || len(channel.redeemedWire["secret://"+referenceName]) == 0 {
			t.Fatalf("unexpected management credential set: %v", keysOf(channel.redeemedWire))
		}
		for _, value := range channel.redeemedWire {
			if !bytes.Equal(value, make([]byte, len(value))) {
				t.Fatal("host runtime retained wire credential bytes")
			}
		}
		blob, err := os.ReadFile(path) // #nosec G304 -- fixed filename inside this test's private TempDir (CWE-22).
		if err != nil {
			t.Fatal(err)
		}
		key, chain, err := pfx.Decode(blob, canaryPassword)
		secret.Wipe(blob)
		if err != nil {
			t.Fatal(err)
		}
		secret.Wipe(key)
		info, err := certinfo.Inspect(chain)
		if err != nil || info.SHA256Fingerprint != channel.lastCredentialFingerprint || info.SHA256Fingerprint == previous {
			t.Fatalf("generation%d keystore does not match the newly signed certificate: info=%+v err=%v", generation, info, err)
		}
		previous = info.SHA256Fingerprint
		if generation == 0 {
			firstFingerprint = previous
		}
		if _, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: channel.jobID, Attempt: channel.attempt}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("completed attempt can redeem again: %v", err)
		}
		assertNoCanaryInJobRows(t, ctx, h)
		// Real issuance events contain public certificate PEM and fingerprints.
		// Check the exact password (including encoded forms) across every byte;
		// an entropy heuristic cannot distinguish those public values from keys.
		if err := h.log.Replay(ctx, 0, func(e events.Event) error {
			if e.TenantID == h.tenant {
				assertNoCanaryBytes(t, "host issuance event "+e.Type, e.Data)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets/"+target+"/rollback", token, "host-keystore-rollback",
		map[string]any{"identity_id": identity.ID, "reason": "restore the first Java generation"})
	if code != http.StatusOK {
		t.Fatalf("rollback: HTTP%d %s", code, body)
	}
	channel := &servedHostKeystoreChannel{servedHostRelayChannel: servedHostRelayChannel{client: h.client, identity: h.identity}}
	// A new local ledger instance proves predecessor custody survived restart.
	rollbackState, err = agentrelay.NewHostRollbackStore(filepath.Join(dir, "rollback"), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	executed, err := agentrelay.RunOnceWithSelfUpgradeAndHostRollback(ctx, channel, http.DefaultClient, connector.LocalOpsConfig{AllowedRoots: []string{dir}}, nil, nil, rollbackState, 1, 120)
	if err != nil || executed != 1 || !channel.lastAccepted || len(channel.redeemedWire) != 1 {
		t.Fatalf("rollback runtime=%d err=%v outcome=%s detail=%s accepted=%v", executed, err, channel.lastOutcome, channel.lastDetail, channel.lastAccepted)
	}
	blob, err := os.ReadFile(path) // #nosec G304 -- fixed filename inside this test's private TempDir (CWE-22).
	if err != nil {
		t.Fatal(err)
	}
	key, chain, err := pfx.Decode(blob, canaryPassword)
	secret.Wipe(blob)
	secret.Wipe(key)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certinfo.Inspect(chain)
	if err != nil || info.SHA256Fingerprint != firstFingerprint {
		t.Fatalf("rollback did not restore exact predecessor: %v", err)
	}
	for _, value := range channel.redeemedWire {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("rollback retained wire password")
		}
	}

}

type servedHostKeystoreChannel struct {
	servedHostRelayChannel
	redeemedWire map[string][]byte
	jobID        int64
	attempt      int
}

func (c *servedHostKeystoreChannel) RedeemJobCredential(ctx context.Context, id int64, attempt int) (map[string][]byte, error) {
	items, err := c.servedHostRelayChannel.RedeemJobCredential(ctx, id, attempt)
	c.redeemedWire, c.jobID, c.attempt = items, id, attempt
	return items, err
}

func (c *servedHostKeystoreChannel) SignJobCSR(ctx context.Context, id int64, attempt int, csr []byte) ([]byte, []byte, string, error) {
	response, err := c.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: id, Attempt: attempt, CSRDER: csr})
	if err != nil {
		return nil, nil, "", err
	}
	return response.CertificatePEM, response.ChainPEM, response.Fingerprint, nil
}
