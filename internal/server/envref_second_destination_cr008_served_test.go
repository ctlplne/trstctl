// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/discovery/netpath/awsnetpath/ec2test"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// CR-008 (design §4, review 2 item 5): where one credential serves two
// destinations, the binding must name both. Here only the second destination is
// the other party's collector: AWS Elastic Load Balancing behind an EC2 endpoint
// the owner bound (the attack-path reader), and the token service a container
// registry names in its challenge (third-party collection, which sends the
// username and token there as basic credentials). Each is refused by the pin,
// with nothing received.
func TestServedSecondDestinationsNeedTheirOwnBindingCR008(t *testing.T) {
	const (
		accessKey = "AKIAAAAAAAAAACR8"                  // #nosec G101 -- fabricated fixture value (CWE-798)
		secretKey = "served-test-secret-cr008"          // #nosec G101 -- fabricated fixture value (CWE-798)
		regUser   = "cr008-registry-user"               // #nosec G101 -- fabricated fixture value (CWE-798)
		regToken  = "cr008-registry-token-value"        // #nosec G101 -- fabricated fixture value (CWE-798)
		keyRef    = "env:TRSTCTL_CR008S_EC2_ACCESS_KEY" // #nosec G101 -- reference names only (CWE-798)
		secretRef = "env:TRSTCTL_CR008S_EC2_SECRET_KEY" // #nosec G101 -- reference names only (CWE-798)
		userRef   = "env:TRSTCTL_CR008S_REGISTRY_USER"  // #nosec G101 -- reference names only (CWE-798)
		tokenRef  = "env:TRSTCTL_CR008S_REGISTRY_TOKEN" // #nosec G101 -- reference names only (CWE-798)
	)
	t.Setenv(strings.TrimPrefix(keyRef, "env:"), accessKey)
	t.Setenv(strings.TrimPrefix(secretRef, "env:"), secretKey)
	t.Setenv(strings.TrimPrefix(userRef, "env:"), regUser)
	t.Setenv(strings.TrimPrefix(tokenRef, "env:"), regToken)
	var other cr008Collector
	otherServer := httptest.NewServer(other.handler(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer otherServer.Close()

	// The owner's EC2 stand-in, with a public application load balancer whose
	// listeners the reader asks Elastic Load Balancing for.
	stand := ec2test.New(accessKey, secretKey)
	t.Cleanup(stand.Close)
	allowAll := []ec2test.ACLEntry{{Number: 100, Allow: true, Protocol: "-1", CIDR: "0.0.0.0/0"}, {Number: 100, Egress: true, Allow: true, Protocol: "-1", CIDR: "0.0.0.0/0"}}
	stand.Seed(
		[]ec2test.Interface{{ID: "eni-alb", SubnetID: "subnet-lb", VPCID: "vpc-1", PublicIP: "203.0.113.20", Groups: []string{"sg-alb"},
			RequesterManaged: true, Description: "ELB app/web/50dc6c495c0c9188", PrivateIP: "10.0.1.20"}},
		[]ec2test.SecurityGroup{{ID: "sg-alb", Inbound: []ec2test.Permission{{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"0.0.0.0/0"}}}}},
		[]ec2test.RouteTable{{ID: "rtb-lb", VPCID: "vpc-1", Subnets: []string{"subnet-lb"}, Routes: []ec2test.Route{
			{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "0.0.0.0/0", Target: "igw-1"}}}},
		[]ec2test.NetworkACL{{ID: "acl-1", Subnets: []string{"subnet-lb"}, Entries: allowAll}},
	)
	stand.SeedLoadBalancers(ec2test.LoadBalancer{ARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/50dc6c495c0c9188",
		Name: "web", Type: "application", Scheme: "internet-facing", SecurityGroups: []string{"sg-alb"},
		Listeners: []ec2test.Listener{{Port: 443, Protocol: "HTTPS"}}})
	// The owner's registry, whose challenge names the other party's token service.
	var challenged atomic.Int32
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenged.Add(1)
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+otherServer.URL+`/token",service="cr008-registry"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer registry.Close()
	loopback := []string{serviceNowSinkCIDR(t, stand.URL())}

	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil),
		bindOutboundEnvCredentialRefs("cloud_network_path", []string{stand.URL()}, keyRef, secretRef),
		bindOutboundEnvCredentialRefs("secret_third_party", []string{registry.URL}, userRef, tokenRef))
	ctx := t.Context()

	// Elastic Load Balancing: a cloud_network_path source stored without the
	// API's check names the bound EC2 endpoint and an unbound ELB endpoint.
	raw, err := json.Marshal(map[string]any{"providers": []map[string]any{{
		"provider": "aws-ec2", "region": "us-east-1", "endpoint": stand.URL(), "elb_endpoint": otherServer.URL,
		"allow_private_endpoint": true, "private_egress_cidrs": loopback, "access_key_id_ref": keyRef, "secret_access_key_ref": secretRef,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	const findingID = "22222222-2222-2222-2222-22222222c008"
	seedDiscoveryPostureFindingWithIDs(t, h.store, h.tenant, "22222222-2222-2222-2222-22222222c0a8", "22222222-2222-2222-2222-22222222c0b8",
		findingID, time.Now().UTC(), map[string]any{"public_endpoint": "https://203.0.113.20/api"})
	validate := func(t *testing.T, tenantID string) store.DiscoveryRun {
		t.Helper()
		source, err := h.srv.orch.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{Kind: orchestrator.AttackPathSourceKind, Name: "cr008 elb", Config: raw})
		if err != nil {
			t.Fatal(err)
		}
		runID, err := h.srv.orch.QueueAttackPathValidation(ctx, tenantID, "cr008-elb-"+googleuuid.NewString(), "cr008", source.ID,
			[]orchestrator.AttackPathEndpoint{{InventoryID: "finding/" + findingID, Endpoint: "https://203.0.113.20/api", Address: "203.0.113.20:443"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		run, err := h.store.GetDiscoveryRun(ctx, tenantID, runID)
		if err != nil {
			t.Fatal(err)
		}
		return run
	}
	// Another tenant's stored source names the owner's references: refused by
	// the tenant check before the owner's EC2 endpoint is reached.
	otherTenant := googleuuid.NewString()
	registerServedTenantID(t, h, otherTenant, "CR-008 second tenant")
	// Ordered subtests: each case fails on its own under a mutation.
	t.Run("Elastic Load Balancing, another tenant", func(t *testing.T) {
		if run := validate(t, otherTenant); run.Status != "failed" || !strings.Contains(run.Error, "has not bound it to this tenant") ||
			stand.Calls("DescribeNetworkInterfaces") != 0 {
			t.Fatalf("another tenant's attack-path source was not refused by the tenant check: %s (%s)", run.Status, run.Error)
		}
	})
	t.Run("Elastic Load Balancing, the owner", func(t *testing.T) {
		run := validate(t, h.tenant)
		if stand.Calls("DescribeNetworkInterfaces") == 0 {
			t.Fatalf("the reader never reached the bound EC2 endpoint, so the ELB case proves nothing (run %s: %s)", run.Status, run.Error)
		}
		// The reader went on to Elastic Load Balancing, and the pin refused that
		// request: the observation says so.
		reader := seedScopedToken(t, h.store, h.tenant, "nhi:read")
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/exposure", reader, nil)
		var posture struct {
			Findings []attackPathPostureRow `json:"findings"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &posture) != nil {
			t.Fatalf("posture = %d %s", status, body)
		}
		elbOrigin := otherServer.URL
		refusedAtELB := false
		for _, row := range posture.Findings {
			if row.InventoryID != "finding/"+findingID {
				continue
			}
			for _, endpoint := range row.AttackPath.Endpoints {
				if strings.Contains(endpoint.Reason, "is outside the origins the credential is bound to") && strings.Contains(endpoint.Reason, elbOrigin) {
					refusedAtELB = true
				}
			}
		}
		if !refusedAtELB {
			t.Fatalf("no observation says the pin refused Elastic Load Balancing at %s: %s", elbOrigin, body)
		}
	})
	t.Run("registry token service", func(t *testing.T) {
		// The registry's token service: the owner's collection is accepted (its
		// references are bound to the registry), and the run follows the challenge.
		tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", string(authz.PrivateEgress))
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/container_registry/ingest", tok, "cr008-registry",
			map[string]any{"source": "cr008-registry-app", "event": "cr008", "collect": map[string]any{"base_url": registry.URL, "repository": "team/app",
				"reference": "v1", "username_ref": userRef, "token_ref": tokenRef, "allow_private_endpoint": true, "private_egress_cidrs": loopback}})
		var receipt struct {
			RunID string `json:"run_id"`
		}
		if status != http.StatusAccepted || json.Unmarshal(body, &receipt) != nil || receipt.RunID == "" {
			t.Fatalf("ingest: HTTP %d %s", status, body)
		}
		// The refused token request is not a definite refusal to the collection, so
		// the run retries; every attempt is refused the same way. Once the registry
		// has challenged the run, deliver its row once more by hand to read why.
		deadline := time.Now().Add(10 * time.Second)
		for challenged.Load() == 0 && time.Now().Before(deadline) {
			h.srv.dispatchOnce(context.Background())
			time.Sleep(50 * time.Millisecond)
		}
		if challenged.Load() == 0 {
			t.Fatal("the registry collection never met the challenge, so the token-service case proves nothing")
		}
		var m orchestrator.Message
		if err := h.store.SystemPool().QueryRow(ctx, `SELECT id, tenant_id::text, destination, idempotency_key, payload FROM outbox
			  WHERE tenant_id = $1 AND destination = 'discovery.run' ORDER BY id DESC LIMIT 1`, h.tenant).Scan(
			&m.ID, &m.TenantID, &m.Destination, &m.IdempotencyKey, &m.Payload); err != nil {
			t.Fatalf("the collection's outbox row: %v", err)
		}
		if err := h.srv.obHandler.Deliver(ctx, m); err == nil || !strings.Contains(err.Error(), "is outside the origins the credential is bound to") ||
			!strings.Contains(err.Error(), otherServer.URL) {
			t.Fatalf("the collection was not refused at the unbound token service: %v", err)
		}
	})

	if other.received(accessKey) || other.received(regToken) || other.received(regUser+":"+regToken) || other.requests() != 0 {
		t.Fatalf("the other party's collector received %d requests", other.requests())
	}
}
