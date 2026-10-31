// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/discovery/netpath/awsnetpath/ec2test"
)

type attackPathPostureRow struct {
	InventoryID  string   `json:"inventory_id"`
	EvidenceRefs []string `json:"evidence_refs"`
	AttackPath   *struct {
		Status    string `json:"status"`
		Endpoints []struct {
			Address   string   `json:"address"`
			Status    string   `json:"status"`
			BlockedBy string   `json:"blocked_by"`
			Resource  string   `json:"resource"`
			Path      []string `json:"path"`
			Reason    string   `json:"reason"`
		} `json:"endpoints"`
	} `json:"attack_path"`
}

// A167 Done-when: provider-native attack-path validation. An operator asks the
// cloud account that hosts the exposed NHIs' public endpoints whether its own
// network configuration admits the internet to them. The control plane reads
// the account through a cloud_network_path source — read-only, signed EC2
// Describe calls with referenced credentials — and the exposure posture then
// shows, per record, the verdict and the route table, network ACL or security
// group that decided it. Nothing is changed in the account and nothing is sent
// to the endpoints.
func TestServedAttackPathValidationNamesTheCloudResourceThatDecides(t *testing.T) {
	const (
		accessKey = "AKIAA167SERVED"
		secretKey = "a167-served-secret" // #nosec G101 -- fabricated fixture credential; the test needs the shape, no value is real (CWE-798)
	)
	stand := ec2test.New(accessKey, secretKey)
	t.Cleanup(stand.Close)
	stand.Seed(
		[]ec2test.Interface{
			{ID: "eni-web", SubnetID: "subnet-public", VPCID: "vpc-1", PublicIP: "203.0.113.10", Groups: []string{"sg-web"}},
			{ID: "eni-admin", SubnetID: "subnet-public", VPCID: "vpc-1", PublicIP: "203.0.113.11", Groups: []string{"sg-admin"}},
			{ID: "eni-private", SubnetID: "subnet-private", VPCID: "vpc-1", PublicIP: "203.0.113.12", Groups: []string{"sg-web"}},
		},
		[]ec2test.SecurityGroup{
			{ID: "sg-web", Inbound: []ec2test.Permission{{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"0.0.0.0/0"}}}},
			{ID: "sg-admin", Inbound: []ec2test.Permission{{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"198.51.100.0/24"}}}},
		},
		[]ec2test.RouteTable{
			{ID: "rtb-main", VPCID: "vpc-1", Main: true, Routes: []ec2test.Route{{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "0.0.0.0/0", Target: "nat-1"}}},
			{ID: "rtb-public", VPCID: "vpc-1", Subnets: []string{"subnet-public"}, Routes: []ec2test.Route{{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "0.0.0.0/0", Target: "igw-1"}}},
		},
		[]ec2test.NetworkACL{{ID: "acl-1", Subnets: []string{"subnet-public", "subnet-private"}, Entries: []ec2test.ACLEntry{
			{Number: 100, Allow: true, Protocol: "6", CIDR: "0.0.0.0/0", FromPort: 443, ToPort: 443},
			{Number: 32767, Protocol: "-1", CIDR: "0.0.0.0/0"},
			{Number: 100, Egress: true, Allow: true, Protocol: "6", CIDR: "0.0.0.0/0", FromPort: 1024, ToPort: 65535},
			{Number: 32767, Egress: true, Protocol: "-1", CIDR: "0.0.0.0/0"},
		}}},
	)
	t.Setenv("TRSTCTL_A167_EC2_ACCESS_KEY_ID", accessKey)
	t.Setenv("TRSTCTL_A167_EC2_SECRET_ACCESS_KEY", secretKey)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs(
		"env:TRSTCTL_A167_EC2_ACCESS_KEY_ID", "env:TRSTCTL_A167_EC2_SECRET_ACCESS_KEY", "env:TRSTCTL_A167_UNSET"))
	ctx := t.Context()
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "nhi:read", string(authz.PrivateEgress))
	reader := seedScopedToken(t, h.store, h.tenant, "nhi:read")

	const web, admin, private, foreign = "22222222-2222-2222-2222-2222222a1671", "22222222-2222-2222-2222-2222222a1672",
		"22222222-2222-2222-2222-2222222a1673", "22222222-2222-2222-2222-2222222a1674"
	now := time.Now().UTC()
	for i, record := range []struct{ id, endpoint string }{
		{web, "https://203.0.113.10/api"}, {admin, "https://203.0.113.11/admin"},
		{private, "https://203.0.113.12/internal"}, {foreign, "https://198.51.100.20/hook"},
	} {
		suffix := string(rune('a' + i))
		seedDiscoveryPostureFindingWithIDs(t, h.store, h.tenant, "22222222-2222-2222-2222-2222222a16a"+suffix,
			"22222222-2222-2222-2222-2222222a16b"+suffix, record.id, now, map[string]any{"public_endpoint": record.endpoint})
	}

	createSource := func(name string, provider map[string]any) string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, map[string]any{
			"name": name, "kind": "cloud_network_path", "config": map[string]any{"providers": []map[string]any{provider}},
		})
		var source struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
			t.Fatalf("create %s source: %d %s", name, status, body)
		}
		return source.ID
	}
	ec2 := map[string]any{ // #nosec G101 -- credential references only; no credential value enters the config (CWE-798)
		"provider": "aws-ec2", "region": "us-east-1", "endpoint": stand.URL(),
		"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, stand.URL())},
		"access_key_id_ref": "env:TRSTCTL_A167_EC2_ACCESS_KEY_ID", "secret_access_key_ref": "env:TRSTCTL_A167_EC2_SECRET_ACCESS_KEY",
	}
	sourceID := createSource("aws-ec2-east", ec2)

	const path = "/api/v1/nhi/posture/exposure/attack-paths"
	if status, body := secretsReqKey(t, h, http.MethodPost, path, reader, "a167-reader", map[string]any{"source_id": sourceID}); status != http.StatusForbidden {
		t.Fatalf("validate with nhi:read = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, path, writer, "a167-no-source", map[string]any{}); status != http.StatusBadRequest {
		t.Fatalf("validate without a source = %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, path, writer, "a167-other-source", map[string]any{"source_id": "22222222-2222-2222-2222-2222222a16ff"}); status != http.StatusConflict ||
		!bytes.Contains(body, []byte("cloud_network_path")) {
		t.Fatalf("validate with a source that is not cloud_network_path = %d %s", status, body)
	}

	status, body := secretsReqKey(t, h, http.MethodPost, path, writer, "a167-1", map[string]any{"source_id": sourceID})
	var queued struct {
		RunID     string `json:"run_id"`
		SourceID  string `json:"source_id"`
		Endpoints []struct {
			InventoryID string `json:"inventory_id"`
			Address     string `json:"address"`
		} `json:"endpoints"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil || queued.RunID == "" || queued.SourceID != sourceID || len(queued.Endpoints) != 4 {
		t.Fatalf("validate = %d %s", status, body)
	}
	if status, replay := secretsReqKey(t, h, http.MethodPost, path, writer, "a167-1", map[string]any{"source_id": sourceID}); status != http.StatusAccepted || !bytes.Equal(replay, body) {
		t.Fatalf("replay = %d %s", status, replay)
	}
	if stand.Calls("DescribeNetworkInterfaces") != 0 {
		t.Fatal("the request handler read the cloud account; only the outbox worker may")
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	run, err := h.store.GetDiscoveryRun(ctx, h.tenant, queued.RunID)
	if err != nil || run.Status != "succeeded" || run.SourceID != sourceID || run.Targets != 4 || run.Discovered != 1 {
		t.Fatalf("validation run = %+v %v", run, err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/nhi/posture/exposure", reader, nil)
	var posture struct {
		Coverage []string `json:"coverage"`
		Summary  struct {
			PathValidated int `json:"path_validated"`
			PathOpen      int `json:"path_open"`
		} `json:"summary"`
		Findings []attackPathPostureRow `json:"findings"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &posture) != nil {
		t.Fatalf("posture = %d %s", status, body)
	}
	rows := map[string]attackPathPostureRow{}
	for _, row := range posture.Findings {
		rows[row.InventoryID] = row
	}
	want := map[string]struct{ status, blockedBy, resource string }{
		web: {"open", "", "sg-web"}, admin: {"blocked", "security_group", "sg-admin"},
		private: {"blocked", "route", "rtb-main"}, foreign: {"not_in_account", "", ""},
	}
	for id, w := range want {
		row := rows["finding/"+id]
		if row.AttackPath == nil || row.AttackPath.Status != w.status || len(row.AttackPath.Endpoints) != 1 {
			t.Fatalf("%s attack path = %+v", id, row.AttackPath)
		}
		endpoint := row.AttackPath.Endpoints[0]
		if endpoint.Status != w.status || endpoint.BlockedBy != w.blockedBy || endpoint.Resource != w.resource || endpoint.Reason == "" ||
			!strings.HasSuffix(endpoint.Address, ":443") {
			t.Fatalf("%s endpoint verdict = %+v", id, endpoint)
		}
		evidenced := false
		for _, ref := range row.EvidenceRefs {
			evidenced = evidenced || strings.HasPrefix(ref, "attack_path:")
		}
		if !evidenced {
			t.Fatalf("%s carries no attack-path evidence ref: %v", id, row.EvidenceRefs)
		}
	}
	if open := rows["finding/"+web].AttackPath.Endpoints[0]; strings.Join(open.Path, ">") != "eni-web>sg-web>acl-1>rtb-public>igw-1" {
		t.Fatalf("open path = %v", open.Path)
	}
	if posture.Summary.PathValidated != 4 || posture.Summary.PathOpen != 1 || !strings.Contains(strings.Join(posture.Coverage, ","), "cloud_attack_paths") {
		t.Fatalf("posture summary = %+v coverage %v", posture.Summary, posture.Coverage)
	}
	if stand.NonDescribeCalls() != 0 || stand.Refused() != 0 {
		t.Fatalf("the validation changed the account (%d non-describe calls) or signed badly (%d refused)", stand.NonDescribeCalls(), stand.Refused())
	}

	// A source whose credential reference is unset fails its run with the
	// reason and judges no endpoint.
	broken := map[string]any{}
	for k, v := range ec2 {
		broken[k] = v
	}
	broken["secret_access_key_ref"] = "env:TRSTCTL_A167_UNSET"
	brokenID := createSource("aws-ec2-broken", broken)
	status, body = secretsReqKey(t, h, http.MethodPost, path, writer, "a167-broken", map[string]any{"source_id": brokenID, "inventory_ids": []string{"finding/" + web}})
	if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil {
		t.Fatalf("validate on a broken source = %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain broken: %v", err)
	}
	if run, err := h.store.GetDiscoveryRun(ctx, h.tenant, queued.RunID); err != nil || run.Status != "failed" || !strings.Contains(run.Error, "TRSTCTL_A167_UNSET is not set") {
		t.Fatalf("broken validation run = %+v %v", run, err)
	}
}
