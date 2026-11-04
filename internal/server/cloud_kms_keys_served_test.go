// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// TestServedCloudKMSKeyInventoryShowsTypeAndRotationX4 is X4 part 1 on
// LocalStack KMS, through a cloud_kms_key source configured as an operator
// configures one: a rotating and an unrotated symmetric key, an RSA signing
// key and an EC signing key appear with their type, size, usage and rotation
// status; only the unrotated key is flagged; nothing is changed in KMS; and
// another tenant sees none of it.
func TestServedCloudKMSKeyInventoryShowsTypeAndRotationX4(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	localstack, address := a201Container(t, "4566", "-e", "SERVICES=kms", a202LocalStackImage)
	a201Await(t, "LocalStack KMS", func() bool {
		_, err := a201Exec(localstack, "awslocal", "kms", "list-keys")
		return err == nil
	})
	awslocal := func(args ...string) string {
		t.Helper()
		out, err := a201Exec(localstack, append([]string{"awslocal"}, args...)...)
		if err != nil {
			t.Fatalf("awslocal %v: %v %s", args, err, out)
		}
		return out
	}
	create := func(args ...string) string {
		t.Helper()
		return awslocal(append([]string{"kms", "create-key", "--query", "KeyMetadata.KeyId", "--output", "text"}, args...)...)
	}
	rotating, unrotated := create(), create()
	rsa := create("--key-spec", "RSA_2048", "--key-usage", "SIGN_VERIFY")
	ec := create("--key-spec", "ECC_NIST_P256", "--key-usage", "SIGN_VERIFY")
	awslocal("kms", "enable-key-rotation", "--key-id", rotating)

	t.Setenv("TRSTCTL_X4_KMS_ACCESS_KEY_ID", "test")
	t.Setenv("TRSTCTL_X4_KMS_SECRET_ACCESS_KEY", "test")
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs(
		"env:TRSTCTL_X4_KMS_ACCESS_KEY_ID", "env:TRSTCTL_X4_KMS_SECRET_ACCESS_KEY"))
	ctx := t.Context()
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", string(authz.PrivateEgress))
	endpoint := "http://" + address
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, map[string]any{
		"name": "aws-kms-us-east-1", "kind": "cloud_kms_key", "config": map[string]any{"providers": []map[string]any{{ // #nosec G101 -- credential references only; no credential value enters the config (CWE-798)
			"provider": "aws-kms", "region": "us-east-1", "endpoint": endpoint, "allow_private_endpoint": true,
			"private_egress_cidrs": []string{serviceNowSinkCIDR(t, endpoint)},
			"access_key_id_ref":    "env:TRSTCTL_X4_KMS_ACCESS_KEY_ID", "secret_access_key_ref": "env:TRSTCTL_X4_KMS_SECRET_ACCESS_KEY",
		}}},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create cloud_kms_key source: %d %s", status, body)
	}
	before := awslocal("kms", "list-keys")

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", writer, "x4-kms-run", map[string]any{"source_id": source.ID})
	var queued struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &queued) != nil || queued.ID == "" {
		t.Fatalf("queue run: %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	run, err := h.store.GetDiscoveryRun(ctx, h.tenant, queued.ID)
	if err != nil || run.Status != "succeeded" || run.Targets != 1 || run.Discovered != 4 {
		t.Fatalf("run = %+v %v", run, err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, writer, nil)
	var listed struct {
		Items []struct {
			Kind      string         `json:"kind"`
			Ref       string         `json:"ref"`
			RiskScore int            `json:"risk_score"`
			Metadata  map[string]any `json:"metadata"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &listed) != nil || len(listed.Items) != 4 {
		t.Fatalf("findings = %d %s", status, body)
	}
	want := map[string]struct {
		keyType  string
		bits     float64
		usage    string
		rotation string
		risk     int
	}{
		rotating:  {"AES", 256, "ENCRYPT_DECRYPT", "enabled", 20},
		unrotated: {"AES", 256, "ENCRYPT_DECRYPT", "disabled", 60},
		rsa:       {"RSA", 2048, "SIGN_VERIFY", "not_supported", 20},
		ec:        {"ECDSA", 256, "SIGN_VERIFY", "not_supported", 20},
	}
	for _, f := range listed.Items {
		id, _ := f.Metadata["key_id"].(string)
		w, ok := want[id]
		if !ok || f.Kind != "cloud_kms_key" || f.Metadata["key_type"] != w.keyType || f.Metadata["key_bits"] != w.bits ||
			f.Metadata["key_usage"] != w.usage || f.Metadata["rotation"] != w.rotation || f.RiskScore != w.risk ||
			f.Metadata["unrotated"] != (id == unrotated) || f.Metadata["key_manager"] != "CUSTOMER" || f.Metadata["created_at"] == nil ||
			!bytes.HasPrefix([]byte(f.Ref), []byte("arn:aws:kms:us-east-1:")) {
			t.Fatalf("key %s finding = %+v, want %+v", id, f, w)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatalf("keys missing from the inventory: %v", want)
	}
	if after := awslocal("kms", "list-keys"); after != before {
		t.Fatalf("the run changed KMS:\nbefore %s\nafter %s", before, after)
	}

	other := uuid.NewString()
	registerServedTenantID(t, h, other, "X4 isolation tenant")
	otherToken := seedScopedToken(t, h.store, other, "discovery:read")
	for _, path := range []string{"/api/v1/discovery/findings?run_id=" + queued.ID, "/api/v1/discovery/sources"} {
		status, body := secretsReq(t, h, http.MethodGet, path, otherToken, nil)
		if bytes.Contains(body, []byte(rotating)) || bytes.Contains(body, []byte(source.ID)) {
			t.Fatalf("another tenant read X4 data at %s: %d %s", path, status, body)
		}
	}
}
