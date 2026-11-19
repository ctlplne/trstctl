// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/cloudentitlements/change"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// CR-008 (design §4): an approved cloud machine change stored without the API's
// check, whose writer session reference the operator bound to the owner tenant
// and the AWS IAM endpoint only, is refused by the worker with nothing sent,
// once when another tenant names the owner's reference and once when the owner
// points the change at another IAM endpoint. The change ends failed and says
// why.
func TestServedStoredCloudChangeWriterSendsNothingOutsideItsBindingCR008(t *testing.T) {
	const writerRef = "env:TRSTCTL_CR008W_WRITER_SESSION_FILE"                    // #nosec G101 -- a reference name only (CWE-798)
	keyID, sessionToken := "ASIACR008WOWNERWRITER", "cr008w-writer-session-value" // #nosec G101 -- fabricated fixture values (CWE-798)
	session, err := json.Marshal(map[string]any{"Credentials": map[string]any{    // #nosec G101 -- fabricated fixture values; no value is real (CWE-798)
		"AccessKeyId": keyID, "SecretAccessKey": "cr008w-writer-secret-value", "SessionToken": sessionToken,
		"Expiration": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "writer-session.json")
	if err := os.WriteFile(path, session, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(strings.TrimPrefix(writerRef, "env:"), path)
	var other cr008Collector
	otherTLS := httptest.NewTLSServer(other.handler(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer otherTLS.Close()
	otherCA := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherTLS.TLS.Certificates[0].Certificate[0]}))
	loopback := []string{serviceNowSinkCIDR(t, otherTLS.URL)}
	// The owner's own IAM stand-in, bound for the owner's writer session.
	var ownerIAM cr008Collector
	ownerIAMServer := httptest.NewTLSServer(ownerIAM.handler(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ownerIAMServer.Close()
	ownerCA := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ownerIAMServer.TLS.Certificates[0].Certificate[0]}))
	h := newOperatingServedHarness(t, config.Protocols{},
		bindOutboundEnvCredentialRefs("cloud_machine_change", []string{"https://iam.amazonaws.com", ownerIAMServer.URL}, writerRef))
	otherTenant := googleuuid.NewString()
	registerServedTenantID(t, h, otherTenant, "CR-008 second tenant")
	ctx := t.Context()

	const arn = "arn:aws:iam::111122223333:user/cr008-workload"
	for _, scenario := range []struct {
		who, tenantID, endpoint, ca, refusal string
	}{
		{"another tenant", otherTenant, otherTLS.URL, otherCA, "has not bound it to this tenant"},
		// Only the tenant check stands between another tenant and the owner's
		// bound IAM endpoint.
		{"another tenant at the owner's IAM endpoint", otherTenant, ownerIAMServer.URL, ownerCA, "has not bound it to this tenant"},
		{"the owner to another IAM endpoint", h.tenant, otherTLS.URL, otherCA, "has not bound it to send to"},
		// The control: the owner's change at its bound endpoint passes the check
		// and its writer reaches the owner's IAM, which refuses it.
		{"the owner at its bound IAM endpoint", h.tenant, ownerIAMServer.URL, ownerCA, ""},
	} {
		ownerBefore := ownerIAM.requests()
		cfg := assessment.SourceConfig{Endpoint: scenario.endpoint, CAPEM: scenario.ca, SessionFileRef: "env:TRSTCTL_CR008W_READER_SESSION_FILE",
			AllowPrivateEndpoint: true, PrivateEgressCIDRs: loopback, Principals: []awsiam.Selection{{Kind: awspolicy.IAMUser, Name: "cr008-workload"}},
			Input: assessment.Input{Checks: []assessment.Check{{PrincipalARN: arn, Action: "s3:GetObject", Resource: "arn:aws:s3:::cr008/object", ResourceAccountID: "111122223333"}}}}
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		source, err := h.srv.orch.UpsertDiscoverySource(ctx, scenario.tenantID, store.DiscoverySource{Kind: assessment.SourceKind, Name: "cr008 " + scenario.who, Config: raw})
		if err != nil {
			t.Fatalf("%s: store the source: %v", scenario.who, err)
		}
		decoded, err := assessment.DecodeSource(source.Config)
		if err != nil {
			t.Fatal(err)
		}
		sourceFingerprint, err := assessment.SourceFingerprint(decoded)
		if err != nil {
			t.Fatal(err)
		}
		runID, findingID := googleuuid.NewString(), googleuuid.NewString()
		if err := h.store.WithTenant(ctx, scenario.tenantID, func(tx pgx.Tx) error {
			if err := h.store.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{ID: runID, TenantID: scenario.tenantID, SourceID: source.ID,
				Status: "queued", CreatedAt: time.Now().UTC()}); err != nil {
				return err
			}
			return h.store.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{ID: findingID, TenantID: scenario.tenantID, RunID: runID,
				SourceID: source.ID, Kind: assessment.SourceKind, Ref: arn, Provenance: "aws-iam", Fingerprint: "cr008w-finding",
				Metadata: []byte(`{}`), DiscoveredAt: time.Now().UTC()})
		}); err != nil {
			t.Fatalf("%s: seed the finding: %v", scenario.who, err)
		}
		id := googleuuid.NewString()
		plan, err := h.srv.orch.ProposeCloudMachineChange(ctx, scenario.tenantID, id, "cr008-requester", change.Intent{ // #nosec G101 -- fabricated fixture values; no value is real (CWE-798)
			RequiredApprovals: 1, Action: change.RevokeKey, SourceID: source.ID, FindingID: findingID, FindingFingerprint: "cr008w-finding",
			SourceFingerprint: sourceFingerprint, PrincipalARN: arn, PrincipalID: "AIDACR008WORKLOAD0001", PrincipalKind: string(awspolicy.IAMUser),
			PrincipalName: "cr008-workload", Endpoint: scenario.endpoint, CAPEM: scenario.ca, AllowPrivateEndpoint: true, PrivateEgressCIDRs: loopback,
			WriterSessionFileRef: writerRef, AccessKeyID: "AKIACR008WORKLOADKEY", Reason: "CR-008 stored writer declaration",
		}, 1)
		if err != nil {
			t.Fatalf("%s: store the change: %v", scenario.who, err)
		}
		reviewer := seedScopedTokenSubject(t, h.store, scenario.tenantID, "cr008-reviewer", "approvals:review", "access:approve", "access:read")
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+plan.ApprovalRequestID+"/approvals", reviewer,
			"cr008-approve-"+id, map[string]any{"intent_digest": plan.IntentDigest}); status != http.StatusOK {
			t.Fatalf("%s: approve: %d %s", scenario.who, status, body)
		}
		if _, err := h.srv.orch.ExecuteCloudMachineChange(ctx, scenario.tenantID, id, "cr008-requester"); err != nil {
			t.Fatalf("%s: queue the change: %v", scenario.who, err)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		got, err := h.store.GetCloudMachineChange(ctx, scenario.tenantID, id)
		if err != nil {
			t.Fatal(err)
		}
		if scenario.refusal == "" {
			if got.Result == nil || strings.Contains(got.Result.Error, "not bound") || ownerIAM.requests() == ownerBefore || !ownerIAM.received(keyID) {
				t.Errorf("%s: the bound writer did not reach its IAM endpoint: state %s result %+v, %d requests there", scenario.who, got.State,
					got.Result, ownerIAM.requests()-ownerBefore)
			}
			continue
		}
		if got.State != change.Failed || got.Result == nil || !strings.Contains(got.Result.Error, "not bound to this use") ||
			!strings.Contains(got.Result.Error, scenario.refusal) {
			t.Errorf("%s: the worker did not refuse the writer reference: state %s result %+v", scenario.who, got.State, got.Result)
		}
		if n := ownerIAM.requests() - ownerBefore; n != 0 {
			t.Errorf("%s: the owner's IAM endpoint received %d requests", scenario.who, n)
		}
	}
	if other.received(keyID) || other.received(sessionToken) || other.requests() != 0 {
		t.Fatalf("the other IAM endpoint received %d requests carrying the owner's writer session", other.requests())
	}
}
