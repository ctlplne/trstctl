// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/agent"
	"trstctl.com/trstctl/internal/succession/minter"
)

func TestCR332OfflineApprovalPayloadRoundTripsThroughSignerVerifier(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	const identity = "spiffe://approval.example/workload"
	dir := t.TempDir()
	intentPath := filepath.Join(dir, "intent.json")
	payloadPath := filepath.Join(dir, "payload.json")
	signaturePath := filepath.Join(dir, "signature.bin")
	publicPath := filepath.Join(dir, "authority.pem")
	requestPath := filepath.Join(dir, "request.json")
	intent := `{"tenant_id":"` + tenant + `","identity_id":"` + identity + `","credential_type":"workload-svid","deployment_scope":"spiffe://approval.example","predecessor_custody":"signer","predecessor_epoch":0,"target_algorithm":"ECDSA-P384","policy_ref":"policy:reviewed","delegation_scope":"team-a"}`
	if err := os.WriteFile(intentPath, []byte(intent), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(words ...string) (int, string) {
		t.Helper()
		var out, errOut bytes.Buffer
		code := cli.Run(context.Background(), words, cli.Env{Tenant: tenant}, strings.NewReader(""), &out, &errOut)
		return code, errOut.String()
	}
	if code, stderr := run("pcas", "succession", "approval", "prepare", "-f", intentPath, "--out", payloadPath); code != 0 {
		t.Fatalf("prepare exact approval payload: code=%d stderr=%s", code, stderr)
	}
	payload, err := os.ReadFile(payloadPath) // #nosec G304 -- test reads the output path under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	privatePEM, publicPEM, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(privatePEM)
	signature, err := crypto.SignEd25519(privatePEM, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil { // #nosec G703 -- test writes under t.TempDir
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, publicPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stderr := run("pcas", "succession", "approval", "assemble", "-f", intentPath,
		"--payload", payloadPath, "--signature", signaturePath, "--public-key", publicPath, "--out", requestPath); code != 0 {
		t.Fatalf("assemble exact signed request: code=%d stderr=%s", code, stderr)
	}
	body, err := os.ReadFile(requestPath) // #nosec G304 -- test reads the output path under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Authorization   json.RawMessage `json:"authorization"`
		DelegationScope string          `json:"delegation_scope"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	if request.DelegationScope != "team-a" {
		t.Fatalf("request delegation scope = %q", request.DelegationScope)
	}
	pubDER, err := crypto.ParseEd25519PublicKeyPEM(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	minterRequest := signing.MintRequest{
		IdentityID: identity, TenantID: tenant, DeploymentScope: "spiffe://approval.example",
		PredecessorHandle: succession.TenantKeyHandle(tenant, identity, 0),
		TargetAlgorithm:   crypto.ECDSAP384, PolicyRef: "policy:reviewed", DelegationScope: "team-a",
	}
	authorizer := minter.NewSignedTokenAuthorizer(pubDER)
	if err := authorizer.VerifyAndConsume(request.Authorization, minterRequest, minter.RequestParamsDigest(minterRequest)); err != nil {
		t.Fatalf("actual signer rejected CLI-built approval: %v", err)
	}
	if err := minter.NewSignedTokenAuthorizerForCustody(pubDER, succession.PredecessorCustodyWorkload).
		VerifyAndConsume(request.Authorization, minterRequest, minter.RequestParamsDigest(minterRequest)); err == nil {
		t.Fatal("workload verifier accepted a signer-held approval")
	}
	if err := authorizer.VerifyAndConsume(request.Authorization, minterRequest, minter.RequestParamsDigest(minterRequest)); err == nil {
		t.Fatal("actual signer accepted the CLI-built token twice")
	}
	misbound := minterRequest
	misbound.DelegationScope = "team-b"
	if err := minter.NewSignedTokenAuthorizer(pubDER).VerifyAndConsume(request.Authorization, misbound, minter.RequestParamsDigest(misbound)); err == nil {
		t.Fatal("actual signer accepted a token for another delegation scope")
	}

	// The same offline command can target the workload-held first succession.
	// Its bytes must verify at the independent agent, not just at the signer.
	workloadIntentPath := filepath.Join(dir, "workload-intent.json")
	workloadPayloadPath := filepath.Join(dir, "workload-payload.json")
	workloadSignaturePath := filepath.Join(dir, "workload-signature.bin")
	workloadRequestPath := filepath.Join(dir, "workload-request.json")
	workloadIntent := `{"tenant_id":"` + tenant + `","identity_id":"` + identity + `","credential_type":"workload-svid","deployment_scope":"spiffe://approval.example","predecessor_custody":"workload","predecessor_epoch":0,"target_algorithm":"ECDSA-P384","policy_ref":"policy:reviewed"}`
	if err := os.WriteFile(workloadIntentPath, []byte(workloadIntent), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stderr := run("pcas", "succession", "approval", "prepare", "-f", workloadIntentPath, "--out", workloadPayloadPath); code != 0 {
		t.Fatalf("prepare workload approval: code=%d stderr=%s", code, stderr)
	}
	workloadPayload, err := os.ReadFile(workloadPayloadPath) // #nosec G304 -- test reads the output path under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	workloadSignature, err := crypto.SignEd25519(privatePEM, workloadPayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workloadSignaturePath, workloadSignature, 0o600); err != nil { // #nosec G703 -- test writes under t.TempDir
		t.Fatal(err)
	}
	if code, stderr := run("pcas", "succession", "approval", "assemble", "-f", workloadIntentPath,
		"--payload", workloadPayloadPath, "--signature", workloadSignaturePath,
		"--public-key", publicPath, "--out", workloadRequestPath); code != 0 {
		t.Fatalf("assemble workload approval: code=%d stderr=%s", code, stderr)
	}
	workloadBody, err := os.ReadFile(workloadRequestPath) // #nosec G304 -- test reads the output path under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	var workloadRequest struct {
		PredecessorCustody string          `json:"predecessor_custody"`
		Authorization      json.RawMessage `json:"authorization"`
	}
	if err := json.Unmarshal(workloadBody, &workloadRequest); err != nil {
		t.Fatal(err)
	}
	if workloadRequest.PredecessorCustody != "workload" {
		t.Fatalf("custody = %q", workloadRequest.PredecessorCustody)
	}
	pred, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	succ, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP384)
	if err != nil {
		t.Fatal(err)
	}
	agentSigner, err := agent.New(agent.Config{TenantID: tenant, IdentityID: identity,
		DeploymentScope: "spiffe://approval.example", Signer: pred,
		Approval: minter.NewSignedTokenAuthorizerForCustody(pubDER, succession.PredecessorCustodyWorkload)})
	if err != nil {
		t.Fatal(err)
	}
	fields := succession.CommitmentFields{TenantID: tenant, IdentityID: identity,
		DeploymentScope: "spiffe://approval.example", PredecessorEpoch: 0, Epoch: 1,
		PredecessorAlg: pred.Algorithm(), PredecessorPub: pred.Public().DER,
		SuccessorAlg: succ.Algorithm(), SuccessorPub: succ.Public().DER,
		PolicyRef: "policy:reviewed", HashAlg: succession.HashAlgSHA256,
		NotBefore: 1, NotAfter: 1000, CommitmentVersion: 2}
	if _, err := agentSigner.CoSign(agent.Request{Purpose: agent.Purpose, Fields: fields,
		Authorization: workloadRequest.Authorization}); err != nil {
		t.Fatalf("workload agent rejected CLI-built approval: %v", err)
	}
	if err := minter.NewSignedTokenAuthorizer(pubDER).VerifyAndConsume(workloadRequest.Authorization,
		minterRequest, minter.RequestParamsDigest(minterRequest)); err == nil {
		t.Fatal("signer-held verifier accepted a workload-held approval")
	}
}
