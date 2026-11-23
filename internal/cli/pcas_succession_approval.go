// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/minter"
)

// The CLI prepares the exact bytes an independent quorum authority signs. It
// never reads that authority's private key. The signer, not the CLI, consumes
// the token after validating its signature and request binding.
type pcasApprovalIntent struct {
	TenantID           string  `json:"tenant_id"`
	IdentityID         string  `json:"identity_id"`
	CredentialType     string  `json:"credential_type"`
	DeploymentScope    string  `json:"deployment_scope"`
	PredecessorEpoch   *uint64 `json:"predecessor_epoch"`
	TargetAlgorithm    string  `json:"target_algorithm"`
	PolicyRef          string  `json:"policy_ref"`
	DelegationScope    string  `json:"delegation_scope,omitempty"`
	PredecessorCustody string  `json:"predecessor_custody,omitempty"`
}

func pcasSuccessionApprovalUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl pcas succession approval prepare -f intent.json --out payload.json")
	_, _ = fmt.Fprintln(w, "       trstctl pcas succession approval assemble -f intent.json --payload payload.json --signature signature.bin --public-key authority.pem --out request.json")
	_, _ = fmt.Fprintln(w, "Prepare the exact request-bound payload for an independent Ed25519 approval authority; assemble verifies its detached signature and writes the body for 'pcas succession request -f'. The authority private key never enters trstctl.")
}

func pcasSuccessionApprovalModeUsage(w io.Writer, mode string) {
	if mode == "prepare" {
		_, _ = fmt.Fprintln(w, "Usage: trstctl pcas succession approval prepare -f intent.json --out payload.json")
		_, _ = fmt.Fprintln(w, "Example: trstctl pcas succession approval prepare -f reviewed-intent.json --out exact-payload.json")
		return
	}
	_, _ = fmt.Fprintln(w, "Usage: trstctl pcas succession approval assemble -f intent.json --payload payload.json --signature signature.bin --public-key authority.pem --out request.json")
	_, _ = fmt.Fprintln(w, "Example: trstctl pcas succession approval assemble -f reviewed-intent.json --payload exact-payload.json --signature approval.bin --public-key authority.pem --out request.json")
}

func runPCASSuccessionApproval(args []string, tenant string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		pcasSuccessionApprovalUsage(stderr)
		return 2
	}
	mode := args[0]
	if mode == "prepare" || mode == "assemble" {
		for _, arg := range args[1:] {
			if arg == "--help" || arg == "-h" {
				pcasSuccessionApprovalModeUsage(stdout, mode)
				return 0
			}
		}
	}
	fs := flag.NewFlagSet("pcas succession approval "+mode, flag.ContinueOnError)
	fs.SetOutput(stderr)
	intentPath := fs.String("f", "", "reviewed succession intent JSON")
	outPath := fs.String("out", "", "new output file")
	var payloadPath, signaturePath, publicPath *string
	if mode == "assemble" {
		payloadPath = fs.String("payload", "", "prepared exact payload file")
		signaturePath = fs.String("signature", "", "detached Ed25519 signature bytes")
		publicPath = fs.String("public-key", "", "authority public key PEM")
	} else if mode != "prepare" {
		pcasSuccessionApprovalUsage(stderr)
		return 2
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			pcasSuccessionApprovalModeUsage(stdout, mode)
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *intentPath == "" || *outPath == "" ||
		(mode == "assemble" && (*payloadPath == "" || *signaturePath == "" || *publicPath == "")) {
		pcasSuccessionApprovalUsage(stderr)
		return 2
	}
	intent, req, err := readPCASApprovalIntent(*intentPath, tenant)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pcas approval: %v\n", err)
		return 1
	}
	var output []byte
	if mode == "prepare" {
		nonce, err := crypto.RandomBytes(24)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "pcas approval: nonce: %v\n", err)
			return 1
		}
		output, err = json.Marshal(minter.AuthorizationToken{
			IdentityID: intent.IdentityID, TenantID: intent.TenantID,
			PredecessorCustody:       intent.PredecessorCustody,
			AssertedPredecessorEpoch: *intent.PredecessorEpoch,
			TargetAlgorithm:          req.TargetAlgorithm, ParamsDigest: minter.RequestParamsDigest(req),
			Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		})
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "pcas approval: encode payload: %v\n", err)
			return 1
		}
	} else {
		output, err = assemblePCASSuccessionRequest(intent, req, *payloadPath, *signaturePath, *publicPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "pcas approval: %v\n", err)
			return 1
		}
	}
	if err := writeNewPCASApprovalFile(*outPath, output); err != nil {
		_, _ = fmt.Fprintf(stderr, "pcas approval: write output: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s\n", *outPath)
	return 0
}

func readPCASApprovalIntent(path, tenant string) (pcasApprovalIntent, signing.MintRequest, error) {
	raw, err := readPCASApprovalFile(path, 64<<10)
	if err != nil {
		return pcasApprovalIntent{}, signing.MintRequest{}, err
	}
	var intent pcasApprovalIntent
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return intent, signing.MintRequest{}, fmt.Errorf("decode intent: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return intent, signing.MintRequest{}, errors.New("intent contains trailing JSON")
	}
	if intent.TenantID == "" || intent.IdentityID == "" || intent.DeploymentScope == "" ||
		intent.TargetAlgorithm == "" || intent.PolicyRef == "" || intent.PredecessorEpoch == nil ||
		!map[string]bool{"x509": true, "ssh": true, "workload-svid": true, "api-token": true, "secret": true}[intent.CredentialType] {
		return intent, signing.MintRequest{}, errors.New("intent requires tenant_id, identity_id, credential_type, deployment_scope, predecessor_epoch, target_algorithm and policy_ref")
	}
	if tenant != "" && tenant != intent.TenantID {
		return intent, signing.MintRequest{}, errors.New("intent tenant_id differs from CLI tenant")
	}
	custody := strings.TrimSpace(intent.PredecessorCustody)
	if custody != succession.PredecessorCustodySigner && custody != succession.PredecessorCustodyWorkload {
		return intent, signing.MintRequest{}, errors.New("intent must explicitly confirm predecessor_custody=signer or workload")
	}
	if custody == succession.PredecessorCustodyWorkload && intent.DelegationScope != "" {
		return intent, signing.MintRequest{}, errors.New("workload-held first succession does not support delegation_scope")
	}
	req := signing.MintRequest{
		IdentityID: intent.IdentityID, TenantID: intent.TenantID,
		DeploymentScope:          intent.DeploymentScope,
		PredecessorHandle:        succession.TenantKeyHandle(intent.TenantID, intent.IdentityID, *intent.PredecessorEpoch),
		AssertedPredecessorEpoch: *intent.PredecessorEpoch,
		TargetAlgorithm:          crypto.Algorithm(intent.TargetAlgorithm), PolicyRef: intent.PolicyRef,
		DelegationScope: intent.DelegationScope,
	}
	return intent, req, nil
}

func assemblePCASSuccessionRequest(intent pcasApprovalIntent, req signing.MintRequest, payloadPath, signaturePath, publicPath string) ([]byte, error) {
	payload, err := readPCASApprovalFile(payloadPath, 64<<10)
	if err != nil {
		return nil, err
	}
	var token minter.AuthorizationToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	canonical, err := json.Marshal(token)
	if err != nil || !bytes.Equal(payload, canonical) || token.Nonce == "" ||
		token.IdentityID != req.IdentityID || token.TenantID != req.TenantID ||
		token.PredecessorCustody != intent.PredecessorCustody ||
		token.AssertedPredecessorEpoch != req.AssertedPredecessorEpoch ||
		token.TargetAlgorithm != req.TargetAlgorithm ||
		!bytes.Equal(token.ParamsDigest, minter.RequestParamsDigest(req)) {
		return nil, errors.New("approval payload differs from reviewed request parameters")
	}
	signature, err := readPCASApprovalFile(signaturePath, 1<<10)
	if err != nil {
		return nil, err
	}
	publicPEM, err := readPCASApprovalFile(publicPath, 16<<10)
	if err != nil {
		return nil, err
	}
	publicDER, err := crypto.ParseEd25519PublicKeyPEM(publicPEM)
	if err != nil {
		return nil, fmt.Errorf("approval public key: %w", err)
	}
	if err := crypto.VerifyEd25519(publicDER, payload, signature); err != nil {
		return nil, fmt.Errorf("approval signature: %w", err)
	}
	body := struct {
		IdentityID         string `json:"identity_id"`
		CredentialType     string `json:"credential_type"`
		TargetAlgorithm    string `json:"target_algorithm"`
		PolicyRef          string `json:"policy_ref"`
		DeploymentScope    string `json:"deployment_scope"`
		PredecessorCustody string `json:"predecessor_custody"`
		DelegationScope    string `json:"delegation_scope,omitempty"`
		Authorization      struct {
			Payload json.RawMessage `json:"payload"`
			Sig     []byte          `json:"sig"`
		} `json:"authorization"`
	}{IdentityID: intent.IdentityID, CredentialType: intent.CredentialType,
		TargetAlgorithm: intent.TargetAlgorithm, PolicyRef: intent.PolicyRef,
		DeploymentScope: intent.DeploymentScope, PredecessorCustody: intent.PredecessorCustody,
		DelegationScope: intent.DelegationScope}
	body.Authorization.Payload, body.Authorization.Sig = payload, signature
	return json.Marshal(body)
}

func readPCASApprovalFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-selected local public artifact (CWE-22)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("approval input must be a nonempty regular file within its size limit")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("approval input grew beyond its size limit")
	}
	return raw, nil
}

func writeNewPCASApprovalFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-selected create-new output (CWE-22)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err = f.Write(data); err != nil {
		_ = os.Remove(path)
		return err
	}
	return f.Sync()
}
