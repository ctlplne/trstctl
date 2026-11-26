// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"trstctl.com/trstctl/internal/authmethod"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// CR-214: an EKS-signed proof has no trstctl server-ID header and a previously
// accepted trstctl proof cannot be used to mint another session.

const (
	v2nd25Account  = "123456789012"
	v2nd25KeyID    = "ASIAV2ND25WORKLOAD01"
	v2nd25Secret   = "v2nd25-fixture-session-signing-value" // #nosec G101 -- fabricated local SigV4 test signing input, never a live AWS credential (CWE-798)
	v2nd25Token    = "fixture123"                           // #nosec G101 -- fabricated local session-token fixture, never a live AWS credential (CWE-798)
	v2nd25Region   = "us-east-1"
	v2nd25ServerID = "trstctl.v2nd25.example.test"
)

func v2nd25Creds() aws.Credentials {
	return aws.Credentials{AccessKeyID: v2nd25KeyID, SecretAccessKey: v2nd25Secret, SessionToken: v2nd25Token}
}

// v2nd25STS stands in for STS GetCallerIdentity as AWS serves it: the request
// must carry a valid SigV4 signature (Authorization header or presigned query)
// by a known identity, over every header it lists as signed, dated within
// STS's 15-minute window. STS gives no meaning to extra signed headers (EKS's
// x-k8s-aws-id) and keeps no record of requests it answered. The signature is
// recomputed with the AWS SDK's own SigV4 signer (aws-sdk-go-v2 v1.42.0).
type v2nd25STS struct {
	*httptest.Server
	mu       sync.Mutex
	answered int
	refused  []string
}

var v2nd25SignerParams = map[string]bool{"X-Amz-Algorithm": true, "X-Amz-Credential": true, "X-Amz-Date": true,
	"X-Amz-SignedHeaders": true, "X-Amz-Security-Token": true, "X-Amz-Signature": true}

func (s *v2nd25STS) verify(r *http.Request, body []byte) string {
	q := r.URL.Query()
	presigned := q.Get("X-Amz-Signature") != ""
	var credential, signedHeaders, signature, date, token string
	if presigned {
		credential, signedHeaders, signature = q.Get("X-Amz-Credential"), q.Get("X-Amz-SignedHeaders"), q.Get("X-Amz-Signature")
		date, token = q.Get("X-Amz-Date"), q.Get("X-Amz-Security-Token")
	} else {
		for _, part := range strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 "), ",") {
			k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
			switch k {
			case "Credential":
				credential = v
			case "SignedHeaders":
				signedHeaders = v
			case "Signature":
				signature = v
			}
		}
		date, token = r.Header.Get("X-Amz-Date"), r.Header.Get("X-Amz-Security-Token")
	}
	scope := strings.Split(credential, "/")
	if len(scope) != 5 || scope[0] != v2nd25KeyID || scope[3] != "sts" || token != v2nd25Token {
		return "InvalidClientTokenId"
	}
	when, err := time.Parse("20060102T150405Z", date)
	if err != nil || time.Since(when) > 15*time.Minute || time.Until(when) > 15*time.Minute {
		return "SignatureDoesNotMatch(expired)"
	}
	keep := url.Values{}
	for k, v := range q {
		if !v2nd25SignerParams[k] {
			keep[k] = v
		}
	}
	target := "http://" + r.Host + "/"
	if len(keep) > 0 {
		target += "?" + keep.Encode()
	}
	re, err := http.NewRequest(r.Method, target, bytes.NewReader(body)) // #nosec G704 -- test-only re-signing inside a local httptest handler; this request is never sent (CWE-918)
	if err != nil {
		return "MalformedQueryString"
	}
	for _, name := range strings.Split(signedHeaders, ";") {
		if name != "host" && name != "content-length" {
			re.Header[http.CanonicalHeaderKey(name)] = r.Header.Values(name)
		}
	}
	signer := v4.NewSigner()
	payload := crypto.SHA256Hex(body)
	if presigned {
		signedURL, _, err := signer.PresignHTTP(context.Background(), v2nd25Creds(), re, payload, "sts", scope[2], when)
		if err != nil {
			return "SignatureDoesNotMatch"
		}
		u, err := url.Parse(signedURL)
		if err != nil || u.Query().Get("X-Amz-Signature") != signature || u.Query().Get("X-Amz-SignedHeaders") != signedHeaders {
			return "SignatureDoesNotMatch"
		}
		return ""
	}
	if err := signer.SignHTTP(context.Background(), v2nd25Creds(), re, payload, "sts", scope[2], when); err != nil || re.Header.Get("Authorization") != r.Header.Get("Authorization") {
		return "SignatureDoesNotMatch"
	}
	return ""
}

func newV2ND25STS(t *testing.T) *v2nd25STS {
	t.Helper()
	s := &v2nd25STS{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		action := r.URL.Query().Get("Action")
		if form, err := url.ParseQuery(string(body)); err == nil && form.Get("Action") != "" {
			action = form.Get("Action")
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		code := s.verify(r, body)
		if code == "" && action != "GetCallerIdentity" {
			code = "InvalidAction"
		}
		if code != "" {
			s.refused = append(s.refused, code)
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code></Error></ErrorResponse>`, code) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
			return
		}
		s.answered++
		_, _ = fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::%s:assumed-role/payments-api/i-0v2nd25</Arn><UserId>AROAV2ND25PAYMENTS:i-0v2nd25</UserId><Account>%s</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`,
			v2nd25Account, v2nd25Account) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
	}))
	t.Cleanup(s.Close)
	return s
}

// v2nd25EKSToken is what `aws eks get-token` / aws-iam-authenticator hands a
// Kubernetes API server: "k8s-aws-v1." + base64url of a presigned GET
// sts:GetCallerIdentity URL whose signed headers include x-k8s-aws-id.
func v2nd25EKSToken(t *testing.T, endpoint, cluster string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, endpoint+"/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Expires=60", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("x-k8s-aws-id", cluster)
	signedURL, _, err := v4.NewSigner().PresignHTTP(context.Background(), v2nd25Creds(), req, crypto.SHA256Hex(nil), "sts", v2nd25Region, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return "k8s-aws-v1." + base64.RawURLEncoding.EncodeToString([]byte(signedURL))
}

// v2nd25FromEKSToken is what the receiving side (the cluster's authenticator,
// or anything that sees the bearer token) can submit to trstctl: the decoded
// presigned URL plus the cluster name it already knows.
func v2nd25FromEKSToken(t *testing.T, token, cluster string) authmethod.AWSSignedGetCallerIdentityRequest {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "k8s-aws-v1."))
	if err != nil {
		t.Fatal(err)
	}
	return authmethod.AWSSignedGetCallerIdentityRequest{Method: http.MethodGet, URL: string(raw), Headers: map[string][]string{"x-k8s-aws-id": {cluster}}}
}

// v2nd25OwnLoginCredential is the workload's own aws-iam login credential as
// the docs describe it: a header-signed POST sts:GetCallerIdentity.
func v2nd25OwnLoginCredential(t *testing.T, endpoint string) authmethod.AWSSignedGetCallerIdentityRequest {
	t.Helper()
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	req, err := http.NewRequest(http.MethodPost, endpoint+"/", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set(authmethod.AWSIAMServerIDHeader, v2nd25ServerID)
	if err := v4.NewSigner().SignHTTP(context.Background(), v2nd25Creds(), req, crypto.SHA256Hex([]byte(body)), "sts", v2nd25Region, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	headers := map[string][]string{}
	for _, k := range []string{"Authorization", "Content-Type", "X-Amz-Date", "X-Amz-Security-Token", authmethod.AWSIAMServerIDHeader} {
		headers[k] = []string{req.Header.Get(k)}
	}
	return authmethod.AWSSignedGetCallerIdentityRequest{Method: http.MethodPost, URL: endpoint + "/", Headers: headers, Body: body}
}

func v2nd25OwnPresignedCredential(t *testing.T, endpoint string) authmethod.AWSSignedGetCallerIdentityRequest {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, endpoint+"/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Expires=60", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(authmethod.AWSIAMServerIDHeader, v2nd25ServerID)
	signedURL, _, err := v4.NewSigner().PresignHTTP(context.Background(), v2nd25Creds(), req, crypto.SHA256Hex(nil), "sts", v2nd25Region, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return authmethod.AWSSignedGetCallerIdentityRequest{
		Method: http.MethodGet, URL: signedURL,
		Headers: map[string][]string{authmethod.AWSIAMServerIDHeader: {v2nd25ServerID}},
	}
}

type v2nd25LoginResult struct {
	status    int
	sessionID string
	principal string
	scopes    []string
}

func v2nd25Login(t *testing.T, h *servedHarness, idemKey string, credential authmethod.AWSSignedGetCallerIdentityRequest) v2nd25LoginResult {
	t.Helper()
	cred, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"method": "aws-iam", "credential": string(cred)})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/login", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", h.tenant)
	req.Header.Set("Idempotency-Key", idemKey)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	var sess struct {
		SessionID string   `json:"session_id"`
		Principal string   `json:"principal"`
		Scopes    []string `json:"scopes"`
	}
	_ = json.Unmarshal(data, &sess)
	return v2nd25LoginResult{status: resp.StatusCode, sessionID: sess.SessionID, principal: sess.Principal, scopes: sess.Scopes}
}

// VH27-N1 / V2ND-25: the aws-iam login, configured the production way
// (machineAuthMethodsFromConfig + the replay-guard wrapper as run.go:838, the
// real HTTPSignedSTSClient against the stand-in endpoint), must refuse (1) a
// signed GetCallerIdentity made for another relying party — here an EKS
// token, which binds the cluster (x-k8s-aws-id) and not trstctl — and (2) a
// second login with a credential that already logged in once (as every
// JWT-family method does). Controls prove the stand-in checks signatures and
// signed headers, and that the workload's own credential logs in.
func TestServedAWSIAMLoginBindsAudienceAndRefusesReplayV2ND25(t *testing.T) {
	sts := newV2ND25STS(t)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		methods, err := machineAuthMethodsFromConfig([]config.MachineAuthMethod{{
			Name: "aws-iam", TenantID: servedTestTenant, STSEndpoint: sts.URL, ServerID: v2nd25ServerID,
			AllowedAccounts: []string{v2nd25Account}, Scopes: []string{"secrets:read"},
		}})
		if err != nil {
			t.Fatalf("aws-iam machine login config: %v", err)
		}
		d.MachineAuthMethods = withMachineCredentialReplayGuardLimit(methods, d.Store, 0)
	})

	const cluster = "prod-eks"
	eks := v2nd25FromEKSToken(t, v2nd25EKSToken(t, sts.URL, cluster), cluster)

	// Control 1: a forged signature is refused (the stand-in verifies SigV4).
	forged := eks
	u, err := url.Parse(forged.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	sig := []byte(q.Get("X-Amz-Signature"))
	sig[len(sig)-1] = map[bool]byte{true: '1', false: '0'}[sig[len(sig)-1] == '0']
	q.Set("X-Amz-Signature", string(sig))
	u.RawQuery = q.Encode()
	forged.URL = u.String()
	if got := v2nd25Login(t, h, "v2nd25-forged", forged); got.status == http.StatusOK {
		t.Fatalf("control: a forged signature logged in (stand-in does not verify)")
	}
	// Control 2: dropping the signed x-k8s-aws-id header breaks the signature
	// (STS binds every signed header, so the cluster name must be sent).
	stripped := eks
	stripped.Headers = nil
	if got := v2nd25Login(t, h, "v2nd25-stripped", stripped); got.status == http.StatusOK {
		t.Fatalf("control: the EKS request without its signed header logged in (stand-in does not bind signed headers)")
	}
	// Control 3: the workload's own trstctl login credential logs in.
	own := v2nd25OwnLoginCredential(t, sts.URL)
	first := v2nd25Login(t, h, "v2nd25-own-1", own)
	if first.status != http.StatusOK {
		t.Fatalf("control: the workload's own aws-iam credential: HTTP %d (stand-in or signing path broken)", first.status)
	}
	presigned := v2nd25OwnPresignedCredential(t, sts.URL)
	if got := v2nd25Login(t, h, "v2nd25-own-presigned-1", presigned); got.status != http.StatusOK {
		t.Fatalf("server-bound presigned GET proof = %d, want 200", got.status)
	}
	if got := v2nd25Login(t, h, "v2nd25-own-presigned-2", presigned); got.status == http.StatusOK {
		t.Fatal("the same server-bound presigned proof minted a second session")
	}

	var problems []string
	// Claim 1 (audience): the EKS token's request was signed for the cluster.
	if got := v2nd25Login(t, h, "v2nd25-eks", eks); got.status == http.StatusOK {
		problems = append(problems, fmt.Sprintf("audience: an EKS token's presigned GetCallerIdentity (signed for x-k8s-aws-id=%s, no trstctl binding) logged in: HTTP 200 principal=%s scopes=%v session=%t",
			cluster, got.principal, got.scopes, got.sessionID != ""))
	}
	// Claim 2 (replay): the same signed login credential, captured once, logs in again.
	if again := v2nd25Login(t, h, "v2nd25-own-2", own); again.status == http.StatusOK {
		problems = append(problems, fmt.Sprintf("replay: the identical signed credential logged in a second time: HTTP 200 principal=%s, a second session (distinct session id: %t)",
			again.principal, again.sessionID != "" && again.sessionID != first.sessionID))
	}
	sts.mu.Lock()
	answered, refused := sts.answered, append([]string(nil), sts.refused...)
	sts.mu.Unlock()
	if len(problems) > 0 {
		t.Fatalf("VH27-N1: %s (STS answered %d, refused %v)", strings.Join(problems, "; "), answered, refused)
	}
	t.Logf("V2ND25_AUDIENCE_AND_REPLAY_REFUSED answered=%d refused=%v", answered, refused)
}
