// SPDX-License-Identifier: BUSL-1.1

package wrapadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Stand-in values the stubs answer with; none is a credential.
const (
	chainKeyID      = "stand-in-chain-key-id"
	chainSecret     = "stand-in-chain-secret-access-key" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	chainToken      = "stand-in-chain-session-token"     // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	chainIMDS       = "stand-in-imds-session"            // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	chainProjected  = "stand-in-projected-service-account-token"
	chainRoleARN    = "arn:aws:iam::111122223333:role/trstctl-kms-wrap"
	chainRoleName   = "trstctl-kms-wrap-instance"
	chainKMSKeyRef  = "arn:aws:kms:us-east-1:111122223333:key/0b1c2d3e-aaaa-bbbb-cccc-000000000001"
	chainExpiration = "2099-01-01T00:00:00Z"
)

// invokeEnv runs the adapter as the signer does, with env as its environment.
func invokeEnv(t *testing.T, env map[string]string, input []byte, args ...string) ([]byte, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, func(name string) string { return env[name] }, bytes.NewReader(input), &stdout, &stderr)
	return stdout.Bytes(), stderr.String(), code
}

// signedBy records the access key that signed each KMS request and the
// session token it carried.
type signedBy struct {
	mu     sync.Mutex
	keyIDs []string
	tokens []string
}

func (s *signedBy) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, credential, _ := strings.Cut(r.Header.Get("Authorization"), "Credential=")
		keyID, _, _ := strings.Cut(credential, "/")
		s.mu.Lock()
		s.keyIDs = append(s.keyIDs, keyID)
		s.tokens = append(s.tokens, r.Header.Get("X-Amz-Security-Token"))
		s.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (s *signedBy) seen() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.keyIDs), slices.Clone(s.tokens)
}

// newIMDSStub answers as the EC2 instance metadata service does with IMDSv2
// required, and records the calls.
func newIMDSStub(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var (
		mu    sync.Mutex
		calls []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" && r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") != "" {
			_, _ = io.WriteString(w, chainIMDS)
			return
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != chainIMDS {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/latest/meta-data/iam/security-credentials/":
			_, _ = io.WriteString(w, chainRoleName)
		case "/latest/meta-data/iam/security-credentials/" + chainRoleName:
			_ = json.NewEncoder(w).Encode(map[string]string{"Code": "Success", "AccessKeyId": chainKeyID,
				"SecretAccessKey": chainSecret, "Token": chainToken, "Expiration": chainExpiration})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(calls)
	}
}

// newSTSStub answers AssumeRoleWithWebIdentity as STS does, for the role and
// projected token these tests use.
func newSTSStub(t *testing.T) (*httptest.Server, func() []url.Values) {
	t.Helper()
	var (
		mu    sync.Mutex
		forms []url.Values
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		mu.Lock()
		forms = append(forms, r.PostForm)
		mu.Unlock()
		if r.PostForm.Get("Action") != "AssumeRoleWithWebIdentity" || r.PostForm.Get("RoleArn") != chainRoleARN ||
			r.PostForm.Get("WebIdentityToken") != chainProjected {
			http.Error(w, "<ErrorResponse/>", http.StatusForbidden)
			return
		}
		_, _ = fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>`+
			`<AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken>`+
			`<Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`,
			chainKeyID, chainSecret, chainToken, chainExpiration)
	}))
	t.Cleanup(server.Close)
	return server, func() []url.Values {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(forms)
	}
}

func wrapAndUnwrap(t *testing.T, env map[string]string) {
	t.Helper()
	wrapped, stderr, code := invokeEnv(t, env, dataKey, "wrap", "awskms", chainKMSKeyRef)
	if code != ExitOK || !bytes.HasPrefix(wrapped, []byte("TKW1A")) {
		t.Fatalf("wrap = %d (%s)", code, stderr)
	}
	plain, stderr, code := invokeEnv(t, env, wrapped, "unwrap", "awskms", chainKMSKeyRef)
	if code != ExitOK || !bytes.Equal(plain, dataKey) {
		t.Fatalf("unwrap = %d (%s)", code, stderr)
	}
}

func assertSignedByChain(t *testing.T, signed *signedBy, requests int) {
	t.Helper()
	keyIDs, tokens := signed.seen()
	if len(keyIDs) != requests {
		t.Fatalf("KMS saw %d requests, want %d", len(keyIDs), requests)
	}
	for i := range keyIDs {
		if keyIDs[i] != chainKeyID || tokens[i] != chainToken {
			t.Fatalf("KMS request %d was signed by %q with session token %t; want the chain's temporary credentials", i, keyIDs[i], tokens[i] == chainToken)
		}
	}
}

// A200-L1 Done when: with no static key, the adapter resolves the AWS
// default chain's credentials — here an EC2 instance role read over IMDSv2
// from a stub metadata endpoint — and KMS sees Encrypt and Decrypt signed
// with those temporary credentials and carrying their session token.
func TestAWSWrapsWithAnInstanceRoleFromTheDefaultChainA200L1(t *testing.T) {
	imds, calls := newIMDSStub(t)
	signed := &signedBy{}
	kms := httptest.NewServer(signed.wrap(&awsDouble{}))
	defer kms.Close()
	config := writeConfig(t, map[string]any{"aws": map[string]any{
		"endpoint": kms.URL, "allow_insecure_loopback": true, "credential_source": "default_chain",
	}})
	wrapAndUnwrap(t, map[string]string{ConfigEnv: config, "AWS_EC2_METADATA_SERVICE_ENDPOINT": imds.URL})
	assertSignedByChain(t, signed, 2)
	one := []string{"PUT /latest/api/token", "GET /latest/meta-data/iam/security-credentials/", "GET /latest/meta-data/iam/security-credentials/" + chainRoleName}
	if got := calls(); !slices.Equal(got, append(slices.Clone(one), one...)) {
		t.Fatalf("metadata calls = %v, want IMDSv2's three per run", got)
	}
}

// A200-L1: on EKS with IRSA the adapter exchanges the projected service
// account token at STS — named in the configuration, or by the
// AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE the EKS webhook injects —
// and signs KMS requests with the role's credentials.
func TestAWSWrapsWithAnIRSAWebIdentityA200L1(t *testing.T) {
	sts, forms := newSTSStub(t)
	signed := &signedBy{}
	kms := httptest.NewServer(signed.wrap(&awsDouble{}))
	defer kms.Close()
	tokenFile := writeFile(t, t.TempDir(), "token", chainProjected+"\n")

	configured := writeConfig(t, map[string]any{"aws": map[string]any{
		"endpoint": kms.URL, "allow_insecure_loopback": true, "credential_source": "web_identity",
		"role_arn": chainRoleARN, "web_identity_token_file": tokenFile, "role_session_name": "signer-a",
		"sts_endpoint": sts.URL,
	}})
	wrapAndUnwrap(t, map[string]string{ConfigEnv: configured})
	assertSignedByChain(t, signed, 2)
	if got := forms(); len(got) != 2 || got[0].Get("RoleSessionName") != "signer-a" {
		t.Fatalf("STS exchanges = %d (session %v), want one per run named signer-a", len(got), got)
	}

	injected := writeConfig(t, map[string]any{"aws": map[string]any{
		"endpoint": kms.URL, "allow_insecure_loopback": true, "credential_source": "default_chain", "sts_endpoint": sts.URL,
	}})
	wrapAndUnwrap(t, map[string]string{ConfigEnv: injected, "AWS_ROLE_ARN": chainRoleARN, "AWS_WEB_IDENTITY_TOKEN_FILE": tokenFile})
	assertSignedByChain(t, signed, 4)
	if got := forms(); len(got) != 4 || got[3].Get("RoleSessionName") != "trstctl" {
		t.Fatalf("STS exchanges = %d, want four with the default session name for the injected run", len(got))
	}
}

// A200-L1: what the adapter refuses about a credential source, before any
// KMS request: mixed static and chain settings and unknown sources are
// usage errors; a chain that finds no credentials fails the operation.
func TestAWSCredentialSourceRefusalsA200L1(t *testing.T) {
	keyFile := writeFile(t, t.TempDir(), "aws-key", "example-secret\n")
	for _, c := range []struct {
		name   string
		aws    map[string]any
		env    map[string]string
		code   int
		reason string
	}{
		{"chain with a static key", map[string]any{"credential_source": "instance_metadata", "access_key_id": "AKIAEXAMPLE", "secret_access_key_file": keyFile}, nil, ExitUsage, "reads no access_key_id"},
		{"unknown source", map[string]any{"credential_source": "shared_config"}, nil, ExitUsage, "credential_source must be"}, // #nosec G101 -- a credential source name, not a credential (CWE-798)
		{"web identity fields on a static key", map[string]any{"access_key_id": "AKIAEXAMPLE", "secret_access_key_file": keyFile, "role_arn": chainRoleARN}, nil, ExitUsage, "need credential_source web_identity or default_chain"},
		{"web identity fields on instance metadata", map[string]any{"credential_source": "instance_metadata", "role_arn": chainRoleARN}, nil, ExitUsage, "need credential_source web_identity or default_chain"},
		{"no static key and no source", map[string]any{}, nil, ExitUsage, "or set credential_source"},
		{"metadata disabled", map[string]any{"credential_source": "default_chain"}, map[string]string{"AWS_EC2_METADATA_DISABLED": "true"}, ExitFailed, "AWS_EC2_METADATA_DISABLED"},
		{"metadata elsewhere", map[string]any{"credential_source": "instance_metadata"}, map[string]string{"AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://10.1.2.3"}, ExitFailed, "not a cloud metadata or loopback address"},
	} {
		t.Run(c.name, func(t *testing.T) {
			env := map[string]string{ConfigEnv: writeConfig(t, map[string]any{"aws": c.aws})}
			for k, v := range c.env {
				env[k] = v
			}
			_, stderr, code := invokeEnv(t, env, dataKey, "wrap", "awskms", chainKMSKeyRef)
			if code != c.code || !strings.Contains(stderr, c.reason) {
				t.Fatalf("exit %d, stderr %q; want %d mentioning %q", code, stderr, c.code, c.reason)
			}
		})
	}
}
