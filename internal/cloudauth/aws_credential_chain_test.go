// SPDX-License-Identifier: BUSL-1.1

package cloudauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/netsec"
)

// Stand-in values the stubs answer with; none is a credential.
const (
	chainKeyID         = "stand-in-chain-key-id"
	chainSecret        = "stand-in-chain-secret-access-key" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	chainSessionToken  = "stand-in-chain-session-token"     // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	chainIMDSSession   = "stand-in-imds-session"            // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	chainPodIdentity   = "stand-in-pod-identity-token"      // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	chainWebIdentity   = "stand-in-projected-service-account-token"
	chainRoleARN       = "arn:aws:iam::111122223333:role/trstctl-kms"
	chainInstanceRole  = "trstctl-kms-instance"
	chainLaterExpiry   = "2099-01-01T00:00:00Z"
	chainEarlierExpiry = "2001-01-01T00:00:00Z"
)

// metadataDoer is the production metadata client builder.
func metadataDoer(endpoint string) (cloudhttp.Doer, error) {
	return netsec.CloudMetadataClient(endpoint, 2*time.Second)
}

func envOf(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

// imdsStub answers as the EC2 instance metadata service does with IMDSv2
// required: a session token on PUT, and every read refused without it.
type imdsStub struct {
	*httptest.Server
	mu         sync.Mutex
	calls      []string
	role       string
	expiration string
	code       string
}

func newIMDSStub(t *testing.T, role, expiration string) *imdsStub {
	t.Helper()
	s := &imdsStub{role: role, expiration: expiration, code: "Success"}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.calls = append(s.calls, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
			if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
				http.Error(w, "missing ttl", http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, chainIMDSSession)
			return
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != chainIMDSSession {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			if s.role == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, s.role+"\n")
		case r.Method == http.MethodGet && s.role != "" && r.URL.Path == "/latest/meta-data/iam/security-credentials/"+s.role:
			_ = json.NewEncoder(w).Encode(map[string]string{
				"Code": s.code, "Type": "AWS-HMAC", "AccessKeyId": chainKeyID,
				"SecretAccessKey": chainSecret, "Token": chainSessionToken, "Expiration": s.expiration,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *imdsStub) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// stsStub answers AssumeRoleWithWebIdentity as STS does.
func newSTSStub(t *testing.T, forms *[]url.Values) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		mu.Lock()
		*forms = append(*forms, r.PostForm)
		mu.Unlock()
		if r.PostForm.Get("Action") != "AssumeRoleWithWebIdentity" || r.PostForm.Get("RoleArn") != chainRoleARN ||
			r.PostForm.Get("WebIdentityToken") != chainWebIdentity {
			http.Error(w, "<ErrorResponse/>", http.StatusForbidden)
			return
		}
		_, _ = fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>`+
			`<AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken>`+
			`<Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`,
			chainKeyID, chainSecret, chainSessionToken, chainLaterExpiry)
	}))
	t.Cleanup(server.Close)
	return server
}

// containerStub answers as the ECS credentials endpoint and the EKS Pod
// Identity agent do, recording the Authorization header it was sent.
func newContainerStub(t *testing.T, authorizations *[]string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*authorizations = append(*authorizations, r.Header.Get("Authorization"))
		mu.Unlock()
		if r.URL.Path != "/v1/credentials" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"AccessKeyId": chainKeyID, "SecretAccessKey": chainSecret, "Token": chainSessionToken,
			"AccountId": "111122223333", "Expiration": chainLaterExpiry,
		})
	}))
	t.Cleanup(server.Close)
	return server
}

func writeChainFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertChainMaterial(t *testing.T, got Material) {
	t.Helper()
	if got.Identifier != chainKeyID || string(got.Primary) != chainSecret || string(got.Secondary) != chainSessionToken {
		t.Fatalf("credentials = %q / %d secret bytes / %d token bytes, want the stub's", got.Identifier, len(got.Primary), len(got.Secondary))
	}
	if want, _ := time.Parse(time.RFC3339, chainLaterExpiry); !got.ExpiresAt.Equal(want) {
		t.Fatalf("expiry = %s, want %s", got.ExpiresAt, want)
	}
}

// A200-L1 Done when: with no static key and nothing else configured, the
// default chain reads an EC2 instance role's credentials over IMDSv2 from a
// stub metadata endpoint — a session token first, then the role, then its
// credentials, both reads carrying the session token.
func TestAWSCredentialChainReadsAnInstanceRoleOverIMDSv2A200L1(t *testing.T) {
	imds := newIMDSStub(t, chainInstanceRole, chainLaterExpiry)
	material, source, err := AWSCredentialChain{
		Source:       AWSSourceDefaultChain,
		Getenv:       envOf(map[string]string{"AWS_EC2_METADATA_SERVICE_ENDPOINT": imds.URL}),
		MetadataDoer: metadataDoer,
	}.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if source != AWSSourceInstanceMetadata {
		t.Fatalf("source = %q, want instance_metadata", source)
	}
	assertChainMaterial(t, material)
	want := []string{
		"PUT /latest/api/token",
		"GET /latest/meta-data/iam/security-credentials/",
		"GET /latest/meta-data/iam/security-credentials/" + chainInstanceRole,
	}
	if got := imds.seen(); !slices.Equal(got, want) {
		t.Fatalf("metadata calls = %v, want %v", got, want)
	}
}

// A200-L1: the default chain takes web identity (IRSA) first, then container
// credentials, the order the AWS SDKs use; the container source sends the
// Pod Identity token from its file and maps a relative URI onto the ECS
// credentials host.
func TestAWSCredentialChainOrderAndContainerCredentialsA200L1(t *testing.T) {
	var forms []url.Values
	sts := newSTSStub(t, &forms)
	var authorizations []string
	container := newContainerStub(t, &authorizations)
	imds := newIMDSStub(t, chainInstanceRole, chainLaterExpiry)
	tokenFile := writeChainFile(t, "token", chainWebIdentity+"\n")
	podToken := writeChainFile(t, "pod-identity-token", chainPodIdentity+"\n")
	env := map[string]string{
		"AWS_ROLE_ARN": chainRoleARN, "AWS_WEB_IDENTITY_TOKEN_FILE": tokenFile,
		"AWS_CONTAINER_CREDENTIALS_FULL_URI":     container.URL + "/v1/credentials",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": podToken,
		"AWS_EC2_METADATA_SERVICE_ENDPOINT":      imds.URL,
	}
	chain := AWSCredentialChain{
		Source: AWSSourceDefaultChain, Getenv: envOf(env), STSEndpoint: sts.URL,
		STSDoer: netsec.InsecureLoopbackClient(2 * time.Second), MetadataDoer: metadataDoer,
	}
	material, source, err := chain.Resolve(context.Background())
	if err != nil || source != AWSSourceWebIdentity {
		t.Fatalf("web identity first = %q %v", source, err)
	}
	assertChainMaterial(t, material)
	if len(forms) != 1 || len(authorizations) != 0 || len(imds.seen()) != 0 {
		t.Fatalf("STS forms %d, container calls %d, metadata calls %d; want only STS", len(forms), len(authorizations), len(imds.seen()))
	}
	if session := forms[0].Get("RoleSessionName"); session != "trstctl" {
		t.Fatalf("role session name = %q, want the default trstctl", session)
	}

	delete(env, "AWS_ROLE_ARN")
	material, source, err = chain.Resolve(context.Background())
	if err != nil || source != AWSSourceContainer {
		t.Fatalf("container second = %q %v", source, err)
	}
	assertChainMaterial(t, material)
	if !slices.Equal(authorizations, []string{chainPodIdentity}) || len(imds.seen()) != 0 {
		t.Fatalf("container Authorization = %q, metadata calls %d", authorizations, len(imds.seen()))
	}

	// A relative URI is read from the ECS credentials host.
	var requested []string
	relative := AWSCredentialChain{
		Source: AWSSourceContainer,
		Getenv: envOf(map[string]string{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/task-1"}),
		MetadataDoer: func(endpoint string) (cloudhttp.Doer, error) {
			requested = append(requested, endpoint)
			return doerFunc(func(r *http.Request) (*http.Response, error) {
				requested = append(requested, r.URL.String())
				body := fmt.Sprintf(`{"AccessKeyId":%q,"SecretAccessKey":%q,"Token":%q,"Expiration":%q}`, chainKeyID, chainSecret, chainSessionToken, chainLaterExpiry)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
			}), nil
		},
	}
	if material, _, err := relative.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	} else {
		assertChainMaterial(t, material)
	}
	want := "http://169.254.170.2/v2/credentials/task-1"
	if !slices.Equal(requested, []string{want, want}) {
		t.Fatalf("relative URI reached %v, want %s", requested, want)
	}
}

// A200-L1: what the chain refuses, each with a reason an operator can act on.
func TestAWSCredentialChainRefusalsA200L1(t *testing.T) {
	ctx := context.Background()
	noRole := newIMDSStub(t, "", chainLaterExpiry)
	expired := newIMDSStub(t, chainInstanceRole, chainEarlierExpiry)
	failed := newIMDSStub(t, chainInstanceRole, chainLaterExpiry)
	failed.code = "Failed"
	emptyToken := writeChainFile(t, "empty-token", "\n")
	cases := []struct {
		name  string
		chain AWSCredentialChain
		want  string
	}{
		{"metadata disabled", AWSCredentialChain{Source: AWSSourceDefaultChain, Getenv: envOf(map[string]string{"AWS_EC2_METADATA_DISABLED": "true"}), MetadataDoer: metadataDoer}, "AWS_EC2_METADATA_DISABLED"},
		{"instance metadata disabled", AWSCredentialChain{Source: AWSSourceInstanceMetadata, Getenv: envOf(map[string]string{"AWS_EC2_METADATA_DISABLED": "TRUE"}), MetadataDoer: metadataDoer}, "AWS_EC2_METADATA_DISABLED"},
		{"no instance role", AWSCredentialChain{Source: AWSSourceInstanceMetadata, Getenv: envOf(map[string]string{"AWS_EC2_METADATA_SERVICE_ENDPOINT": noRole.URL}), MetadataDoer: metadataDoer}, "no IAM role"},
		{"expired", AWSCredentialChain{Source: AWSSourceInstanceMetadata, Getenv: envOf(map[string]string{"AWS_EC2_METADATA_SERVICE_ENDPOINT": expired.URL}), MetadataDoer: metadataDoer}, "expired"},
		{"not success", AWSCredentialChain{Source: AWSSourceInstanceMetadata, Getenv: envOf(map[string]string{"AWS_EC2_METADATA_SERVICE_ENDPOINT": failed.URL}), MetadataDoer: metadataDoer}, "did not answer Success"},
		{"metadata elsewhere", AWSCredentialChain{Source: AWSSourceInstanceMetadata, Getenv: envOf(map[string]string{"AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://10.0.0.5"}), MetadataDoer: metadataDoer}, "not a cloud metadata or loopback address"},
		{"relative URI not a path", AWSCredentialChain{Source: AWSSourceContainer, Getenv: envOf(map[string]string{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "v2/credentials"}), MetadataDoer: metadataDoer}, "must be a path"},
		{"container unset", AWSCredentialChain{Source: AWSSourceContainer, MetadataDoer: metadataDoer}, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"},
		{"web identity without a role", AWSCredentialChain{Source: AWSSourceWebIdentity, WebIdentityTokenFile: emptyToken, STSEndpoint: "https://sts.us-east-1.amazonaws.com/", STSDoer: netsec.SafeClient(time.Second)}, "needs a role ARN"},
		{"empty web identity token", AWSCredentialChain{Source: AWSSourceWebIdentity, RoleARN: chainRoleARN, WebIdentityTokenFile: emptyToken, STSEndpoint: "https://sts.us-east-1.amazonaws.com/", STSDoer: netsec.SafeClient(time.Second)}, "token file is empty"},
		{"unknown source", AWSCredentialChain{Source: "shared_config"}, "unknown AWS credential source"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			material, _, err := tc.chain.Resolve(ctx)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Resolve = %v, want an error naming %q", err, tc.want)
			}
			if material.Identifier != "" || material.Primary != nil || material.Secondary != nil {
				t.Fatal("a refused resolution returned credentials")
			}
			for _, leaked := range []string{chainSecret, chainSessionToken, chainIMDSSession} {
				if strings.Contains(err.Error(), leaked) {
					t.Fatalf("the error carries a credential: %v", err)
				}
			}
		})
	}
}

// A200-L1: the regional STS endpoint, with China's domain.
func TestAWSRegionalSTSEndpointA200L1(t *testing.T) {
	for region, want := range map[string]string{
		"us-east-1":     "https://sts.us-east-1.amazonaws.com/",
		"eu-west-2":     "https://sts.eu-west-2.amazonaws.com/",
		"cn-north-1":    "https://sts.cn-north-1.amazonaws.com.cn/",
		"us-gov-west-1": "https://sts.us-gov-west-1.amazonaws.com/",
	} {
		if got := AWSRegionalSTSEndpoint(region); got != want {
			t.Errorf("AWSRegionalSTSEndpoint(%q) = %q, want %q", region, got, want)
		}
	}
}
