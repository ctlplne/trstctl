// SPDX-License-Identifier: MPL-2.0

package secretsync

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// HTTPDoer is the small seam concrete sync pushers use for real APIs and fixtures.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// GitHubActionsConfig configures a GitHub Actions secret sync destination.
// Values are sealed to GitHub's repository X25519 public key before they leave
// this process; operators should use narrowly scoped repository tokens.
type GitHubActionsConfig struct {
	Endpoint   string
	HTTPClient HTTPDoer
	Owner      string
	Repo       string
	Token      []byte
}

type GitHubActionsPusher struct {
	endpoint string
	doer     HTTPDoer
	owner    string
	repo     string
	token    *secret.Buffer
}

func NewGitHubActionsPusher(cfg GitHubActionsConfig) (*GitHubActionsPusher, error) {
	if cfg.Endpoint == "" || cfg.Owner == "" || cfg.Repo == "" {
		return nil, errors.New("secretsync: github endpoint, owner, and repo are required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = http.DefaultClient
	}
	token, err := lockOptionalSecret(cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("secretsync: lock github token: %w", err)
	}
	return &GitHubActionsPusher{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"),
		doer:     doer,
		owner:    cfg.Owner,
		repo:     cfg.Repo,
		token:    token,
	}, nil
}

func (p *GitHubActionsPusher) Push(ctx context.Context, key string, value []byte) error {
	publicKeyPath := "/repos/" + pathEscape(p.owner) + "/" + pathEscape(p.repo) + "/actions/secrets/public-key"
	keyReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+publicKeyPath, nil)
	if err != nil {
		return err
	}
	if token := secretBufferBytes(p.token); len(token) > 0 {
		keyReq.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	}
	var publicKey struct {
		KeyID string `json:"key_id"`
		Key   string `json:"key"`
	}
	if err := readJSON2xx(p.doer, keyReq, &publicKey); err != nil {
		return fmt.Errorf("secretsync: github repository public key: %w", err)
	}
	if publicKey.KeyID == "" || publicKey.Key == "" {
		return errors.New("secretsync: github returned an empty repository public key")
	}
	sealed, err := crypto.SealAnonymousCurve25519(publicKey.Key, value)
	if err != nil {
		return fmt.Errorf("secretsync: github seal secret: %w", err)
	}
	defer secret.Wipe(sealed)
	body, err := json.Marshal(struct {
		EncodedValue []byte `json:"encrypted_value"`
		KeyID        string `json:"key_id"`
	}{EncodedValue: sealed, KeyID: publicKey.KeyID})
	if err != nil {
		return err
	}
	defer secret.Wipe(body)
	path := "/repos/" + pathEscape(p.owner) + "/" + pathEscape(p.repo) + "/actions/secrets/" + pathEscape(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := secretBufferBytes(p.token); len(token) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	}
	return expect2xx(p.doer, req)
}

// Close destroys the retained repository token. Production constructs pushers
// per delivery, so this runs immediately after one external write.
func (p *GitHubActionsPusher) Close() { destroySecretBuffer(&p.token) }

// AWSSecretsManagerConfig configures an AWS Secrets Manager sync destination.
type AWSSecretsManagerConfig struct {
	Endpoint        string
	HTTPClient      HTTPDoer
	Region          string
	AccessKeyID     string
	SecretAccessKey []byte
	SessionToken    []byte
}

type AWSSecretsManagerPusher struct {
	endpoint     string
	host         string
	doer         HTTPDoer
	region       string
	accessKeyID  string
	secretKey    *secret.Buffer
	sessionToken *secret.Buffer
	now          func() time.Time
}

func NewAWSSecretsManagerPusher(cfg AWSSecretsManagerConfig) (*AWSSecretsManagerPusher, error) {
	if cfg.Endpoint == "" || cfg.Region == "" || cfg.AccessKeyID == "" || len(cfg.SecretAccessKey) == 0 {
		return nil, errors.New("secretsync: aws endpoint, region, access key id, and secret access key are required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = http.DefaultClient
	}
	secretKey, err := lockOptionalSecret(cfg.SecretAccessKey)
	if err != nil {
		return nil, fmt.Errorf("secretsync: lock aws secret access key: %w", err)
	}
	sessionToken, err := lockOptionalSecret(cfg.SessionToken)
	if err != nil {
		destroySecretBuffer(&secretKey)
		return nil, fmt.Errorf("secretsync: lock aws session token: %w", err)
	}
	p := &AWSSecretsManagerPusher{
		endpoint:     strings.TrimRight(cfg.Endpoint, "/"),
		doer:         doer,
		region:       cfg.Region,
		accessKeyID:  cfg.AccessKeyID,
		secretKey:    secretKey,
		sessionToken: sessionToken,
		now:          time.Now,
	}
	if u, err := url.Parse(cfg.Endpoint); err == nil {
		p.host = u.Host
	}
	return p, nil
}

func (p *AWSSecretsManagerPusher) Push(ctx context.Context, key string, value []byte) error {
	body, err := json.Marshal(struct {
		Name               string `json:"Name"`
		SecretBinary       []byte `json:"SecretBinary"`
		ClientRequestToken string `json:"ClientRequestToken,omitempty"`
	}{Name: key, SecretBinary: value, ClientRequestToken: operationIDFromContext(ctx)})
	if err != nil {
		return err
	}
	defer secret.Wipe(body)
	err = p.call(ctx, "secretsmanager.PutSecretValue", body)
	if !isAWSMissingSecret(err) {
		return err
	}
	// PutSecretValue updates an existing secret but cannot create the first
	// version. CreateSecret makes the target a real upsert instead of a fixture-
	// only write. A concurrent creator is handled by retrying the put.
	err = p.call(ctx, "secretsmanager.CreateSecret", body)
	if isAWSAlreadyExists(err) {
		return p.call(ctx, "secretsmanager.PutSecretValue", body)
	}
	return err
}

func (p *AWSSecretsManagerPusher) call(ctx context.Context, target string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	p.signV4(req, body, p.now().UTC())
	return expect2xx(p.doer, req)
}

func (p *AWSSecretsManagerPusher) Close() {
	destroySecretBuffer(&p.secretKey)
	destroySecretBuffer(&p.sessionToken)
}

func (p *AWSSecretsManagerPusher) signV4(req *http.Request, body []byte, t time.Time) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if session := secretBufferBytes(p.sessionToken); len(session) > 0 {
		req.Header.Set("X-Amz-Security-Token", secrettext.String(session))
	}
	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if p.sessionToken != nil && p.sessionToken.Len() > 0 {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)
	var canonHeaders strings.Builder
	for _, h := range signed {
		v := strings.TrimSpace(req.Header.Get(h))
		if h == "host" {
			v = p.host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	signedHeaders := strings.Join(signed, ";")
	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		"",
		canonHeaders.String(),
		signedHeaders,
		crypto.SHA256Hex(body),
	}, "\n")
	credScope := dateStamp + "/" + p.region + "/secretsmanager/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		crypto.SHA256Hex([]byte(canonicalRequest)),
	}, "\n")
	kSigning := awsSyncSigningKey(secretBufferBytes(p.secretKey), dateStamp, p.region, "secretsmanager")
	defer secret.Wipe(kSigning)
	signature := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 "+
		"Credential="+p.accessKeyID+"/"+credScope+", "+
		"SignedHeaders="+signedHeaders+", "+
		"Signature="+signature)
}

func awsSyncSigningKey(secretAccessKey []byte, dateStamp, region, service string) []byte {
	seed := make([]byte, 0, len("AWS4")+len(secretAccessKey))
	seed = append(seed, "AWS4"...)
	seed = append(seed, secretAccessKey...)
	kDate := crypto.HMACSHA256(seed, []byte(dateStamp))
	secret.Wipe(seed)
	kRegion := crypto.HMACSHA256(kDate, []byte(region))
	secret.Wipe(kDate)
	kService := crypto.HMACSHA256(kRegion, []byte(service))
	secret.Wipe(kRegion)
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	secret.Wipe(kService)
	return kSigning
}

// GCPSecretManagerConfig configures a GCP Secret Manager sync destination.
type GCPSecretManagerConfig struct {
	Endpoint    string
	HTTPClient  HTTPDoer
	Project     string
	BearerToken []byte
}

type GCPSecretManagerPusher struct {
	endpoint string
	doer     HTTPDoer
	project  string
	token    *secret.Buffer
}

func NewGCPSecretManagerPusher(cfg GCPSecretManagerConfig) (*GCPSecretManagerPusher, error) {
	if cfg.Endpoint == "" || cfg.Project == "" {
		return nil, errors.New("secretsync: gcp endpoint and project are required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = http.DefaultClient
	}
	token, err := lockOptionalSecret(cfg.BearerToken)
	if err != nil {
		return nil, fmt.Errorf("secretsync: lock gcp bearer token: %w", err)
	}
	return &GCPSecretManagerPusher{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"),
		doer:     doer,
		project:  cfg.Project,
		token:    token,
	}, nil
}

func (p *GCPSecretManagerPusher) Push(ctx context.Context, key string, value []byte) error {
	if operationIDFromContext(ctx) != "" {
		matches, err := p.latestMatches(ctx, key, value)
		if err != nil {
			return err
		}
		if matches {
			return nil
		}
	}
	body, err := json.Marshal(struct {
		Payload struct {
			Data []byte `json:"data"`
		} `json:"payload"`
	}{Payload: struct {
		Data []byte `json:"data"`
	}{Data: value}})
	if err != nil {
		return err
	}
	defer secret.Wipe(body)
	path := "/v1/projects/" + pathEscape(p.project) + "/secrets/" + pathEscape(key) + ":addVersion"
	err = p.send(ctx, http.MethodPost, path, body)
	if statusCode(err) != http.StatusNotFound {
		return err
	}
	// addVersion requires the Secret container to exist. Create it on first
	// delivery, tolerate a concurrent creator, then add the version.
	createBody := []byte(`{"replication":{"automatic":{}}}`)
	createPath := "/v1/projects/" + pathEscape(p.project) + "/secrets?secretId=" + url.QueryEscape(key)
	createErr := p.send(ctx, http.MethodPost, createPath, createBody)
	if createErr != nil {
		if statusCode(createErr) != http.StatusConflict {
			return createErr
		}
	}
	return p.send(ctx, http.MethodPost, path, body)
}

func (p *GCPSecretManagerPusher) latestMatches(ctx context.Context, key string, value []byte) (bool, error) {
	path := "/v1/projects/" + pathEscape(p.project) + "/secrets/" + pathEscape(key) + "/versions/latest:access"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+path, nil)
	if err != nil {
		return false, err
	}
	setBearer(req, secretBufferBytes(p.token))
	var out struct {
		Payload struct {
			Data secret.JSONBytes `json:"data"`
		} `json:"payload"`
	}
	err = readJSON2xx(p.doer, req, &out)
	if statusCode(err) == http.StatusNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// Closure: the field is nil until the response is decoded below, so a bare
	// defer would capture that nil and wipe nothing (AN-8).
	defer func() { secret.Wipe(out.Payload.Data) }()
	decoded, err := decodeBase64Secret(out.Payload.Data)
	if err != nil {
		return false, fmt.Errorf("secretsync: decode GCP latest secret: %w", err)
	}
	defer secret.Wipe(decoded)
	return crypto.ConstantTimeEqual(decoded, value), nil
}

func (p *GCPSecretManagerPusher) send(ctx context.Context, method, path string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, p.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	setBearer(req, secretBufferBytes(p.token))
	return expect2xx(p.doer, req)
}

func (p *GCPSecretManagerPusher) Close() { destroySecretBuffer(&p.token) }

// AzureKeyVaultConfig configures an Azure Key Vault secret sync destination.
type AzureKeyVaultConfig struct {
	Endpoint    string
	HTTPClient  HTTPDoer
	APIVersion  string
	BearerToken []byte
}

type AzureKeyVaultPusher struct {
	endpoint   string
	doer       HTTPDoer
	apiVersion string
	token      *secret.Buffer
}

func NewAzureKeyVaultPusher(cfg AzureKeyVaultConfig) (*AzureKeyVaultPusher, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("secretsync: azure key vault endpoint is required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = http.DefaultClient
	}
	apiVersion := strings.TrimSpace(cfg.APIVersion)
	if apiVersion == "" {
		apiVersion = "7.4"
	}
	token, err := lockOptionalSecret(cfg.BearerToken)
	if err != nil {
		return nil, fmt.Errorf("secretsync: lock azure bearer token: %w", err)
	}
	return &AzureKeyVaultPusher{
		endpoint:   strings.TrimRight(cfg.Endpoint, "/"),
		doer:       doer,
		apiVersion: apiVersion,
		token:      token,
	}, nil
}

func (p *AzureKeyVaultPusher) Push(ctx context.Context, key string, value []byte) error {
	if operationIDFromContext(ctx) != "" {
		matches, err := p.latestMatches(ctx, key, value)
		if err != nil {
			return err
		}
		if matches {
			return nil
		}
	}
	body, err := json.Marshal(struct {
		Value       []byte `json:"value"`
		ContentType string `json:"contentType"`
	}{Value: value, ContentType: "application/octet-stream;base64"})
	if err != nil {
		return err
	}
	defer secret.Wipe(body)
	path := "/secrets/" + pathEscape(key) + "?api-version=" + url.QueryEscape(p.apiVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	setBearer(req, secretBufferBytes(p.token))
	return expect2xx(p.doer, req)
}

func (p *AzureKeyVaultPusher) latestMatches(ctx context.Context, key string, value []byte) (bool, error) {
	path := "/secrets/" + pathEscape(key) + "?api-version=" + url.QueryEscape(p.apiVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+path, nil)
	if err != nil {
		return false, err
	}
	setBearer(req, secretBufferBytes(p.token))
	var out struct {
		Value secret.JSONBytes `json:"value"`
	}
	err = readJSON2xx(p.doer, req, &out)
	if statusCode(err) == http.StatusNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// Closure: the field is nil until the response is decoded below, so a bare
	// defer would capture that nil and wipe nothing (AN-8).
	defer func() { secret.Wipe(out.Value) }()
	decoded, err := decodeBase64Secret(out.Value)
	if err != nil {
		return false, fmt.Errorf("secretsync: decode Azure latest secret: %w", err)
	}
	defer secret.Wipe(decoded)
	return crypto.ConstantTimeEqual(decoded, value), nil
}

func (p *AzureKeyVaultPusher) Close() { destroySecretBuffer(&p.token) }

// GitLabCIConfig configures a GitLab project CI/CD variable sync destination.
type GitLabCIConfig struct {
	Endpoint         string
	HTTPClient       HTTPDoer
	ProjectID        string
	Token            []byte
	EnvironmentScope string
}

type GitLabCIPusher struct {
	endpoint         string
	doer             HTTPDoer
	projectID        string
	token            *secret.Buffer
	environmentScope string
}

func NewGitLabCIPusher(cfg GitLabCIConfig) (*GitLabCIPusher, error) {
	if cfg.Endpoint == "" || cfg.ProjectID == "" {
		return nil, errors.New("secretsync: gitlab endpoint and project id are required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = http.DefaultClient
	}
	scope := strings.TrimSpace(cfg.EnvironmentScope)
	if scope == "" {
		scope = "*"
	}
	token, err := lockOptionalSecret(cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("secretsync: lock gitlab token: %w", err)
	}
	return &GitLabCIPusher{
		endpoint:         strings.TrimRight(cfg.Endpoint, "/"),
		doer:             doer,
		projectID:        cfg.ProjectID,
		token:            token,
		environmentScope: scope,
	}, nil
}

func (p *GitLabCIPusher) Push(ctx context.Context, key string, value []byte) error {
	body := marshalGitLabVariable(key, value, p.environmentScope)
	defer secret.Wipe(body)
	collection := "/api/v4/projects/" + pathEscape(p.projectID) + "/variables"
	err := p.send(ctx, http.MethodPut, collection+"/"+pathEscape(key), body)
	if statusCode(err) != http.StatusNotFound {
		return err
	}
	return p.send(ctx, http.MethodPost, collection, body)
}

func (p *GitLabCIPusher) send(ctx context.Context, method, path string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, p.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := secretBufferBytes(p.token); len(token) > 0 {
		req.Header.Set("PRIVATE-TOKEN", secrettext.String(token))
	}
	return expect2xx(p.doer, req)
}

func (p *GitLabCIPusher) Close() { destroySecretBuffer(&p.token) }

// VercelConfig configures a Vercel project environment secret sync destination.
type VercelConfig struct {
	Endpoint   string
	HTTPClient HTTPDoer
	ProjectID  string
	TeamID     string
	Token      []byte
	Targets    []string
}

type VercelPusher struct {
	endpoint  string
	doer      HTTPDoer
	projectID string
	teamID    string
	token     *secret.Buffer
	targets   []string
}

func NewVercelPusher(cfg VercelConfig) (*VercelPusher, error) {
	if cfg.Endpoint == "" || cfg.ProjectID == "" {
		return nil, errors.New("secretsync: vercel endpoint and project id are required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = http.DefaultClient
	}
	targets := append([]string(nil), cfg.Targets...)
	if len(targets) == 0 {
		targets = []string{"production", "preview", "development"}
	}
	token, err := lockOptionalSecret(cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("secretsync: lock vercel token: %w", err)
	}
	return &VercelPusher{
		endpoint:  strings.TrimRight(cfg.Endpoint, "/"),
		doer:      doer,
		projectID: cfg.ProjectID,
		teamID:    strings.TrimSpace(cfg.TeamID),
		token:     token,
		targets:   targets,
	}, nil
}

func (p *VercelPusher) Push(ctx context.Context, key string, value []byte) error {
	body, err := marshalVercelEnvironmentVariable(key, value, p.targets)
	if err != nil {
		return err
	}
	defer secret.Wipe(body)
	path := "/v10/projects/" + pathEscape(p.projectID) + "/env"
	if p.teamID != "" {
		path += "?teamId=" + url.QueryEscape(p.teamID)
	}
	err = p.send(ctx, http.MethodPost, path, body)
	if statusCode(err) != http.StatusConflict {
		return err
	}
	remoteID, lookupErr := p.lookupEnvironmentVariable(ctx, key)
	if lookupErr != nil {
		return lookupErr
	}
	patchPath := "/v9/projects/" + pathEscape(p.projectID) + "/env/" + pathEscape(remoteID)
	if p.teamID != "" {
		patchPath += "?teamId=" + url.QueryEscape(p.teamID)
	}
	return p.send(ctx, http.MethodPatch, patchPath, body)
}

func (p *VercelPusher) send(ctx context.Context, method, path string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, p.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	setBearer(req, secretBufferBytes(p.token))
	return expect2xx(p.doer, req)
}

func (p *VercelPusher) lookupEnvironmentVariable(ctx context.Context, key string) (string, error) {
	path := "/v9/projects/" + pathEscape(p.projectID) + "/env"
	if p.teamID != "" {
		path += "?teamId=" + url.QueryEscape(p.teamID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+path, nil)
	if err != nil {
		return "", err
	}
	setBearer(req, secretBufferBytes(p.token))
	var response struct {
		Envs []struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"envs"`
	}
	if err := readJSON2xx(p.doer, req, &response); err != nil {
		return "", err
	}
	for _, item := range response.Envs {
		if item.Key == key && item.ID != "" {
			return item.ID, nil
		}
	}
	return "", fmt.Errorf("secretsync: vercel environment variable %q was not returned after conflict", key)
}

func (p *VercelPusher) Close() { destroySecretBuffer(&p.token) }

// CIPusherConfig configures a generic CI/CD secret sync endpoint.
type CIPusherConfig struct {
	Endpoint    string
	HTTPClient  HTTPDoer
	BearerToken []byte
	Provider    string
}

type CIPusher struct {
	inner *JSONPusher
}

func NewCIPusher(cfg CIPusherConfig) (*CIPusher, error) {
	provider := strings.TrimSpace(cfg.Provider)
	if provider == "" {
		provider = "ci"
	}
	inner, err := NewJSONPusher(JSONPusherConfig{
		Endpoint: cfg.Endpoint, HTTPClient: cfg.HTTPClient, BearerToken: cfg.BearerToken, Provider: provider,
	})
	if err != nil {
		return nil, err
	}
	return &CIPusher{inner: inner}, nil
}

func (p *CIPusher) Push(ctx context.Context, key string, value []byte) error {
	return p.inner.Push(ctx, key, value)
}

func (p *CIPusher) Close() { p.inner.Close() }

// KubernetesConfig configures a Kubernetes Secret sync destination.
type KubernetesConfig struct {
	Endpoint    string
	HTTPClient  HTTPDoer
	Namespace   string
	BearerToken []byte
}

type KubernetesPusher struct {
	endpoint  string
	doer      HTTPDoer
	namespace string
	token     *secret.Buffer
}

func NewKubernetesPusher(cfg KubernetesConfig) (*KubernetesPusher, error) {
	if cfg.Endpoint == "" || cfg.Namespace == "" {
		return nil, errors.New("secretsync: kubernetes endpoint and namespace are required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = http.DefaultClient
	}
	token, err := lockOptionalSecret(cfg.BearerToken)
	if err != nil {
		return nil, fmt.Errorf("secretsync: lock kubernetes bearer token: %w", err)
	}
	return &KubernetesPusher{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"), doer: doer, namespace: cfg.Namespace, token: token,
	}, nil
}

func (p *KubernetesPusher) Push(ctx context.Context, key string, value []byte) error {
	collection := "/api/v1/namespaces/" + pathEscape(p.namespace) + "/secrets"
	resource := collection + "/" + pathEscape(key)
	resourceVersion := ""
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+resource, nil)
	if err != nil {
		return err
	}
	if token := secretBufferBytes(p.token); len(token) > 0 {
		getReq.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	}
	var existing struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	getErr := readJSON2xx(p.doer, getReq, &existing)
	if getErr != nil && statusCode(getErr) != http.StatusNotFound {
		return getErr
	}
	if getErr == nil {
		resourceVersion = existing.Metadata.ResourceVersion
		if resourceVersion == "" {
			return errors.New("secretsync: kubernetes returned a Secret without resourceVersion")
		}
	}
	metadata := map[string]string{"name": key, "namespace": p.namespace}
	if resourceVersion != "" {
		metadata["resourceVersion"] = resourceVersion
	}
	body, err := json.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   metadata,
		"type":       "Opaque",
		"data":       map[string][]byte{"value": value},
	})
	if err != nil {
		return err
	}
	defer secret.Wipe(body)
	method, path := http.MethodPost, collection
	if resourceVersion != "" {
		method, path = http.MethodPut, resource
	}
	req, err := http.NewRequestWithContext(ctx, method, p.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := secretBufferBytes(p.token); len(token) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	}
	return expect2xx(p.doer, req)
}

func (p *KubernetesPusher) Close() { destroySecretBuffer(&p.token) }

type JSONPusherConfig struct {
	Endpoint    string
	HTTPClient  HTTPDoer
	BearerToken []byte
	Provider    string
}

type JSONPusher struct {
	endpoint string
	doer     HTTPDoer
	token    *secret.Buffer
	provider string
}

func NewJSONPusher(cfg JSONPusherConfig) (*JSONPusher, error) {
	if cfg.Endpoint == "" || cfg.Provider == "" {
		return nil, errors.New("secretsync: json pusher endpoint and provider are required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = http.DefaultClient
	}
	token, err := lockOptionalSecret(cfg.BearerToken)
	if err != nil {
		return nil, fmt.Errorf("secretsync: lock generic CI bearer token: %w", err)
	}
	return &JSONPusher{endpoint: strings.TrimRight(cfg.Endpoint, "/"), doer: doer, token: token, provider: cfg.Provider}, nil
}

func (p *JSONPusher) Push(ctx context.Context, key string, value []byte) error {
	body, err := json.Marshal(struct {
		Provider     string `json:"provider"`
		Key          string `json:"key"`
		EncodedValue []byte `json:"encoded_value"`
	}{Provider: p.provider, Key: key, EncodedValue: value})
	if err != nil {
		return err
	}
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/secrets", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := secretBufferBytes(p.token); len(token) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	}
	return expect2xx(p.doer, req)
}

func (p *JSONPusher) Close() { destroySecretBuffer(&p.token) }

func marshalGitLabVariable(key string, value []byte, scope string) []byte {
	var out []byte
	out = append(out, `{"key":`...)
	out = appendJSONValueBytes(out, []byte(key))
	out = append(out, `,"value":`...)
	out = appendJSONValueBytes(out, value)
	out = append(out, `,"variable_type":"env_var","masked":true,"protected":false,"raw":true,"environment_scope":`...)
	out = appendJSONValueBytes(out, []byte(scope))
	return append(out, '}')
}

func marshalVercelEnvironmentVariable(key string, value []byte, targets []string) ([]byte, error) {
	encodedTargets, err := json.Marshal(targets)
	if err != nil {
		return nil, err
	}
	var out []byte
	out = append(out, `{"key":`...)
	out = appendJSONValueBytes(out, []byte(key))
	out = append(out, `,"value":`...)
	out = appendJSONValueBytes(out, value)
	out = append(out, `,"type":"encrypted","target":`...)
	out = append(out, encodedTargets...)
	return append(out, '}'), nil
}

// appendJSONValueBytes writes a JSON string without converting secret bytes to
// an immutable Go string. GitLab and Vercel require plaintext JSON string fields
// on their vendor wire contracts, so the request body itself is wiped by callers.
func appendJSONValueBytes(dst, src []byte) []byte {
	dst = append(dst, '"')
	const hexDigits = "0123456789abcdef"
	for _, value := range src {
		switch value {
		case '"', '\\':
			dst = append(dst, '\\', value)
		case '\b':
			dst = append(dst, `\b`...)
		case '\f':
			dst = append(dst, `\f`...)
		case '\n':
			dst = append(dst, `\n`...)
		case '\r':
			dst = append(dst, `\r`...)
		case '\t':
			dst = append(dst, `\t`...)
		default:
			if value < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[value>>4], hexDigits[value&0xf])
			} else {
				dst = append(dst, value)
			}
		}
	}
	return append(dst, '"')
}

func lockOptionalSecret(value []byte) (*secret.Buffer, error) {
	if len(value) == 0 {
		return nil, nil
	}
	return secret.NewFrom(value)
}

func secretBufferBytes(value *secret.Buffer) []byte {
	if value == nil {
		return nil
	}
	return value.Bytes()
}

func destroySecretBuffer(value **secret.Buffer) {
	if value == nil || *value == nil {
		return
	}
	(*value).Destroy()
	*value = nil
}

func setBearer(req *http.Request, token []byte) {
	if len(token) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	}
}

type responseStatusError struct {
	code int
	kind responseStatusKind
}

type responseStatusKind uint8

const (
	responseStatusGeneric responseStatusKind = iota
	responseStatusAWSMissing
	responseStatusAWSAlreadyExists
)

func (e *responseStatusError) Error() string {
	return fmt.Sprintf("returned HTTP %d", e.code)
}

func statusCode(err error) int {
	var status *responseStatusError
	if errors.As(err, &status) {
		return status.code
	}
	return 0
}

func isAWSMissingSecret(err error) bool {
	var status *responseStatusError
	return errors.As(err, &status) && status.kind == responseStatusAWSMissing
}

func isAWSAlreadyExists(err error) bool {
	var status *responseStatusError
	return errors.As(err, &status) && status.kind == responseStatusAWSAlreadyExists
}

func readJSON2xx(doer HTTPDoer, req *http.Request, out any) error {
	if operationID := operationIDFromContext(req.Context()); operationID != "" {
		req.Header.Set("Idempotency-Key", operationID)
	}
	resp, err := doer.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := secret.ReadBounded(resp.Body, cloudhttp.MaxBodyBytes)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		kind := responseStatusGeneric
		if bytes.Contains(raw, []byte("ResourceNotFoundException")) {
			kind = responseStatusAWSMissing
		} else if bytes.Contains(raw, []byte("ResourceExistsException")) {
			kind = responseStatusAWSAlreadyExists
		}
		secret.Wipe(raw)
		// A receiver may echo the submitted secret. Retain only a closed status
		// classification and destroy the response bytes before returning (AN-8).
		return &responseStatusError{code: resp.StatusCode, kind: kind}
	}
	defer secret.Wipe(raw)
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("secretsync: decode %s %s response: %w", req.Method, req.URL.Path, err)
		}
	}
	return nil
}

func decodeBase64Secret(encoded []byte) ([]byte, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(decoded, encoded)
	if err != nil {
		secret.Wipe(decoded)
		return nil, err
	}
	return decoded[:n], nil
}

func expect2xx(doer HTTPDoer, req *http.Request) error {
	return readJSON2xx(doer, req, nil)
}

func pathEscape(v string) string { return url.PathEscape(v) }
