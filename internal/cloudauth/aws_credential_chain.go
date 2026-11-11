// SPDX-License-Identifier: BUSL-1.1

package cloudauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// AWS credential sources for a process that holds no static key (A200-L1).
const (
	AWSSourceWebIdentity      = "web_identity"
	AWSSourceContainer        = "container"
	AWSSourceInstanceMetadata = "instance_metadata"
	AWSSourceDefaultChain     = "default_chain"
)

// AWS's link-local credential endpoints: the ECS container credentials host a
// relative URI is read from, and the EC2 instance metadata service.
const (
	AWSContainerCredentialsHost = "http://169.254.170.2" // #nosec G101 -- a link-local endpoint address, not a credential (CWE-798)
	AWSInstanceMetadataEndpoint = "http://169.254.169.254"
)

const (
	awsDefaultRoleSessionName = "trstctl"
	// awsMetadataTimeout bounds one metadata request. The services answer
	// on the host or node itself, so a slow answer means none is there.
	awsMetadataTimeout = 5 * time.Second
	// imdsSessionTTLSeconds is the life of the IMDSv2 session token; one
	// resolution uses it for two reads.
	imdsSessionTTLSeconds = "60"
)

// AWSCredentialChain resolves temporary AWS credentials for a process that
// holds no static key, the way the AWS SDKs' default chain does (A200-L1): a
// web identity token (IRSA on EKS) exchanged at STS, then container
// credentials (an ECS task role or EKS Pod Identity), then the EC2 instance
// metadata service over IMDSv2 (an instance role). Each source reads the
// environment variables the AWS SDKs read, and the fields override them.
// Nothing is cached: a one-shot process resolves once, a long-lived one
// wraps Resolve in a Minter.
type AWSCredentialChain struct {
	// Source is one of the AWSSource* names; default_chain tries web
	// identity, container credentials and instance metadata in that order.
	Source string
	// Getenv reads the process environment (os.Getenv in production).
	Getenv func(string) string
	// RoleARN, WebIdentityTokenFile and RoleSessionName override
	// AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_SESSION_NAME.
	RoleARN              string
	WebIdentityTokenFile string
	RoleSessionName      string
	// STSEndpoint is where a web identity token is exchanged (the regional
	// STS endpoint); STSDoer is the egress-guarded client that reaches it.
	STSEndpoint string
	STSDoer     cloudhttp.Doer
	// MetadataDoer returns the client for one link-local metadata endpoint
	// (netsec.CloudMetadataClient in production).
	MetadataDoer func(endpoint string) (cloudhttp.Doer, error)
	// Now is the clock the credentials' expiry is checked against.
	Now func() time.Time
}

// AWSRegionalSTSEndpoint is the regional STS endpoint for region; the China
// regions use the amazonaws.com.cn domain.
func AWSRegionalSTSEndpoint(region string) string {
	region = strings.TrimSpace(region)
	domain := "amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		domain = "amazonaws.com.cn"
	}
	return "https://sts." + region + "." + domain + "/"
}

// Resolve returns temporary credentials and the source that answered. The
// caller wipes Material.Primary (the secret access key) and
// Material.Secondary (the session token).
func (c AWSCredentialChain) Resolve(ctx context.Context) (Material, string, error) {
	getenv := c.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	source := strings.ToLower(strings.TrimSpace(c.Source))
	if source == AWSSourceDefaultChain {
		switch {
		case c.webIdentityConfigured(getenv):
			source = AWSSourceWebIdentity
		case awsContainerConfigured(getenv):
			source = AWSSourceContainer
		case awsMetadataDisabled(getenv):
			return Material{}, "", errors.New("cloudauth: no AWS credential source: no web identity token or container credentials are configured, and AWS_EC2_METADATA_DISABLED turns off the instance metadata service")
		default:
			source = AWSSourceInstanceMetadata
		}
	}
	var (
		material Material
		err      error
	)
	switch source {
	case AWSSourceWebIdentity:
		material, err = c.webIdentity(ctx, getenv)
	case AWSSourceContainer:
		material, err = c.container(ctx, getenv)
	case AWSSourceInstanceMetadata:
		if awsMetadataDisabled(getenv) {
			return Material{}, source, errors.New("cloudauth: AWS_EC2_METADATA_DISABLED turns off the instance metadata service")
		}
		material, err = c.instanceMetadata(ctx, getenv)
	default:
		return Material{}, "", fmt.Errorf("cloudauth: unknown AWS credential source %q", c.Source)
	}
	if err != nil {
		return Material{}, source, err
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	if !material.ExpiresAt.After(now()) {
		secret.Wipe(material.Primary)
		secret.Wipe(material.Secondary)
		return Material{}, source, fmt.Errorf("cloudauth: the AWS %s credentials have expired", strings.ReplaceAll(source, "_", " "))
	}
	return material, source, nil
}

func (c AWSCredentialChain) webIdentityConfigured(getenv func(string) string) bool {
	return firstNonBlank(c.RoleARN, getenv("AWS_ROLE_ARN")) != "" &&
		firstNonBlank(c.WebIdentityTokenFile, getenv("AWS_WEB_IDENTITY_TOKEN_FILE")) != ""
}

func awsContainerConfigured(getenv func(string) string) bool {
	return strings.TrimSpace(getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")) != "" ||
		strings.TrimSpace(getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")) != ""
}

func awsMetadataDisabled(getenv func(string) string) bool {
	return strings.EqualFold(strings.TrimSpace(getenv("AWS_EC2_METADATA_DISABLED")), "true")
}

// webIdentity exchanges the platform's projected token (IRSA's service
// account token) for the role's credentials at STS.
func (c AWSCredentialChain) webIdentity(ctx context.Context, getenv func(string) string) (Material, error) {
	roleARN := firstNonBlank(c.RoleARN, getenv("AWS_ROLE_ARN"))
	tokenFile := firstNonBlank(c.WebIdentityTokenFile, getenv("AWS_WEB_IDENTITY_TOKEN_FILE"))
	if roleARN == "" || tokenFile == "" {
		return Material{}, errors.New("cloudauth: AWS web identity needs a role ARN and a token file (role_arn and web_identity_token_file, or AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE)")
	}
	if strings.TrimSpace(c.STSEndpoint) == "" || c.STSDoer == nil {
		return Material{}, errors.New("cloudauth: AWS web identity needs an STS endpoint and a reviewed client")
	}
	raw, err := os.ReadFile(tokenFile) // #nosec G304 -- operator- or platform-configured projected token path (CWE-22)
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: read the AWS web identity token file: %w", err)
	}
	defer secret.Wipe(raw)
	token := bytes.TrimSpace(raw)
	if len(token) == 0 {
		return Material{}, errors.New("cloudauth: the AWS web identity token file is empty")
	}
	return ExchangeAWSWebIdentity(ctx, c.STSDoer, AWSExchangeRequest{
		Endpoint:         c.STSEndpoint,
		RoleARN:          roleARN,
		RoleSessionName:  firstNonBlank(c.RoleSessionName, getenv("AWS_ROLE_SESSION_NAME"), awsDefaultRoleSessionName),
		WebIdentityToken: token,
	})
}

// container reads an ECS task role's or an EKS Pod Identity association's
// credentials from the endpoint the platform names.
func (c AWSCredentialChain) container(ctx context.Context, getenv func(string) string) (Material, error) {
	endpoint := strings.TrimSpace(getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"))
	if relative := strings.TrimSpace(getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")); relative != "" {
		if !strings.HasPrefix(relative, "/") {
			return Material{}, errors.New("cloudauth: AWS_CONTAINER_CREDENTIALS_RELATIVE_URI must be a path")
		}
		endpoint = AWSContainerCredentialsHost + relative
	}
	if endpoint == "" {
		return Material{}, errors.New("cloudauth: AWS container credentials need AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or AWS_CONTAINER_CREDENTIALS_FULL_URI")
	}
	doer, err := c.metadataDoer(endpoint)
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: AWS container credentials endpoint: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: build the AWS container credentials request: %w", err)
	}
	authorization, wipe, err := awsContainerAuthorization(getenv)
	if err != nil {
		return Material{}, err
	}
	defer wipe()
	if len(authorization) > 0 {
		req.Header.Set("Authorization", string(authorization))
	}
	raw, err := cloudhttp.Bytes(doer, req, cloudhttp.WithTimeout(awsMetadataTimeout))
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: AWS container credentials: %w", err)
	}
	defer secret.Wipe(raw)
	return parseAWSMetadataCredentials(raw, "container credentials")
}

// awsContainerAuthorization is the token EKS Pod Identity (or an ECS agent
// that asks for one) expects in the Authorization header, preferring the
// file the platform rotates over the variable.
func awsContainerAuthorization(getenv func(string) string) ([]byte, func(), error) {
	if file := strings.TrimSpace(getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")); file != "" {
		raw, err := os.ReadFile(file) // #nosec G304 -- platform-configured Pod Identity token path (CWE-22)
		if err != nil {
			return nil, func() {}, fmt.Errorf("cloudauth: read AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE: %w", err)
		}
		token := bytes.TrimSpace(raw)
		if len(token) == 0 {
			secret.Wipe(raw)
			return nil, func() {}, errors.New("cloudauth: the AWS container authorization token file is empty")
		}
		return token, func() { secret.Wipe(raw) }, nil
	}
	if token := strings.TrimSpace(getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")); token != "" {
		return []byte(token), func() {}, nil
	}
	return nil, func() {}, nil
}

// instanceMetadata reads the instance role's credentials over IMDSv2: a
// session token first, then the role's name, then its credentials, each
// read carrying the session token.
func (c AWSCredentialChain) instanceMetadata(ctx context.Context, getenv func(string) string) (Material, error) {
	base := strings.TrimRight(firstNonBlank(getenv("AWS_EC2_METADATA_SERVICE_ENDPOINT"), AWSInstanceMetadataEndpoint), "/")
	doer, err := c.metadataDoer(base)
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: AWS instance metadata endpoint: %w", err)
	}
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/latest/api/token", nil)
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: build the AWS instance metadata session request: %w", err)
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", imdsSessionTTLSeconds)
	sessionRaw, err := cloudhttp.Bytes(doer, tokenReq, cloudhttp.WithTimeout(awsMetadataTimeout))
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: AWS instance metadata session token (IMDSv2; a container on EC2 needs a hop limit of 2): %w", err)
	}
	defer secret.Wipe(sessionRaw)
	session := string(bytes.TrimSpace(sessionRaw))
	if session == "" {
		return Material{}, errors.New("cloudauth: AWS instance metadata returned an empty session token")
	}
	get := func(path string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-aws-ec2-metadata-token", session)
		return cloudhttp.Bytes(doer, req, cloudhttp.WithTimeout(awsMetadataTimeout))
	}
	roles, err := get("/latest/meta-data/iam/security-credentials/")
	if err != nil {
		var status *cloudhttp.StatusError
		if errors.As(err, &status) && status.StatusCode == http.StatusNotFound {
			return Material{}, errors.New("cloudauth: the instance has no IAM role (instance profile) attached")
		}
		return Material{}, fmt.Errorf("cloudauth: AWS instance metadata role: %w", err)
	}
	role, _, _ := strings.Cut(strings.TrimSpace(string(roles)), "\n")
	role = strings.TrimSpace(role)
	if !validIAMRoleName(role) {
		return Material{}, errors.New("cloudauth: AWS instance metadata returned no usable role name")
	}
	raw, err := get("/latest/meta-data/iam/security-credentials/" + role)
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: AWS instance metadata credentials: %w", err)
	}
	defer secret.Wipe(raw)
	return parseAWSMetadataCredentials(raw, "instance metadata")
}

func (c AWSCredentialChain) metadataDoer(endpoint string) (cloudhttp.Doer, error) {
	if c.MetadataDoer == nil {
		return nil, errors.New("a reviewed metadata client is required")
	}
	return c.MetadataDoer(endpoint)
}

// validIAMRoleName accepts an IAM role name: 1 to 64 of letters, digits and
// +=,.@_- (so it is safe as one path segment).
func validIAMRoleName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("+=,.@_-", r):
		default:
			return false
		}
	}
	return true
}

type awsMetadataCredentials struct {
	Code            string     `json:"Code"`
	AccessKeyID     string     `json:"AccessKeyId"`
	SecretAccessKey secretText `json:"SecretAccessKey"`
	Token           secretText `json:"Token"`
	Expiration      string     `json:"Expiration"`
}

// parseAWSMetadataCredentials reads the JSON the instance metadata service,
// the ECS credentials endpoint and the Pod Identity agent all answer with.
func parseAWSMetadataCredentials(raw []byte, what string) (Material, error) {
	var decoded awsMetadataCredentials
	err := json.Unmarshal(raw, &decoded)
	defer secret.Wipe(decoded.SecretAccessKey)
	defer secret.Wipe(decoded.Token)
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: AWS %s returned malformed JSON", what)
	}
	if decoded.Code != "" && decoded.Code != "Success" {
		return Material{}, fmt.Errorf("cloudauth: AWS %s did not answer Success", what)
	}
	expiresAt, err := time.Parse(time.RFC3339, decoded.Expiration)
	if err != nil {
		return Material{}, fmt.Errorf("cloudauth: AWS %s returned an invalid expiration", what)
	}
	if decoded.AccessKeyID == "" || len(decoded.SecretAccessKey) == 0 || len(decoded.Token) == 0 {
		return Material{}, fmt.Errorf("cloudauth: AWS %s returned incomplete credentials", what)
	}
	return Material{
		Identifier: decoded.AccessKeyID,
		Primary:    append([]byte(nil), decoded.SecretAccessKey...),
		Secondary:  append([]byte(nil), decoded.Token...),
		ExpiresAt:  expiresAt.UTC(),
	}, nil
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
