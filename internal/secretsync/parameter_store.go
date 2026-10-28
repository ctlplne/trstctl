// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

// AWSParameterStoreConfig configures an AWS Systems Manager Parameter Store
// destination (A202): each secret becomes a SecureString parameter.
type AWSParameterStoreConfig struct {
	Endpoint        string
	HTTPClient      HTTPDoer
	Region          string
	AccessKeyID     string
	SecretAccessKey []byte
	SessionToken    []byte
	// PathPrefix places parameters at /<path_prefix>/<key>; empty is /<key>.
	PathPrefix string
	// KMSKeyID encrypts the SecureString under that key; empty is the
	// account's AWS-managed key for SSM.
	KMSKeyID string
}

// AWSParameterStorePusher writes SecureString parameters with PutParameter.
type AWSParameterStorePusher struct {
	endpoint     string
	host         string
	doer         HTTPDoer
	region       string
	accessKeyID  string
	secretKey    *secret.Buffer
	sessionToken *secret.Buffer
	prefix       string
	kmsKeyID     string
	now          func() time.Time
}

func NewAWSParameterStorePusher(cfg AWSParameterStoreConfig) (*AWSParameterStorePusher, error) {
	if cfg.Endpoint == "" || cfg.Region == "" || cfg.AccessKeyID == "" || len(cfg.SecretAccessKey) == 0 {
		return nil, errors.New("secretsync: parameter store endpoint, region, access key id, and secret access key are required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = netsec.HardenedClient(30 * time.Second)
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
	p := &AWSParameterStorePusher{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"), doer: doer, region: cfg.Region,
		accessKeyID: cfg.AccessKeyID, secretKey: secretKey, sessionToken: sessionToken,
		prefix: strings.Trim(strings.TrimSpace(cfg.PathPrefix), "/"), kmsKeyID: strings.TrimSpace(cfg.KMSKeyID), now: time.Now,
	}
	if u, err := url.Parse(cfg.Endpoint); err == nil {
		p.host = u.Host
	}
	return p, nil
}

// ParameterName is the hierarchical parameter a key lands at.
func (p *AWSParameterStorePusher) ParameterName(key string) string {
	key = strings.Trim(strings.TrimSpace(key), "/")
	if p.prefix == "" {
		return "/" + key
	}
	return "/" + p.prefix + "/" + key
}

// Push writes the value as the parameter's next version (Overwrite), as a
// SecureString. Parameter values are text, so the secret must be UTF-8.
func (p *AWSParameterStorePusher) Push(ctx context.Context, key string, value []byte) error {
	if strings.Trim(strings.TrimSpace(key), "/") == "" {
		return errors.New("secretsync: parameter store key is required")
	}
	if !utf8.Valid(value) {
		return errors.New("secretsync: parameter store values are text; the secret must be UTF-8")
	}
	var body []byte
	body = append(body, `{"Name":`...)
	body = appendJSONValueBytes(body, []byte(p.ParameterName(key)))
	body = append(body, `,"Value":`...)
	body = appendJSONValueBytes(body, value)
	body = append(body, `,"Type":"SecureString","Overwrite":true`...)
	if p.kmsKeyID != "" {
		body = append(body, `,"KeyId":`...)
		body = appendJSONValueBytes(body, []byte(p.kmsKeyID))
	}
	body = append(body, '}')
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AmazonSSM.PutParameter")
	signAWSJSONRequest(req, body, p.now().UTC(), p.host, p.region, "ssm", p.accessKeyID, p.secretKey, p.sessionToken)
	return expect2xx(p.doer, req)
}

func (p *AWSParameterStorePusher) Close() {
	destroySecretBuffer(&p.secretKey)
	destroySecretBuffer(&p.sessionToken)
}
