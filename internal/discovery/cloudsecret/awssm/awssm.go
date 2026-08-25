// SPDX-License-Identifier: MPL-2.0

// Package awssm enumerates certificate material stored in AWS Secrets Manager.
// It uses only read-only ListSecrets and GetSecretValue calls, signs requests with
// AWS Signature Version 4 through internal/crypto, and returns metadata-only
// cloudsecret findings.
package awssm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	service = "secretsmanager"
	amzJSON = "application/x-amz-json-1.1"
)

// Config configures AWS Secrets Manager discovery.
type Config struct {
	Region          string
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey []byte
	SessionToken    []byte
	TagKey          string
	TagValue        string
	NamePrefix      string
	// InspectContent is the explicit opt-in to GetSecretValue. The default
	// metadata-only inventory never calls that API.
	InspectContent bool
	HTTPClient     *http.Client
	Now            func() time.Time
	Retry          cloudcert.RetryPolicy
}

// Enumerator is a read-only AWS Secrets Manager certificate-secret source.
type Enumerator struct {
	cfg  Config
	host string
}

// New builds an AWS Secrets Manager enumerator.
func New(cfg Config) (*Enumerator, error) {
	if cfg.Region == "" {
		return nil, fmt.Errorf("awssm: region required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://secretsmanager." + cfg.Region + ".amazonaws.com"
	}
	if cfg.AccessKeyID == "" {
		return nil, fmt.Errorf("awssm: access key id required")
	}
	if len(cfg.SecretAccessKey) == 0 {
		return nil, fmt.Errorf("awssm: secret access key required")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("awssm: bad endpoint: %w", err)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.SafeClient(30 * time.Second)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Retry.Max == 0 && cfg.Retry.Base == 0 {
		cfg.Retry = cloudcert.DefaultRetry()
	}
	cfg.SecretAccessKey = secrettext.Clone(cfg.SecretAccessKey)
	cfg.SessionToken = secrettext.Clone(cfg.SessionToken)
	return &Enumerator{cfg: cfg, host: u.Host}, nil
}

// Close wipes credential bytes held by the enumerator.
func (e *Enumerator) Close() {
	secret.Wipe(e.cfg.SecretAccessKey)
	secret.Wipe(e.cfg.SessionToken)
}

// Name identifies the provider.
func (e *Enumerator) Name() string { return "aws-secrets-manager" }

// Enumerate always returns metadata for matching resources. It retrieves values
// only when InspectContent was explicitly enabled.
func (e *Enumerator) Enumerate(ctx context.Context) ([]cloudsecret.Found, error) {
	secrets, err := e.listSecrets(ctx)
	if err != nil {
		return nil, err
	}
	var out []cloudsecret.Found
	for _, s := range secrets {
		if !e.matches(s) {
			continue
		}
		provenance := "aws-sm://" + e.cfg.Region + "/" + s.Name
		out = append(out, cloudsecret.MetadataFound(e.Name(), s.ARN, s.Name, e.cfg.Region, provenance, map[string]string{
			"secret_name": s.Name, "resource_id": s.ARN, "region": e.cfg.Region,
			"created_at": s.CreatedAt, "updated_at": s.UpdatedAt,
			"rotation_enabled": strconv.FormatBool(s.RotationEnabled), "tag_count": strconv.Itoa(len(s.Tags)),
			"content_inspected": "false",
		}))
		if !e.cfg.InspectContent {
			continue
		}
		found, err := e.inspectSecret(ctx, s)
		if err != nil {
			return nil, err
		}
		out = append(out, found...)
	}
	return out, nil
}

type secretSummary struct {
	Name            string
	ARN             string
	Tags            map[string]string
	CreatedAt       string
	UpdatedAt       string
	RotationEnabled bool
}

func (e *Enumerator) matches(s secretSummary) bool {
	if e.cfg.NamePrefix != "" && !strings.HasPrefix(s.Name, e.cfg.NamePrefix) {
		return false
	}
	if e.cfg.TagKey != "" {
		if s.Tags[e.cfg.TagKey] != e.cfg.TagValue {
			return false
		}
	}
	return true
}

func (e *Enumerator) listSecrets(ctx context.Context) ([]secretSummary, error) {
	var out []secretSummary
	next := ""
	for {
		payload := map[string]any{"MaxResults": 100}
		if next != "" {
			payload["NextToken"] = next
		}
		raw, err := e.call(ctx, "secretsmanager.ListSecrets", payload)
		if err != nil {
			return nil, err
		}
		var resp struct {
			SecretList []struct {
				Name            string `json:"Name"`
				ARN             string `json:"ARN"`
				CreatedDate     string `json:"CreatedDate"`
				LastChangedDate string `json:"LastChangedDate"`
				RotationEnabled bool   `json:"RotationEnabled"`
				Tags            []struct {
					Key   string `json:"Key"`
					Value string `json:"Value"`
				} `json:"Tags"`
			} `json:"SecretList"`
			NextToken string `json:"NextToken"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("awssm: parse list: %w", err)
		}
		for _, s := range resp.SecretList {
			tags := map[string]string{}
			for _, tag := range s.Tags {
				tags[tag.Key] = tag.Value
			}
			out = append(out, secretSummary{
				Name: s.Name, ARN: s.ARN, Tags: tags, CreatedAt: s.CreatedDate,
				UpdatedAt: s.LastChangedDate, RotationEnabled: s.RotationEnabled,
			})
		}
		if resp.NextToken == "" {
			break
		}
		next = resp.NextToken
	}
	return out, nil
}

func (e *Enumerator) inspectSecret(ctx context.Context, s secretSummary) ([]cloudsecret.Found, error) {
	value, err := e.getSecretValue(ctx, s.Name)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(value)
	provenance := "aws-sm://" + e.cfg.Region + "/" + s.Name
	return cloudsecret.InspectSecret(e.Name(), cloudsecret.Secret{
		Name:       s.Name,
		ResourceID: s.ARN,
		Location:   e.cfg.Region,
		Provenance: provenance,
		Value:      value,
		Metadata: map[string]string{
			"secret_name":       s.Name,
			"resource_id":       s.ARN,
			"region":            e.cfg.Region,
			"content_inspected": "true",
		},
	})
}

func (e *Enumerator) getSecretValue(ctx context.Context, name string) ([]byte, error) {
	raw, err := e.call(ctx, "secretsmanager.GetSecretValue", map[string]any{"SecretId": name})
	if err != nil {
		return nil, err
	}
	var resp struct {
		SecretString secretjson.StringBytes `json:"SecretString"`
		SecretBinary secretjson.StringBytes `json:"SecretBinary"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("awssm: parse get: %w", err)
	}
	defer secret.Wipe(resp.SecretString)
	defer secret.Wipe(resp.SecretBinary)
	if len(resp.SecretString) > 0 {
		return append([]byte(nil), resp.SecretString...), nil
	}
	if len(resp.SecretBinary) > 0 {
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(resp.SecretBinary)))
		n, err := base64.StdEncoding.Decode(decoded, resp.SecretBinary)
		if err != nil {
			secret.Wipe(decoded)
			return nil, fmt.Errorf("awssm: decode SecretBinary: %w", err)
		}
		return decoded[:n], nil
	}
	return nil, nil
}

func (e *Enumerator) call(ctx context.Context, target string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.Endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", amzJSON)
	req.Header.Set("X-Amz-Target", target)
	e.signV4(req, body, e.cfg.Now().UTC())
	return cloudcert.Fetch(ctx, e.cfg.HTTPClient, req, body, e.cfg.Retry)
}

func (e *Enumerator) signV4(req *http.Request, body []byte, t time.Time) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if len(e.cfg.SessionToken) > 0 {
		req.Header.Set("X-Amz-Security-Token", secrettext.String(e.cfg.SessionToken))
	}

	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if len(e.cfg.SessionToken) > 0 {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)

	var canonHeaders strings.Builder
	for _, h := range signed {
		v := strings.TrimSpace(req.Header.Get(h))
		if h == "host" {
			v = e.host
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

	credScope := dateStamp + "/" + e.cfg.Region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		crypto.SHA256Hex([]byte(canonicalRequest)),
	}, "\n")

	seed := make([]byte, 0, len("AWS4")+len(e.cfg.SecretAccessKey))
	seed = append(seed, "AWS4"...)
	seed = append(seed, e.cfg.SecretAccessKey...)
	kDate := crypto.HMACSHA256(seed, []byte(dateStamp))
	secret.Wipe(seed)
	kRegion := crypto.HMACSHA256(kDate, []byte(e.cfg.Region))
	secret.Wipe(kDate)
	kService := crypto.HMACSHA256(kRegion, []byte(service))
	secret.Wipe(kRegion)
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	secret.Wipe(kService)
	signature := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))
	secret.Wipe(kSigning)

	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 "+
		"Credential="+e.cfg.AccessKeyID+"/"+credScope+", "+
		"SignedHeaders="+signedHeaders+", "+
		"Signature="+signature)
}
