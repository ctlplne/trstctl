// SPDX-License-Identifier: MPL-2.0

package awspca

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	awsPCAService = "acm-pca"
	awsPCAType    = "ACMPrivateCA"
)

// HTTPConfig configures the production AWS Private CA JSON/SigV4 transport.
// SecretAccessKey and SessionToken are copied on construction and erased by
// Destroy. Endpoint may point at an AWS VPC endpoint or a faithful emulator.
type HTTPConfig struct {
	Endpoint        string
	Region          string
	AccessKeyID     string
	SecretAccessKey []byte
	SessionToken    []byte
	HTTPClient      cloudhttp.Doer
	Timeout         time.Duration
}

// HTTPAPI is the real AWS JSON protocol implementation of API.
type HTTPAPI struct {
	endpoint     string
	region       string
	accessKeyID  string
	secretKey    []byte
	sessionToken []byte
	doer         cloudhttp.Doer
	timeout      time.Duration
	now          func() time.Time
}

var _ API = (*HTTPAPI)(nil)

// NewHTTPAPI constructs a SigV4-authenticated acm-pca client.
func NewHTTPAPI(cfg HTTPConfig) (*HTTPAPI, error) {
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		return nil, errors.New("awspca: HTTP region is required")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint == "" {
		endpoint = "https://acm-pca." + region + ".amazonaws.com"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("awspca: HTTP endpoint must be an absolute URL")
	}
	if strings.TrimSpace(cfg.AccessKeyID) == "" || len(cfg.SecretAccessKey) == 0 {
		return nil, errors.New("awspca: HTTP access key credentials are required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		if err := ca.ValidateExternalCAEndpoint("awspca", endpoint, ca.HTTPClientConfig{}); err != nil {
			return nil, err
		}
		doer = ca.DefaultExternalCAHTTPClient(ca.HTTPClientConfig{})
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &HTTPAPI{
		endpoint: endpoint, region: region, accessKeyID: cfg.AccessKeyID,
		secretKey: secrettext.Clone(cfg.SecretAccessKey), sessionToken: secrettext.Clone(cfg.SessionToken),
		doer: doer, timeout: timeout, now: time.Now,
	}, nil
}

// Destroy erases SigV4 credentials and closes idle network connections.
func (a *HTTPAPI) Destroy() {
	secret.Wipe(a.secretKey)
	secret.Wipe(a.sessionToken)
	if client, ok := a.doer.(*http.Client); ok {
		client.CloseIdleConnections()
	}
}

func (a *HTTPAPI) IssueCertificate(ctx context.Context, in IssueCertificateInput) (IssueCertificateOutput, error) {
	var out IssueCertificateOutput
	err := a.call(ctx, "IssueCertificate", in, &out)
	return out, err
}

func (a *HTTPAPI) GetCertificate(ctx context.Context, in GetCertificateInput) (GetCertificateOutput, error) {
	var out GetCertificateOutput
	err := a.call(ctx, "GetCertificate", in, &out)
	if isAWSRequestInProgress(err) {
		return GetCertificateOutput{}, ErrRequestInProgress
	}
	return out, err
}

func (a *HTTPAPI) call(ctx context.Context, operation string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("awspca: encode %s: %w", operation, err)
	}
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", awsPCAType+"."+operation)
	req = cloudhttp.SetBody(req, body)
	if err := cloudhttp.JSON(a.doer, req, out,
		cloudhttp.WithTimeout(a.timeout), cloudhttp.WithSigner(a.sigV4Signer()),
		cloudhttp.WithStatusMapper(mapAWSPrivateCAStatus)); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrRequestInProgress) {
			return err
		}
		var statusErr *cloudhttp.StatusError
		if errors.As(err, &statusErr) {
			return fmt.Errorf("awspca: %s: status %d", operation, statusErr.StatusCode)
		}
		return fmt.Errorf("awspca: %s request failed", operation)
	}
	return nil
}

func mapAWSPrivateCAStatus(_ int, body []byte) error {
	if containsASCIIFold(body, []byte("requestinprogressexception")) ||
		containsASCIIFold(body, []byte("request in progress")) {
		return ErrRequestInProgress
	}
	return nil
}

// containsASCIIFold classifies a bounded response without converting secret-bearing
// bytes into an immutable string or allocating a lowercase copy.
func containsASCIIFold(body, needle []byte) bool {
	for i := 0; i+len(needle) <= len(body); i++ {
		if bytes.EqualFold(body[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

func isAWSRequestInProgress(err error) bool {
	return errors.Is(err, ErrRequestInProgress)
}

func (a *HTTPAPI) sigV4Signer() cloudhttp.Signer {
	return func(req *http.Request, body []byte) error {
		a.signV4(req, body, a.now().UTC())
		return nil
	}
}

func (a *HTTPAPI) signV4(req *http.Request, body []byte, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if len(a.sessionToken) != 0 {
		req.Header.Set("X-Amz-Security-Token", secrettext.String(a.sessionToken))
	}

	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if len(a.sessionToken) != 0 {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)
	canonicalHeaders := make([]byte, 0, 256+len(a.sessionToken))
	for _, header := range signed {
		canonicalHeaders = append(canonicalHeaders, header...)
		canonicalHeaders = append(canonicalHeaders, ':')
		switch header {
		case "host":
			canonicalHeaders = append(canonicalHeaders, req.URL.Host...)
		case "x-amz-security-token":
			// Do not read the forced HTTP string copy back into another string.
			canonicalHeaders = append(canonicalHeaders, bytes.TrimSpace(a.sessionToken)...)
		default:
			canonicalHeaders = append(canonicalHeaders, strings.TrimSpace(req.Header.Get(header))...)
		}
		canonicalHeaders = append(canonicalHeaders, '\n')
	}
	signedHeaders := strings.Join(signed, ";")
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalRequest := make([]byte, 0, len(canonicalHeaders)+len(req.Method)+len(canonicalURI)+len(signedHeaders)+128)
	canonicalRequest = append(canonicalRequest, req.Method...)
	canonicalRequest = append(canonicalRequest, '\n')
	canonicalRequest = append(canonicalRequest, canonicalURI...)
	canonicalRequest = append(canonicalRequest, '\n')
	canonicalRequest = append(canonicalRequest, req.URL.Query().Encode()...)
	canonicalRequest = append(canonicalRequest, '\n')
	canonicalRequest = append(canonicalRequest, canonicalHeaders...)
	canonicalRequest = append(canonicalRequest, '\n')
	canonicalRequest = append(canonicalRequest, signedHeaders...)
	canonicalRequest = append(canonicalRequest, '\n')
	canonicalRequest = append(canonicalRequest, crypto.SHA256Hex(body)...)
	canonicalHash := crypto.SHA256Hex(canonicalRequest)
	secret.Wipe(canonicalRequest)
	secret.Wipe(canonicalHeaders)
	scope := dateStamp + "/" + a.region + "/" + awsPCAService + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, canonicalHash,
	}, "\n")
	key := awsPCASigningKey(a.secretKey, dateStamp, a.region)
	signatureBytes := crypto.HMACSHA256(key, []byte(stringToSign))
	secret.Wipe(key)
	signatureHex := make([]byte, hex.EncodedLen(len(signatureBytes)))
	hex.Encode(signatureHex, signatureBytes)
	secret.Wipe(signatureBytes)
	authorization := make([]byte, 0, 96+len(a.accessKeyID)+len(scope)+len(signedHeaders)+len(signatureHex))
	authorization = append(authorization, "AWS4-HMAC-SHA256 Credential="...)
	authorization = append(authorization, a.accessKeyID...)
	authorization = append(authorization, '/')
	authorization = append(authorization, scope...)
	authorization = append(authorization, ", SignedHeaders="...)
	authorization = append(authorization, signedHeaders...)
	authorization = append(authorization, ", Signature="...)
	authorization = append(authorization, signatureHex...)
	req.Header.Set("Authorization", secrettext.String(authorization))
	secret.Wipe(authorization)
	secret.Wipe(signatureHex)
}

func awsPCASigningKey(secretAccessKey []byte, dateStamp, region string) []byte {
	seed := make([]byte, 0, len("AWS4")+len(secretAccessKey))
	seed = append(seed, "AWS4"...)
	seed = append(seed, secretAccessKey...)
	kDate := crypto.HMACSHA256(seed, []byte(dateStamp))
	secret.Wipe(seed)
	kRegion := crypto.HMACSHA256(kDate, []byte(region))
	secret.Wipe(kDate)
	kService := crypto.HMACSHA256(kRegion, []byte(awsPCAService))
	secret.Wipe(kRegion)
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	secret.Wipe(kService)
	return kSigning
}
