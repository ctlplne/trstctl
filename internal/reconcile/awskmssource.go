// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers"
)

// AWS KMS authority source (A168).
//
// Until A168 the "cloud-kms" reducer was registered with a nil source:
// scheduling it failed observation closed. This adapter observes one AWS KMS
// account and region over the KMS JSON API — ListKeys, DescribeKey,
// ListResourceTags and GetKeyRotationStatus, read-only — and asserts each key's
// identity (its KeyId), key spec, state and rotation standing. By default it asserts only the keys trstctl tagged as its
// own when it created them (the managed-key operation tag); AWS-managed keys
// are never asserted, and nor is a key tagged as another tenant's (A168-L2):
// in an account several tenants share, a round of one tenant reads only its
// own keys and untagged keys created before the tenant tag existed. It pairs with the managed-key inventory authority, which
// asserts what trstctl believes it holds in the same account, so a round
// witnesses a key only one side holds and a key whose state drifted.
//
// Credentials are read from files at each observation and wiped once the
// request is signed; every list and read passes the observation sandbox first.

const (
	awsKMSSourceTimeout = 30 * time.Second
	awsKMSSourceMaxBody = 4 << 20
	// awsKMSSourceMaxKeys bounds one observation; an account holding more fails
	// the observation rather than yield a partial inventory.
	awsKMSSourceMaxKeys = 10000
	// awsKMSManagedTag is the tag trstctl stamps on every key it creates
	// (internal/kms/awskms operationTagKey).
	awsKMSManagedTag = "trstctl-managed-key-operation"
	// awsKMSTenantTag names the tenant a key trstctl created belongs to
	// (internal/kms/awskms tenantTagKey, A168-L2).
	awsKMSTenantTag = "trstctl-tenant"
)

// AWSKMSSourceConfig is the core-owned shape operator config maps onto.
type AWSKMSSourceConfig struct {
	AuthorityID string
	Region      string
	// Address overrides the regional endpoint (a VPC endpoint, a stand-in).
	Address             string
	AccessKeyIDFile     string
	SecretAccessKeyFile string
	SessionTokenFile    string
	// AllCustomerKeys asserts every customer-managed key, not only the keys
	// trstctl tagged as its own.
	AllCustomerKeys bool
	// MaxObjects bounds one observation; zero means awsKMSSourceMaxKeys.
	MaxObjects            int
	AllowInsecureLoopback bool
	PrivateEndpointCIDRs  []netip.Prefix
	HTTPClient            *http.Client
	Now                   func() time.Time
}

var errAWSKMSSourceConfig = errors.New("xrec aws kms source: configuration")

type awsKMSSource struct {
	cfg      AWSKMSSourceConfig
	client   *http.Client
	endpoint string
	host     string
}

var _ reducers.CloudKMSInventorySource = (*awsKMSSource)(nil)

func newAWSKMSSource(cfg AWSKMSSourceConfig) (*awsKMSSource, error) {
	cfg.AuthorityID, cfg.Region = strings.TrimSpace(cfg.AuthorityID), strings.TrimSpace(cfg.Region)
	if cfg.AuthorityID == "" || cfg.Region == "" {
		return nil, fmt.Errorf("%w: authority id and region required", errAWSKMSSourceConfig)
	}
	if strings.TrimSpace(cfg.AccessKeyIDFile) == "" || strings.TrimSpace(cfg.SecretAccessKeyFile) == "" {
		return nil, fmt.Errorf("%w: access key id and secret access key files required", errAWSKMSSourceConfig)
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Address), "/")
	if endpoint == "" {
		endpoint = "https://kms." + cfg.Region + ".amazonaws.com"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("%w: address must be an http(s) URL", errAWSKMSSourceConfig)
	}
	if u.Scheme == "http" && !cfg.AllowInsecureLoopback {
		return nil, fmt.Errorf("%w: plain http needs allow_insecure_loopback", errAWSKMSSourceConfig)
	}
	if cfg.MaxObjects <= 0 {
		cfg.MaxObjects = awsKMSSourceMaxKeys
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	client := cfg.HTTPClient
	if client == nil {
		opts := netsec.SafeClientOptions{AllowPrivateCIDRs: append([]netip.Prefix(nil), cfg.PrivateEndpointCIDRs...)}
		if cfg.AllowInsecureLoopback {
			opts.AllowPrivateCIDRs = append(opts.AllowPrivateCIDRs, netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"))
		}
		client = netsec.SafeClientWithOptions(awsKMSSourceTimeout, opts)
	}
	return &awsKMSSource{cfg: cfg, client: client, endpoint: endpoint, host: u.Host}, nil
}

// CloudKMSSnapshot implements reducers.CloudKMSInventorySource.
func (s *awsKMSSource) CloudKMSSnapshot(ctx context.Context, tenantID string, sb *reducers.ObservationSandbox) (reducers.CloudKMSSnapshot, error) {
	if sb == nil {
		sb = reducers.NewObservationSandbox(reducers.ReadOnlyObservationGrant(s.cfg.AuthorityID), nil)
	}
	creds, err := s.credentials()
	if err != nil {
		return reducers.CloudKMSSnapshot{}, err
	}
	defer creds.wipe()
	now := s.cfg.Now().UTC()
	snap := reducers.CloudKMSSnapshot{Watermark: storeWatermark("aws-kms:"+s.cfg.AuthorityID, now)}
	ids, err := s.listKeys(ctx, sb, creds)
	if err != nil {
		return reducers.CloudKMSSnapshot{}, err
	}
	for _, id := range ids {
		key, keep, err := s.describe(ctx, sb, creds, id, tenantID)
		if err != nil {
			return reducers.CloudKMSSnapshot{}, err
		}
		if keep {
			snap.Keys = append(snap.Keys, key)
		}
	}
	sort.Slice(snap.Keys, func(i, j int) bool { return snap.Keys[i].KeyID < snap.Keys[j].KeyID })
	return snap, nil
}

func (s *awsKMSSource) listKeys(ctx context.Context, sb *reducers.ObservationSandbox, creds awsKMSCredentials) ([]string, error) {
	if _, err := sb.List(ctx, s.resource("keys")); err != nil {
		return nil, fmt.Errorf("xrec aws kms source: list keys: %w", err)
	}
	var ids []string
	marker := ""
	for {
		req := map[string]any{"Limit": 1000}
		if marker != "" {
			req["Marker"] = marker
		}
		var page struct {
			Keys []struct {
				KeyID string `json:"KeyId"`
			} `json:"Keys"`
			NextMarker string `json:"NextMarker"`
			Truncated  bool   `json:"Truncated"`
		}
		if err := s.call(ctx, creds, "ListKeys", req, &page); err != nil {
			return nil, err
		}
		for _, k := range page.Keys {
			ids = append(ids, k.KeyID)
		}
		if len(ids) > s.cfg.MaxObjects {
			return nil, fmt.Errorf("xrec aws kms source: the account holds more than %d keys; raise max_objects rather than observe part of it", s.cfg.MaxObjects)
		}
		if !page.Truncated || page.NextMarker == "" {
			return ids, nil
		}
		marker = page.NextMarker
	}
}

// describe reads one key's metadata and decides whether this authority asserts
// it in tenantID's round: never an AWS-managed key or a key tagged as another
// tenant's, and by default only a key trstctl tagged.
func (s *awsKMSSource) describe(ctx context.Context, sb *reducers.ObservationSandbox, creds awsKMSCredentials, id, tenantID string) (reducers.CloudKMSKey, bool, error) {
	if _, err := sb.Describe(ctx, s.resource("key", id)); err != nil {
		return reducers.CloudKMSKey{}, false, fmt.Errorf("xrec aws kms source: describe %s: %w", id, err)
	}
	var out struct {
		KeyMetadata struct {
			KeyID      string `json:"KeyId"`
			Arn        string `json:"Arn"`
			KeyState   string `json:"KeyState"`
			KeySpec    string `json:"KeySpec"`
			KeyManager string `json:"KeyManager"`
		} `json:"KeyMetadata"`
	}
	if err := s.call(ctx, creds, "DescribeKey", map[string]any{"KeyId": id}, &out); err != nil {
		return reducers.CloudKMSKey{}, false, err
	}
	md := out.KeyMetadata
	if md.KeyManager == "AWS" {
		return reducers.CloudKMSKey{}, false, nil
	}
	tags, err := s.trstctlTags(ctx, creds, id)
	if err != nil {
		return reducers.CloudKMSKey{}, false, err
	}
	if !tags.managed && !s.cfg.AllCustomerKeys {
		return reducers.CloudKMSKey{}, false, nil
	}
	if tags.tenant != "" && tags.tenant != strings.TrimSpace(tenantID) {
		return reducers.CloudKMSKey{}, false, nil
	}
	rotation, err := s.rotationEnabled(ctx, creds, id, md.KeySpec)
	if err != nil {
		return reducers.CloudKMSKey{}, false, err
	}
	// Creation and deletion dates are not asserted: the managed-key authority
	// records when its operation completed, seconds after KMS created the key,
	// and the canonical five-minute buckets would turn that gap into a false
	// disagreement. The state carries a scheduled deletion.
	return reducers.CloudKMSKey{
		KeyID: md.KeyID, AlgorithmSpec: md.KeySpec, Status: awsKMSKeyStatus(md.KeyState),
		RotationEnabled: rotation, NativeID: md.Arn,
	}, true, nil
}

// awsKMSKeyTags is what a key's tags say about trstctl: whether trstctl
// created it, and the tenant it was created for.
type awsKMSKeyTags struct {
	managed bool
	tenant  string
}

func (s *awsKMSSource) trstctlTags(ctx context.Context, creds awsKMSCredentials, id string) (awsKMSKeyTags, error) {
	var tags awsKMSKeyTags
	marker := ""
	for page := 0; page < 20; page++ {
		req := map[string]any{"KeyId": id, "Limit": 50}
		if marker != "" {
			req["Marker"] = marker
		}
		var out struct {
			Tags []struct {
				TagKey   string `json:"TagKey"`
				TagValue string `json:"TagValue"`
			} `json:"Tags"`
			NextMarker string `json:"NextMarker"`
			Truncated  bool   `json:"Truncated"`
		}
		if err := s.call(ctx, creds, "ListResourceTags", req, &out); err != nil {
			return awsKMSKeyTags{}, err
		}
		for _, tag := range out.Tags {
			switch tag.TagKey {
			case awsKMSManagedTag:
				tags.managed = true
			case awsKMSTenantTag:
				tags.tenant = strings.TrimSpace(tag.TagValue)
			}
		}
		if !out.Truncated || out.NextMarker == "" {
			return tags, nil
		}
		marker = out.NextMarker
	}
	return tags, nil
}

// rotationEnabled asks only about symmetric keys: KMS rotates nothing else and
// answers the question for other specs with an error, not with false.
func (s *awsKMSSource) rotationEnabled(ctx context.Context, creds awsKMSCredentials, id, spec string) (bool, error) {
	if spec != "SYMMETRIC_DEFAULT" {
		return false, nil
	}
	var out struct {
		KeyRotationEnabled bool `json:"KeyRotationEnabled"`
	}
	if err := s.call(ctx, creds, "GetKeyRotationStatus", map[string]any{"KeyId": id}, &out); err != nil {
		return false, err
	}
	return out.KeyRotationEnabled, nil
}

// awsKMSKeyStatus maps KMS key states onto the canonical vocabulary; a state
// that is neither usable, disabled nor scheduled for deletion is unknown
// rather than guessed.
func awsKMSKeyStatus(state string) string {
	switch state {
	case "Enabled":
		return canon.StatusActive
	case "Disabled":
		return canon.StatusDisabled
	case "PendingDeletion", "PendingReplicaDeletion":
		return canon.StatusPendingDeletion
	default:
		return canon.StatusUnknown
	}
}

// resource names what the sandbox is asked to allow, under the authority's
// own scope as the read-only grant requires.
func (s *awsKMSSource) resource(parts ...string) string {
	return s.cfg.AuthorityID + "/kms/" + s.cfg.Region + "/" + strings.Join(parts, "/")
}

type awsKMSCredentials struct {
	accessKeyID, secretAccessKey, sessionToken []byte
}

func (c awsKMSCredentials) wipe() {
	secret.Wipe(c.accessKeyID)
	secret.Wipe(c.secretAccessKey)
	secret.Wipe(c.sessionToken)
}

func (s *awsKMSSource) credentials() (awsKMSCredentials, error) {
	read := func(path string) ([]byte, error) {
		raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured credential file path (CWE-22)
		if err != nil {
			return nil, fmt.Errorf("xrec aws kms source: read credential file: %w", err)
		}
		return bytes.TrimSpace(raw), nil
	}
	var creds awsKMSCredentials
	var err error
	if creds.accessKeyID, err = read(s.cfg.AccessKeyIDFile); err != nil {
		return awsKMSCredentials{}, err
	}
	if creds.secretAccessKey, err = read(s.cfg.SecretAccessKeyFile); err != nil {
		creds.wipe()
		return awsKMSCredentials{}, err
	}
	if strings.TrimSpace(s.cfg.SessionTokenFile) != "" {
		if creds.sessionToken, err = read(s.cfg.SessionTokenFile); err != nil {
			creds.wipe()
			return awsKMSCredentials{}, err
		}
	}
	if len(creds.accessKeyID) == 0 || len(creds.secretAccessKey) == 0 {
		creds.wipe()
		return awsKMSCredentials{}, errors.New("xrec aws kms source: a credential file is empty")
	}
	return creds, nil
}

// call signs and sends one KMS JSON 1.1 operation. A non-2xx answer is
// reported by status only.
func (s *awsKMSSource) call(ctx context.Context, creds awsKMSCredentials, op string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService."+op)
	s.signV4(req, body, creds, s.cfg.Now().UTC())
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("xrec aws kms source: %s: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, awsKMSSourceMaxBody))
	if err != nil {
		return fmt.Errorf("xrec aws kms source: %s: read response: %w", op, err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("xrec aws kms source: %s: status %d (response body redacted)", op, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("xrec aws kms source: %s: decode response: %w", op, err)
	}
	return nil
}

// signV4 adds AWS Signature Version 4 headers. Digests and the keyed MAC route
// through the crypto boundary (AN-3).
func (s *awsKMSSource) signV4(req *http.Request, body []byte, creds awsKMSCredentials, t time.Time) {
	amzDate, dateStamp := t.Format("20060102T150405Z"), t.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if len(creds.sessionToken) > 0 {
		req.Header.Set("X-Amz-Security-Token", string(creds.sessionToken))
	}
	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if len(creds.sessionToken) > 0 {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)
	var canonHeaders strings.Builder
	for _, h := range signed {
		v := strings.TrimSpace(req.Header.Get(h))
		if h == "host" {
			v = s.host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	signedHeaders := strings.Join(signed, ";")
	canonical := strings.Join([]string{req.Method, req.URL.EscapedPath(), "", canonHeaders.String(), signedHeaders, crypto.SHA256Hex(body)}, "\n")
	scope := dateStamp + "/" + s.cfg.Region + "/kms/aws4_request"
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, crypto.SHA256Hex([]byte(canonical))}, "\n")
	key := append([]byte("AWS4"), creds.secretAccessKey...)
	defer secret.Wipe(key)
	k := crypto.HMACSHA256(key, []byte(dateStamp))
	k = crypto.HMACSHA256(k, []byte(s.cfg.Region))
	k = crypto.HMACSHA256(k, []byte("kms"))
	k = crypto.HMACSHA256(k, []byte("aws4_request"))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+string(creds.accessKeyID)+"/"+scope+
		", SignedHeaders="+signedHeaders+", Signature="+hex.EncodeToString(crypto.HMACSHA256(k, []byte(toSign))))
}
