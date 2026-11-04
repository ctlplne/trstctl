// SPDX-License-Identifier: BUSL-1.1

// Package awskms reads one AWS account and Region's KMS keys (X4) through the
// read-only KMS JSON API: ListKeys, DescribeKey and GetKeyRotationStatus. Each
// key comes back with its type and size (from its key spec), usage, state,
// manager, origin and automatic-rotation status. It never reads key material
// and changes nothing.
package awskms

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/netsec"
)

const (
	service = "kms"
	// MaxKeys bounds one enumeration.
	MaxKeys = 10000
	maxBody = 4 << 20
)

// Rotation statuses.
const (
	RotationEnabled  = "enabled"
	RotationDisabled = "disabled"
	// RotationNotSupported is a key KMS cannot rotate automatically: an
	// asymmetric or HMAC key, imported key material, or a custom key store.
	RotationNotSupported = "not_supported"
	// RotationUnknown is a key whose rotation status KMS would not report (a
	// refused read, or a state such as pending deletion).
	RotationUnknown = "unknown"
)

// Config is one account and Region's read-only access.
type Config struct {
	Region          string
	Endpoint        string // default https://kms.<region>.amazonaws.com
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	HTTPClient      *http.Client
	Now             func() time.Time
}

// Key is one KMS key's metadata.
type Key struct {
	KeyID, ARN  string
	KeySpec     string // SYMMETRIC_DEFAULT, RSA_2048, ECC_NIST_P256, HMAC_256, ...
	Algorithm   string // AES, RSA, ECDSA, HMAC, SM2, ML-DSA; empty when unknown
	Bits        int
	KeyUsage    string
	KeyState    string
	KeyManager  string // CUSTOMER or AWS
	Origin      string // AWS_KMS, EXTERNAL, AWS_CLOUDHSM, EXTERNAL_KEY_STORE
	Created     time.Time
	Enabled     bool
	MultiRegion bool
	Rotation    Rotation
}

// Rotation is a key's automatic-rotation status.
type Rotation struct {
	Status       string
	PeriodDays   int
	NextRotation *time.Time
	// Error is KMS's error code when Status is unknown because a read failed.
	Error string
}

// Unrotated reports a key KMS could rotate automatically but is not rotating.
func (k Key) Unrotated() bool { return k.Rotation.Status == RotationDisabled }

// KeySpecAlgorithm names a key spec's algorithm family and size.
func KeySpecAlgorithm(spec string) (string, int) {
	switch {
	case spec == "SYMMETRIC_DEFAULT":
		return "AES", 256
	case strings.HasPrefix(spec, "RSA_"):
		return "RSA", atoi(strings.TrimPrefix(spec, "RSA_"))
	case spec == "ECC_NIST_P256", spec == "ECC_SECG_P256K1":
		return "ECDSA", 256
	case spec == "ECC_NIST_P384":
		return "ECDSA", 384
	case spec == "ECC_NIST_P521":
		return "ECDSA", 521
	case spec == "ECC_NIST_EDWARDS25519":
		return "EdDSA", 256
	case strings.HasPrefix(spec, "HMAC_"):
		return "HMAC", atoi(strings.TrimPrefix(spec, "HMAC_"))
	case spec == "SM2":
		return "SM2", 256
	case strings.HasPrefix(spec, "ML_DSA_"):
		return "ML-DSA", 0
	}
	return "", 0
}

// RotationSupported reports whether KMS can rotate a key automatically: only a
// symmetric encryption key whose material KMS generated in its own store.
func RotationSupported(k Key) bool {
	return k.KeySpec == "SYMMETRIC_DEFAULT" && (k.Origin == "" || k.Origin == "AWS_KMS")
}

// Reader reads one account and Region's keys.
type Reader struct {
	cfg  Config
	host string
}

// New builds a reader.
func New(cfg Config) (*Reader, error) {
	if strings.TrimSpace(cfg.Region) == "" {
		return nil, fmt.Errorf("awskms: region is required")
	}
	if strings.TrimSpace(cfg.AccessKeyID) == "" || cfg.SecretAccessKey == "" {
		return nil, fmt.Errorf("awskms: credentials are required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://kms." + cfg.Region + ".amazonaws.com"
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("awskms: bad endpoint")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.HardenedClient(30 * time.Second)
	}
	return &Reader{cfg: cfg, host: u.Host}, nil
}

// Keys lists every key in the Region with its metadata and rotation status,
// in key ID order, at most MaxKeys. A refused rotation read leaves that key's
// status unknown with KMS's error code; any other refused read fails the list.
func (r *Reader) Keys(ctx context.Context) ([]Key, error) {
	var ids []string
	marker := ""
	for {
		in := map[string]any{"Limit": 1000}
		if marker != "" {
			in["Marker"] = marker
		}
		var page struct {
			Keys []struct {
				KeyID string `json:"KeyId"`
			} `json:"Keys"`
			NextMarker string `json:"NextMarker"`
			Truncated  bool   `json:"Truncated"`
		}
		if err := r.call(ctx, "ListKeys", in, &page); err != nil {
			return nil, err
		}
		for _, k := range page.Keys {
			ids = append(ids, k.KeyID)
		}
		if len(ids) >= MaxKeys {
			ids = ids[:MaxKeys]
			break
		}
		if !page.Truncated || page.NextMarker == "" {
			break
		}
		marker = page.NextMarker
	}
	sort.Strings(ids)
	keys := make([]Key, 0, len(ids))
	for _, id := range ids {
		var described struct {
			KeyMetadata struct {
				KeyID        string  `json:"KeyId"`
				Arn          string  `json:"Arn"`
				KeySpec      string  `json:"KeySpec"`
				KeyUsage     string  `json:"KeyUsage"`
				KeyState     string  `json:"KeyState"`
				KeyManager   string  `json:"KeyManager"`
				Origin       string  `json:"Origin"`
				CreationDate float64 `json:"CreationDate"`
				Enabled      bool    `json:"Enabled"`
				MultiRegion  bool    `json:"MultiRegion"`
			} `json:"KeyMetadata"`
		}
		if err := r.call(ctx, "DescribeKey", map[string]any{"KeyId": id}, &described); err != nil {
			return nil, err
		}
		m := described.KeyMetadata
		k := Key{KeyID: m.KeyID, ARN: m.Arn, KeySpec: m.KeySpec, KeyUsage: m.KeyUsage, KeyState: m.KeyState,
			KeyManager: m.KeyManager, Origin: m.Origin, Created: epoch(m.CreationDate), Enabled: m.Enabled, MultiRegion: m.MultiRegion}
		if k.KeyID == "" {
			k.KeyID = id
		}
		k.Algorithm, k.Bits = KeySpecAlgorithm(k.KeySpec)
		k.Rotation = r.rotation(ctx, k)
		keys = append(keys, k)
	}
	return keys, nil
}

func (r *Reader) rotation(ctx context.Context, k Key) Rotation {
	if !RotationSupported(k) {
		return Rotation{Status: RotationNotSupported}
	}
	if k.KeyState == "PendingDeletion" || k.KeyState == "PendingReplicaDeletion" || k.KeyState == "Unavailable" {
		return Rotation{Status: RotationUnknown}
	}
	var out struct {
		KeyRotationEnabled   bool    `json:"KeyRotationEnabled"`
		RotationPeriodInDays int     `json:"RotationPeriodInDays"`
		NextRotationDate     float64 `json:"NextRotationDate"`
	}
	if err := r.call(ctx, "GetKeyRotationStatus", map[string]any{"KeyId": k.KeyID}, &out); err != nil {
		code := "refused"
		var e *apiError
		if errors.As(err, &e) && e.Code != "" {
			code = e.Code
		}
		return Rotation{Status: RotationUnknown, Error: code}
	}
	rot := Rotation{Status: RotationDisabled}
	if out.KeyRotationEnabled {
		rot.Status = RotationEnabled
		rot.PeriodDays = out.RotationPeriodInDays
		if out.NextRotationDate > 0 {
			next := epoch(out.NextRotationDate)
			rot.NextRotation = &next
		}
	}
	return rot
}

// apiError is a KMS error answer: its code and HTTP status, never its message.
type apiError struct {
	Op     string
	Status int
	Code   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("awskms: %s: status %d %s (response body redacted)", e.Op, e.Status, e.Code)
}

func (r *Reader) call(ctx context.Context, op string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(r.cfg.Endpoint, "/")+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService."+op)
	r.signV4(req, body, r.cfg.Now().UTC())
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("awskms: %s: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("awskms: %s: read response: %w", op, err)
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Type string `json:"__type"`
		}
		_ = json.Unmarshal(raw, &e)
		code := e.Type
		if i := strings.LastIndex(code, "#"); i >= 0 {
			code = code[i+1:]
		}
		return &apiError{Op: op, Status: resp.StatusCode, Code: code}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("awskms: %s: decode response: %w", op, err)
	}
	return nil
}

// signV4 adds AWS Signature Version 4 headers through the crypto boundary.
func (r *Reader) signV4(req *http.Request, body []byte, t time.Time) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if r.cfg.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", r.cfg.SessionToken)
	}
	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if r.cfg.SessionToken != "" {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)
	var canonHeaders strings.Builder
	for _, h := range signed {
		v := strings.TrimSpace(req.Header.Get(h))
		if h == "host" {
			v = r.host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	signedHeaders := strings.Join(signed, ";")
	canonicalRequest := strings.Join([]string{
		req.Method, req.URL.EscapedPath(), "", canonHeaders.String(), signedHeaders, crypto.SHA256Hex(body),
	}, "\n")
	credScope := dateStamp + "/" + r.cfg.Region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, credScope, crypto.SHA256Hex([]byte(canonicalRequest))}, "\n")
	kDate := crypto.HMACSHA256([]byte("AWS4"+r.cfg.SecretAccessKey), []byte(dateStamp))
	kRegion := crypto.HMACSHA256(kDate, []byte(r.cfg.Region))
	kService := crypto.HMACSHA256(kRegion, []byte(service))
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+r.cfg.AccessKeyID+"/"+credScope+
		", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func epoch(seconds float64) time.Time {
	if seconds <= 0 {
		return time.Time{}
	}
	whole, frac := math.Modf(seconds)
	return time.Unix(int64(whole), int64(frac*1e9)).UTC()
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
