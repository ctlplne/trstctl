// SPDX-License-Identifier: BUSL-1.1

package objectstore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	// DefaultTimeout bounds one call that moves no payload, and is the base of
	// the deadline for one that does.
	DefaultTimeout = 30 * time.Second
	// DefaultMaxInFlight is how many object-store calls one process runs at
	// once before refusing more with ErrBusy.
	DefaultMaxInFlight = 8
	// MaxObjectBytes is S3's limit for a single PUT. Larger objects need a
	// multipart upload, which this client does not perform.
	MaxObjectBytes int64 = 5 << 30
	// minThroughput scales a call's deadline with its payload, so a large backup
	// artifact has time to move while a wedged endpoint still fails bounded.
	minThroughput = 1 << 20 // bytes per second
)

// listPageSize is how many keys one ListObjectsV2 call asks for (S3's maximum).
const listPageSize = 1000

var (
	bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	ipLike        = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
)

// Options configure an S3 store. SecretAccessKey and SessionToken are copied
// into locked memory by Open; the caller wipes its own copies.
type Options struct {
	// Endpoint is the store's base URL, for example https://s3.us-east-1.amazonaws.com
	// or https://minio.internal:9000. Plain http is accepted only for a loopback
	// host with AllowInsecureLoopback set.
	Endpoint string
	Region   string
	Bucket   string
	// Prefix is an optional deployment root every name is stored under, so
	// several deployments can share one bucket.
	Prefix string
	// PathStyle sends requests to <endpoint>/<bucket>/<key> (MinIO and most
	// S3-compatible stores) instead of <bucket>.<endpoint host>/<key>.
	PathStyle             bool
	AccessKeyID           string
	SecretAccessKey       []byte
	SessionToken          []byte
	CAPEM                 []byte
	AllowInsecureLoopback bool
	Timeout               time.Duration
	MaxInFlight           int
	// ObjectLock, when set, gives every object Create writes that S3 Object
	// Lock retention (A208). The bucket must have Object Lock enabled.
	ObjectLock *ObjectLock
}

// S3 is a Store backed by an S3-compatible service.
type S3 struct {
	client  *s3.Client
	http    *http.Client
	bucket  string
	root    string
	timeout time.Duration
	slots   chan struct{}
	lock    *ObjectLock

	mu              sync.RWMutex
	accessKeyID     string
	secretAccessKey *secret.Buffer
	sessionToken    *secret.Buffer
}

var _ Store = (*S3)(nil)

// Open validates opts, protects the credentials, and builds the client. It
// makes no network call; `trstctl doctor` exercises the store.
func Open(opts Options) (*S3, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(opts.Endpoint), "/")
	if err := validateEndpoint(endpoint, opts.AllowInsecureLoopback); err != nil {
		return nil, err
	}
	if !bucketPattern.MatchString(opts.Bucket) || strings.Contains(opts.Bucket, "..") || ipLike.MatchString(opts.Bucket) {
		return nil, fmt.Errorf("objectstore: bucket %q is not a valid S3 bucket name", opts.Bucket)
	}
	region := opts.Region
	if region == "" {
		region = "us-east-1"
	}
	if !regionPattern.MatchString(region) {
		return nil, fmt.Errorf("objectstore: region %q is not a valid region name", region)
	}
	root := opts.Prefix
	if root != "" {
		if !strings.HasSuffix(root, "/") {
			root += "/"
		}
		if err := ValidName(root, true); err != nil {
			return nil, fmt.Errorf("objectstore: deployment prefix: %w", err)
		}
	}
	if strings.TrimSpace(opts.AccessKeyID) == "" || len(opts.SecretAccessKey) == 0 {
		return nil, errors.New("objectstore: an access key ID and secret access key are required")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxInFlight := opts.MaxInFlight
	if maxInFlight <= 0 {
		maxInFlight = DefaultMaxInFlight
	}
	if !opts.PathStyle && strings.Contains(opts.Bucket, ".") {
		return nil, fmt.Errorf("objectstore: bucket %q contains a dot, which breaks TLS for virtual-hosted requests; set path_style", opts.Bucket)
	}
	var lock *ObjectLock
	if opts.ObjectLock != nil {
		if err := opts.ObjectLock.Validate(); err != nil {
			return nil, err
		}
		l := ObjectLock{Mode: strings.ToUpper(opts.ObjectLock.Mode), Retention: opts.ObjectLock.Retention}
		lock = &l
	}
	client, err := httpClientFor(endpoint, opts, timeout)
	if err != nil {
		return nil, err
	}
	secretKey, err := secret.NewFrom(opts.SecretAccessKey)
	if err != nil {
		return nil, fmt.Errorf("objectstore: protect secret access key: %w", err)
	}
	var session *secret.Buffer
	if len(opts.SessionToken) > 0 {
		if session, err = secret.NewFrom(opts.SessionToken); err != nil {
			secretKey.Destroy()
			return nil, fmt.Errorf("objectstore: protect session token: %w", err)
		}
	}
	store := &S3{
		http: client, bucket: opts.Bucket, root: root, timeout: timeout, lock: lock,
		slots: make(chan struct{}, maxInFlight), accessKeyID: opts.AccessKeyID,
		secretAccessKey: secretKey, sessionToken: session,
	}
	// The SDK keeps no credential cache of its own here: it asks the provider at
	// the SigV4 edge for each request, so the strings it needs live only for
	// that request while the source stays in locked memory.
	store.client = s3.NewFromConfig(awssdk.Config{
		Region:                     region,
		Credentials:                lockedCredentials{store: store},
		HTTPClient:                 client,
		RetryMaxAttempts:           3,
		RequestChecksumCalculation: awssdk.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: awssdk.ResponseChecksumValidationWhenRequired,
	}, func(o *s3.Options) {
		o.BaseEndpoint = awssdk.String(endpoint)
		o.UsePathStyle = opts.PathStyle
	})
	return store, nil
}

func validateEndpoint(endpoint string, allowInsecureLoopback bool) error {
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(endpoint, allowInsecureLoopback); err != nil {
		return fmt.Errorf("objectstore: endpoint: %w", err)
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("objectstore: endpoint %q must be a bare scheme://host[:port]", endpoint)
	}
	return nil
}

// httpClientFor builds the one client the store dials with. The endpoint is
// operator configuration and may legitimately be private (a MinIO on the same
// network), so it takes the hardened transport rather than the SSRF guard, the
// runtime distrust list applies to every chain, an operator CA replaces the
// system roots when one is given, and every request is bound to the
// configured origin before any socket opens.
func httpClientFor(endpoint string, opts Options, timeout time.Duration) (*http.Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	origin := endpoint
	if !opts.PathStyle {
		origin = u.Scheme + "://" + opts.Bucket + "." + u.Host
	}
	// No request may outlive the deadline of the largest object the store moves.
	ceiling := callDeadline(timeout, MaxObjectBytes)
	var client *http.Client
	if netsec.IsInsecureLoopbackHTTPURL(endpoint) {
		if len(opts.CAPEM) > 0 {
			return nil, errors.New("objectstore: ca_file requires an https endpoint")
		}
		if !opts.PathStyle {
			return nil, errors.New("objectstore: a plain-http loopback endpoint requires path_style")
		}
		client = netsec.InsecureLoopbackClient(ceiling)
	} else {
		transport := netsec.HardenedDefaultTransport()
		if len(opts.CAPEM) > 0 {
			pinned, err := mtls.HTTPTransport(opts.CAPEM)
			if err != nil {
				return nil, fmt.Errorf("objectstore: ca_file: %w", err)
			}
			transport = transport.Clone()
			transport.TLSClientConfig = pinned.TLSClientConfig
		}
		client = netsec.ClientFor(transport, ceiling, nil)
	}
	bound, err := netsec.BindTransportToOrigin(origin, client.Transport)
	if err != nil {
		return nil, err
	}
	client.Transport = bound
	// S3 answers a misdirected request with an error document, never a
	// redirect the client should follow with the signed request.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client, nil
}

func callDeadline(base time.Duration, size int64) time.Duration {
	if size <= 0 {
		return base
	}
	return base + time.Duration(size/minThroughput+1)*time.Second
}

// call runs fn under the in-flight bound and a deadline sized for payload
// bytes. A full store refuses at once rather than queueing (AN-7).
func (s *S3) call(ctx context.Context, payload int64, fn func(context.Context) error) error {
	select {
	case s.slots <- struct{}{}:
	default:
		return fmt.Errorf("%w (%d already running)", ErrBusy, cap(s.slots))
	}
	defer func() { <-s.slots }()
	ctx, cancel := context.WithTimeout(ctx, callDeadline(s.timeout, payload))
	defer cancel()
	return fn(ctx)
}

func (s *S3) key(name string) (string, error) {
	if err := ValidName(name, false); err != nil {
		return "", err
	}
	key := s.root + name
	if len(key) > maxKeyBytes {
		return "", fmt.Errorf("%w: %q exceeds %d bytes with the deployment prefix", ErrName, name, maxKeyBytes)
	}
	return key, nil
}

// Create implements Store.
func (s *S3) Create(ctx context.Context, name string, body io.ReadSeeker, size int64, sum []byte) error {
	key, err := s.key(name)
	if err != nil {
		return err
	}
	if len(sum) != 32 {
		return fmt.Errorf("%w: a SHA-256 digest is 32 bytes", ErrDigest)
	}
	if size < 0 || size > MaxObjectBytes {
		return fmt.Errorf("%w: %d bytes (a single object holds at most %d)", ErrTooLarge, size, MaxObjectBytes)
	}
	return s.call(ctx, size, func(ctx context.Context) error {
		if _, err := body.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("objectstore: rewind %s: %w", name, err)
		}
		input := &s3.PutObjectInput{
			Bucket:         awssdk.String(s.bucket),
			Key:            awssdk.String(key),
			Body:           body,
			ContentLength:  awssdk.Int64(size),
			IfNoneMatch:    awssdk.String("*"),
			ChecksumSHA256: awssdk.String(base64.StdEncoding.EncodeToString(sum)),
		}
		if s.lock != nil {
			// A locked write must name its checksum algorithm (or carry
			// Content-MD5); the SHA-256 above is that checksum.
			input.ChecksumAlgorithm = types.ChecksumAlgorithmSha256
			input.ObjectLockMode = types.ObjectLockMode(s.lock.Mode)
			input.ObjectLockRetainUntilDate = awssdk.Time(time.Now().Add(s.lock.Retention).UTC())
		}
		_, err := s.client.PutObject(ctx, input)
		return classify(err, name)
	})
}

// Get implements Store.
func (s *S3) Get(ctx context.Context, name string, w io.Writer, limit int64) (Object, error) {
	key, err := s.key(name)
	if err != nil {
		return Object{}, err
	}
	if limit <= 0 || limit > MaxObjectBytes {
		limit = MaxObjectBytes
	}
	var obj Object
	err = s.call(ctx, limit, func(ctx context.Context) error {
		out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: awssdk.String(s.bucket), Key: awssdk.String(key), ChecksumMode: types.ChecksumModeEnabled,
		})
		if err != nil {
			return classify(err, name)
		}
		defer func() { _ = out.Body.Close() }()
		if length := awssdk.ToInt64(out.ContentLength); length > limit {
			return fmt.Errorf("%w: %s is %d bytes (limit %d)", ErrTooLarge, name, length, limit)
		}
		digest := crypto.NewSHA256HMACDigest(nil)
		n, err := io.Copy(io.MultiWriter(w, digest), io.LimitReader(out.Body, limit+1))
		if err != nil {
			// The SDK validates the stored checksum as the body ends and reports a
			// mismatch with an unexported error; name it as the digest failure it is.
			if strings.Contains(err.Error(), "checksum did not match") {
				return fmt.Errorf("%w: %s: %v", ErrDigest, name, err)
			}
			return fmt.Errorf("objectstore: read %s: %w", name, err)
		}
		if n > limit {
			return fmt.Errorf("%w: %s exceeds %d bytes", ErrTooLarge, name, limit)
		}
		if length := out.ContentLength; length != nil && *length != n {
			return fmt.Errorf("objectstore: read %s: got %d of %d bytes", name, n, *length)
		}
		obj = Object{Name: name, Size: n, SHA256: digest.SHA256Hex()}
		if stored, ok := decodeChecksum(out.ChecksumSHA256); ok && stored != obj.SHA256 {
			return fmt.Errorf("%w: %s read back as sha256 %s, stored as %s", ErrDigest, name, obj.SHA256, stored)
		}
		return nil
	})
	return obj, err
}

// Head implements Store.
func (s *S3) Head(ctx context.Context, name string) (Object, error) {
	key, err := s.key(name)
	if err != nil {
		return Object{}, err
	}
	var obj Object
	err = s.call(ctx, 0, func(ctx context.Context) error {
		out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: awssdk.String(s.bucket), Key: awssdk.String(key), ChecksumMode: types.ChecksumModeEnabled,
		})
		if err != nil {
			return classify(err, name)
		}
		obj = Object{Name: name, Size: awssdk.ToInt64(out.ContentLength)}
		if stored, ok := decodeChecksum(out.ChecksumSHA256); ok {
			obj.SHA256 = stored
		}
		return nil
	})
	return obj, err
}

// List implements Store.
func (s *S3) List(ctx context.Context, prefix string, limit int) ([]Object, error) {
	if err := ValidName(prefix, true); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, errors.New("objectstore: list needs a positive limit")
	}
	var (
		out   []Object
		token *string
	)
	for {
		page := listPageSize
		if remaining := limit + 1 - len(out); remaining < page {
			page = remaining
		}
		var listed *s3.ListObjectsV2Output
		err := s.call(ctx, 0, func(ctx context.Context) error {
			var err error
			listed, err = s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
				Bucket: awssdk.String(s.bucket), Prefix: awssdk.String(s.root + prefix),
				MaxKeys: awssdk.Int32(int32(page)), ContinuationToken: token, // #nosec G115 -- page is at most listPageSize (CWE-190)
			})
			return classify(err, prefix)
		})
		if err != nil {
			return nil, err
		}
		for _, item := range listed.Contents {
			name, ok := strings.CutPrefix(awssdk.ToString(item.Key), s.root)
			if !ok || !strings.HasPrefix(name, prefix) {
				return nil, fmt.Errorf("objectstore: list %s returned %q outside the prefix", prefix, awssdk.ToString(item.Key))
			}
			out = append(out, Object{Name: name, Size: awssdk.ToInt64(item.Size)})
		}
		if len(out) > limit {
			return nil, fmt.Errorf("objectstore: more than %d objects under %s", limit, prefix)
		}
		if !awssdk.ToBool(listed.IsTruncated) || listed.NextContinuationToken == nil {
			return out, nil
		}
		token = listed.NextContinuationToken
	}
}

// Delete implements Store.
func (s *S3) Delete(ctx context.Context, name string) error {
	key, err := s.key(name)
	if err != nil {
		return err
	}
	return s.call(ctx, 0, func(ctx context.Context) error {
		_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: awssdk.String(s.bucket), Key: awssdk.String(key)})
		if err = classify(err, name); errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	})
}

// Location implements Store.
func (s *S3) Location(name string) string {
	return "s3://" + s.bucket + "/" + s.root + name
}

// NameOf implements Store.
func (s *S3) NameOf(location string) (string, error) {
	key, ok := strings.CutPrefix(location, "s3://"+s.bucket+"/")
	if !ok {
		return "", fmt.Errorf("%w: %q is not in bucket %s", ErrName, location, s.bucket)
	}
	name, ok := strings.CutPrefix(key, s.root)
	if !ok {
		return "", fmt.Errorf("%w: %q is outside the deployment prefix %q", ErrName, location, s.root)
	}
	if err := ValidName(name, false); err != nil {
		return "", err
	}
	return name, nil
}

// Destroy wipes the locked credentials and closes idle connections. The store
// refuses every later call. It is safe to call more than once.
func (s *S3) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.secretAccessKey != nil {
		s.secretAccessKey.Destroy()
		s.secretAccessKey = nil
	}
	if s.sessionToken != nil {
		s.sessionToken.Destroy()
		s.sessionToken = nil
	}
	s.mu.Unlock()
	if s.http != nil {
		s.http.CloseIdleConnections()
	}
}

type lockedCredentials struct{ store *S3 }

func (p lockedCredentials) Retrieve(context.Context) (awssdk.Credentials, error) {
	s := p.store
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.secretAccessKey == nil {
		return awssdk.Credentials{}, errors.New("objectstore: the store's credentials were destroyed")
	}
	var session []byte
	if s.sessionToken != nil {
		session = s.sessionToken.Bytes()
	}
	return awssdk.Credentials{
		AccessKeyID:     s.accessKeyID,
		SecretAccessKey: secrettext.String(s.secretAccessKey.Bytes()),
		SessionToken:    secrettext.String(session),
		Source:          "trstctl-object-store",
	}, nil
}

func decodeChecksum(value *string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(awssdk.ToString(value))
	if err != nil || len(raw) != 32 {
		return "", false
	}
	return hex.EncodeToString(raw), true
}

// classify maps the store's answers onto the errors callers act on.
func classify(err error, name string) error {
	if err == nil {
		return nil
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "PreconditionFailed":
			return fmt.Errorf("%w: %s", ErrExists, name)
		case "NoSuchKey", "NotFound":
			return fmt.Errorf("%w: %s", ErrNotFound, name)
		case "BadDigest", "InvalidDigest", "XAmzContentChecksumMismatch", "XAmzContentSHA256Mismatch":
			return fmt.Errorf("%w: %s: %v", ErrDigest, name, err)
		}
	}
	var response *awshttp.ResponseError
	if errors.As(err, &response) {
		switch response.HTTPStatusCode() {
		case http.StatusPreconditionFailed:
			return fmt.Errorf("%w: %s", ErrExists, name)
		case http.StatusNotFound:
			return fmt.Errorf("%w: %s", ErrNotFound, name)
		}
	}
	return fmt.Errorf("objectstore: %s: %w", name, err)
}
