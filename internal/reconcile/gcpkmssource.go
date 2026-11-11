// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"bytes"
	"context"
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

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers"
	"trstctl.com/trstctl/internal/secrettext"
)

// GCP Cloud KMS authority source (A168-L1).
//
// It observes one key ring over the Cloud KMS REST API — the ring's crypto
// keys and each key's versions, read-only — and asserts each version's
// identity (its resource name, which is how trstctl's managed-key record names
// it), algorithm, state and whether the key rotates on a schedule. By default
// it asserts only the keys trstctl created: their IDs carry trstctl's
// operation prefix (internal/kms/gcpkms gcpOperationKeyID). A key labelled as
// another tenant's is never asserted, so a tenant's round over a key ring
// several tenants share reads only its own keys and unlabelled keys created
// before the tenant label existed. It pairs with the managed-key authority for
// provider gcp-kms.
//
// The bearer token is read from a file at each observation and wiped once the
// observation ends; every list passes the observation sandbox first.

const (
	gcpKMSSourceTimeout = 30 * time.Second
	gcpKMSSourceMaxBody = 4 << 20
	// gcpKMSSourceMaxVersions bounds one observation; a ring holding more key
	// versions fails the observation rather than yield a partial inventory.
	gcpKMSSourceMaxVersions = 10000
	gcpKMSSourceMaxPages    = 200
	// gcpKMSTenantLabel names the tenant a key trstctl created belongs to
	// (internal/kms/gcpkms tenantLabelKey).
	gcpKMSTenantLabel = "trstctl-tenant"
)

// gcpKMSManagedPrefixes are the prefixes of the crypto key IDs trstctl
// creates (internal/kms/gcpkms gcpOperationKeyID).
var gcpKMSManagedPrefixes = []string{"trstctl-g-", "trstctl-r-"}

// GCPKMSSourceConfig is the core-owned shape operator config maps onto.
type GCPKMSSourceConfig struct {
	AuthorityID string
	// KeyRing is the ring's resource name:
	// projects/{project}/locations/{location}/keyRings/{ring}.
	KeyRing string
	// Address overrides https://cloudkms.googleapis.com (a private endpoint,
	// a stand-in).
	Address   string
	TokenFile string
	// AllCustomerKeys asserts every key in the ring, not only trstctl's.
	AllCustomerKeys bool
	// MaxObjects bounds one observation; zero means gcpKMSSourceMaxVersions.
	MaxObjects            int
	AllowInsecureLoopback bool
	PrivateEndpointCIDRs  []netip.Prefix
	HTTPClient            *http.Client
	Now                   func() time.Time
}

var errGCPKMSSourceConfig = errors.New("xrec gcp kms source: configuration")

type gcpKMSSource struct {
	cfg      GCPKMSSourceConfig
	client   *http.Client
	endpoint string
}

var _ reducers.CloudKMSInventorySource = (*gcpKMSSource)(nil)

func newGCPKMSSource(cfg GCPKMSSourceConfig) (*gcpKMSSource, error) {
	cfg.AuthorityID, cfg.KeyRing = strings.TrimSpace(cfg.AuthorityID), strings.Trim(strings.TrimSpace(cfg.KeyRing), "/")
	if cfg.AuthorityID == "" || !gcpKeyRingName(cfg.KeyRing) {
		return nil, fmt.Errorf("%w: authority id and key_ring (projects/P/locations/L/keyRings/R) required", errGCPKMSSourceConfig)
	}
	if strings.TrimSpace(cfg.TokenFile) == "" {
		return nil, fmt.Errorf("%w: token_file required", errGCPKMSSourceConfig)
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Address), "/")
	if endpoint == "" {
		endpoint = "https://cloudkms.googleapis.com"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("%w: address must be an http(s) URL with no path", errGCPKMSSourceConfig)
	}
	if u.Scheme == "http" && !cfg.AllowInsecureLoopback {
		return nil, fmt.Errorf("%w: plain http needs allow_insecure_loopback", errGCPKMSSourceConfig)
	}
	if cfg.MaxObjects <= 0 {
		cfg.MaxObjects = gcpKMSSourceMaxVersions
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	client := cfg.HTTPClient
	if client == nil {
		client = cloudKMSSourceClient(gcpKMSSourceTimeout, cfg.AllowInsecureLoopback, cfg.PrivateEndpointCIDRs)
	}
	return &gcpKMSSource{cfg: cfg, client: client, endpoint: endpoint}, nil
}

// gcpKeyRingName accepts projects/{p}/locations/{l}/keyRings/{r} with plain
// segments.
func gcpKeyRingName(name string) bool {
	parts := strings.Split(name, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "keyRings" {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "?#%\\ \t\r\n") {
			return false
		}
	}
	return true
}

// cloudKMSSourceClient is the SSRF-safe client a cloud KMS source dials with.
func cloudKMSSourceClient(timeout time.Duration, loopback bool, private []netip.Prefix) *http.Client {
	opts := netsec.SafeClientOptions{AllowPrivateCIDRs: append([]netip.Prefix(nil), private...)}
	if loopback {
		opts.AllowPrivateCIDRs = append(opts.AllowPrivateCIDRs, netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"))
	}
	return netsec.SafeClientWithOptions(timeout, opts)
}

// CloudKMSSnapshot implements reducers.CloudKMSInventorySource.
func (s *gcpKMSSource) CloudKMSSnapshot(ctx context.Context, tenantID string, sb *reducers.ObservationSandbox) (reducers.CloudKMSSnapshot, error) {
	if sb == nil {
		sb = reducers.NewObservationSandbox(reducers.ReadOnlyObservationGrant(s.cfg.AuthorityID), nil)
	}
	token, err := readSourceToken(s.cfg.TokenFile, "xrec gcp kms source")
	if err != nil {
		return reducers.CloudKMSSnapshot{}, err
	}
	defer secret.Wipe(token)
	now := s.cfg.Now().UTC()
	snap := reducers.CloudKMSSnapshot{Watermark: storeWatermark("gcp-kms:"+s.cfg.AuthorityID, now)}
	if _, err := sb.List(ctx, s.resource("cryptoKeys")); err != nil {
		return reducers.CloudKMSSnapshot{}, fmt.Errorf("xrec gcp kms source: list keys: %w", err)
	}
	var keys []gcpCryptoKey
	if err := s.list(ctx, token, s.cfg.KeyRing+"/cryptoKeys", func(raw json.RawMessage) (int, error) {
		var page struct {
			CryptoKeys []gcpCryptoKey `json:"cryptoKeys"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return 0, err
		}
		keys = append(keys, page.CryptoKeys...)
		return len(page.CryptoKeys), nil
	}); err != nil {
		return reducers.CloudKMSSnapshot{}, err
	}
	versions := 0
	for _, key := range keys {
		if !s.asserts(key, tenantID) {
			continue
		}
		if _, err := sb.Describe(ctx, s.resource("cryptoKeys", lastPathSegment(key.Name))); err != nil {
			return reducers.CloudKMSSnapshot{}, fmt.Errorf("xrec gcp kms source: describe %s: %w", lastPathSegment(key.Name), err)
		}
		if !strings.HasPrefix(key.Name, s.cfg.KeyRing+"/cryptoKeys/") {
			return reducers.CloudKMSSnapshot{}, fmt.Errorf("xrec gcp kms source: key %q is not in key ring %s", key.Name, s.cfg.KeyRing)
		}
		if err := s.list(ctx, token, key.Name+"/cryptoKeyVersions", func(raw json.RawMessage) (int, error) {
			var page struct {
				CryptoKeyVersions []struct {
					Name      string `json:"name"`
					State     string `json:"state"`
					Algorithm string `json:"algorithm"`
				} `json:"cryptoKeyVersions"`
			}
			if err := json.Unmarshal(raw, &page); err != nil {
				return 0, err
			}
			for _, version := range page.CryptoKeyVersions {
				status, asserted := gcpKMSVersionStatus(version.State)
				if !asserted {
					continue
				}
				versions++
				if versions > s.cfg.MaxObjects {
					return 0, fmt.Errorf("the key ring holds more than %d key versions; raise max_objects rather than observe part of it", s.cfg.MaxObjects)
				}
				// Creation and destruction times are not asserted, as for AWS:
				// the managed-key record notes when its operation completed.
				snap.Keys = append(snap.Keys, reducers.CloudKMSKey{
					KeyID: version.Name, AlgorithmSpec: gcpKMSAlgorithm(version.Algorithm), Status: status,
					RotationEnabled: key.RotationPeriod != "", NativeID: version.Name,
				})
			}
			return len(page.CryptoKeyVersions), nil
		}); err != nil {
			return reducers.CloudKMSSnapshot{}, err
		}
	}
	sort.Slice(snap.Keys, func(i, j int) bool { return snap.Keys[i].KeyID < snap.Keys[j].KeyID })
	return snap, nil
}

type gcpCryptoKey struct {
	Name           string            `json:"name"`
	Purpose        string            `json:"purpose"`
	RotationPeriod string            `json:"rotationPeriod"`
	Labels         map[string]string `json:"labels"`
}

// asserts decides whether this authority asserts the key in tenantID's round:
// never a key labelled as another tenant's, and by default only trstctl's.
func (s *gcpKMSSource) asserts(key gcpCryptoKey, tenantID string) bool {
	if tenant := strings.TrimSpace(key.Labels[gcpKMSTenantLabel]); tenant != "" && tenant != strings.TrimSpace(tenantID) {
		return false
	}
	if s.cfg.AllCustomerKeys {
		return true
	}
	id := lastPathSegment(key.Name)
	for _, prefix := range gcpKMSManagedPrefixes {
		if strings.HasPrefix(id, prefix) {
			return true
		}
	}
	return false
}

// gcpKMSVersionStatus maps Cloud KMS version states onto the canonical
// vocabulary. A destroyed version is gone and not asserted; a version still
// being generated or imported is unknown rather than guessed.
func gcpKMSVersionStatus(state string) (string, bool) {
	switch state {
	case "ENABLED":
		return canon.StatusActive, true
	case "DISABLED":
		return canon.StatusDisabled, true
	case "DESTROY_SCHEDULED":
		return canon.StatusPendingDeletion, true
	case "DESTROYED":
		return "", false
	default:
		return canon.StatusUnknown, true
	}
}

// gcpKMSAlgorithm spells a Cloud KMS version algorithm the way trstctl's
// managed-key record does (internal/kms/gcpkms versionAlgorithm in reverse);
// an algorithm trstctl does not manage keeps Cloud KMS's own name.
func gcpKMSAlgorithm(algorithm string) string {
	switch {
	case strings.HasPrefix(algorithm, "EC_SIGN_P256_"):
		return "ECDSA-P256"
	case strings.HasPrefix(algorithm, "EC_SIGN_P384_"):
		return "ECDSA-P384"
	case algorithm == "EC_SIGN_ED25519":
		return "Ed25519"
	case strings.HasPrefix(algorithm, "RSA_"):
		for _, bits := range []string{"2048", "3072", "4096"} {
			if strings.Contains(algorithm, "_"+bits) {
				return "RSA-" + bits
			}
		}
	case strings.HasPrefix(algorithm, "PQ_SIGN_ML_DSA_"):
		return "ML-DSA-" + strings.TrimPrefix(algorithm, "PQ_SIGN_ML_DSA_")
	}
	return algorithm
}

// list GETs every page of a Cloud KMS list (pageToken), handing each page to
// visit, which returns how many items it held.
func (s *gcpKMSSource) list(ctx context.Context, token []byte, path string, visit func(json.RawMessage) (int, error)) error {
	pageToken := ""
	for page := 0; page < gcpKMSSourceMaxPages; page++ {
		query := url.Values{"pageSize": {"1000"}}
		if pageToken != "" {
			query.Set("pageToken", pageToken)
		}
		raw, err := s.get(ctx, token, "/v1/"+path+"?"+query.Encode())
		if err != nil {
			return err
		}
		if _, err := visit(raw); err != nil {
			return fmt.Errorf("xrec gcp kms source: %s: %w", path, err)
		}
		var next struct {
			NextPageToken string `json:"nextPageToken"`
		}
		_ = json.Unmarshal(raw, &next)
		if pageToken = next.NextPageToken; pageToken == "" {
			return nil
		}
	}
	return fmt.Errorf("xrec gcp kms source: %s: more than %d pages", path, gcpKMSSourceMaxPages)
}

func (s *gcpKMSSource) get(ctx context.Context, token []byte, pathAndQuery string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+pathAndQuery, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("xrec gcp kms source: GET: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, gcpKMSSourceMaxBody))
	if err != nil {
		return nil, fmt.Errorf("xrec gcp kms source: read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("xrec gcp kms source: status %d (response body redacted)", resp.StatusCode)
	}
	return raw, nil
}

// resource names what the sandbox is asked to allow, under the authority's
// own scope as the read-only grant requires.
func (s *gcpKMSSource) resource(parts ...string) string {
	return s.cfg.AuthorityID + "/gcp-kms/" + strings.Join(parts, "/")
}

// readSourceToken reads a bearer token file; the caller wipes it.
func readSourceToken(path, who string) ([]byte, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured credential file path (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("%s: read token file: %w", who, err)
	}
	token := bytes.TrimSpace(raw)
	if len(token) == 0 {
		secret.Wipe(raw)
		return nil, fmt.Errorf("%s: the token file is empty", who)
	}
	out := append([]byte(nil), token...)
	secret.Wipe(raw)
	return out, nil
}

func lastPathSegment(name string) string {
	name = strings.TrimRight(name, "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}
