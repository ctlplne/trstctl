// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers"
	"trstctl.com/trstctl/internal/secrettext"
)

// Azure Key Vault key authority source (A168-L1).
//
// It observes one vault's keys over the Key Vault REST API — the keys, each
// key's versions and the soft-deleted keys, read-only — and asserts each
// version's identity ("keys/{name}/{version}", how trstctl's managed-key
// record names it relative to the vault), its key type, whether it is enabled,
// and a deleted key awaiting purge. By default it asserts only the keys
// trstctl created: their names carry trstctl's operation prefix
// (internal/kms/azurekv azureOperationKeyName). A key tagged as another
// tenant's is never asserted. It pairs with the managed-key authority for
// provider azure-kv.
//
// The bearer token is read from a file at each observation and wiped once the
// observation ends; nextLink is followed only on the vault's own host.

const (
	azureKVSourceTimeout = 30 * time.Second
	azureKVSourceMaxBody = 4 << 20
	// azureKVSourceMaxVersions bounds one observation.
	azureKVSourceMaxVersions = 10000
	azureKVSourceMaxPages    = 200
	// AzureKVSourceAPIVersion is the Key Vault data-plane API version.
	AzureKVSourceAPIVersion = "7.4"
	// azureKVTenantTag names the tenant a key trstctl created belongs to
	// (internal/kms/azurekv tenantTagKey).
	azureKVTenantTag = "trstctl-tenant"
)

// azureKVManagedPrefixes are the prefixes of the key names trstctl creates
// (internal/kms/azurekv azureOperationKeyName).
var azureKVManagedPrefixes = []string{"trstctl-generate-", "trstctl-rotate-"}

// AzureKVKeySourceConfig is the core-owned shape operator config maps onto.
type AzureKVKeySourceConfig struct {
	AuthorityID string
	// VaultURL is https://{vault}.vault.azure.net (or a private endpoint, a
	// stand-in).
	VaultURL  string
	TokenFile string
	// AllCustomerKeys asserts every key in the vault, not only trstctl's.
	AllCustomerKeys bool
	// MaxObjects bounds one observation; zero means azureKVSourceMaxVersions.
	MaxObjects            int
	AllowInsecureLoopback bool
	PrivateEndpointCIDRs  []netip.Prefix
	HTTPClient            *http.Client
	Now                   func() time.Time
	// KeyDatesSince, when set, asserts the creation and purge dates of key
	// versions Key Vault created at or after it (A168-L3).
	KeyDatesSince time.Time
}

var errAzureKVSourceConfig = errors.New("xrec azure key vault source: configuration")

type azureKVKeySource struct {
	cfg    AzureKVKeySourceConfig
	client *http.Client
	vault  *url.URL
}

var _ reducers.CloudKMSInventorySource = (*azureKVKeySource)(nil)

func newAzureKVKeySource(cfg AzureKVKeySourceConfig) (*azureKVKeySource, error) {
	cfg.AuthorityID = strings.TrimSpace(cfg.AuthorityID)
	vault, err := url.Parse(strings.TrimRight(strings.TrimSpace(cfg.VaultURL), "/"))
	if cfg.AuthorityID == "" || err != nil || vault.Host == "" || (vault.Scheme != "https" && vault.Scheme != "http") || vault.Path != "" || vault.RawQuery != "" {
		return nil, fmt.Errorf("%w: authority id and a vault URL with no path required", errAzureKVSourceConfig)
	}
	if vault.Scheme == "http" && !cfg.AllowInsecureLoopback {
		return nil, fmt.Errorf("%w: plain http needs allow_insecure_loopback", errAzureKVSourceConfig)
	}
	if strings.TrimSpace(cfg.TokenFile) == "" {
		return nil, fmt.Errorf("%w: token_file required", errAzureKVSourceConfig)
	}
	if cfg.MaxObjects <= 0 {
		cfg.MaxObjects = azureKVSourceMaxVersions
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	client := cfg.HTTPClient
	if client == nil {
		client = cloudKMSSourceClient(azureKVSourceTimeout, cfg.AllowInsecureLoopback, cfg.PrivateEndpointCIDRs)
	}
	return &azureKVKeySource{cfg: cfg, client: client, vault: vault}, nil
}

type azureKVKeyItem struct {
	Kid        string            `json:"kid"`
	Tags       map[string]string `json:"tags"`
	Managed    bool              `json:"managed"`
	Attributes struct {
		Enabled            bool  `json:"enabled"`
		ScheduledPurgeDate int64 `json:"scheduledPurgeDate"`
	} `json:"attributes"`
}

// CloudKMSSnapshot implements reducers.CloudKMSInventorySource.
func (s *azureKVKeySource) CloudKMSSnapshot(ctx context.Context, tenantID string, sb *reducers.ObservationSandbox) (reducers.CloudKMSSnapshot, error) {
	if sb == nil {
		sb = reducers.NewObservationSandbox(reducers.ReadOnlyObservationGrant(s.cfg.AuthorityID), nil)
	}
	token, err := readSourceToken(s.cfg.TokenFile, "xrec azure key vault source")
	if err != nil {
		return reducers.CloudKMSSnapshot{}, err
	}
	defer secret.Wipe(token)
	now := s.cfg.Now().UTC()
	snap := reducers.CloudKMSSnapshot{Watermark: storeWatermark("azure-kv:"+s.cfg.AuthorityID, now)}
	if _, err := sb.List(ctx, s.resource("keys")); err != nil {
		return reducers.CloudKMSSnapshot{}, fmt.Errorf("xrec azure key vault source: list keys: %w", err)
	}
	var keys []azureKVKeyItem
	if err := s.list(ctx, token, "/keys", func(page []azureKVKeyItem) { keys = append(keys, page...) }); err != nil {
		return reducers.CloudKMSSnapshot{}, err
	}
	versions := 0
	add := func(key reducers.CloudKMSKey) error {
		versions++
		if versions > s.cfg.MaxObjects {
			return fmt.Errorf("xrec azure key vault source: the vault holds more than %d key versions; raise max_objects rather than observe part of it", s.cfg.MaxObjects)
		}
		snap.Keys = append(snap.Keys, key)
		return nil
	}
	for _, key := range keys {
		name, _ := azureKVKeyNameVersion(key.Kid)
		if name == "" || key.Managed || !s.asserts(name, key.Tags, tenantID) {
			continue
		}
		if _, err := sb.Describe(ctx, s.resource("keys", name)); err != nil {
			return reducers.CloudKMSSnapshot{}, fmt.Errorf("xrec azure key vault source: describe %s: %w", name, err)
		}
		var versionItems []azureKVKeyItem
		if err := s.list(ctx, token, "/keys/"+url.PathEscape(name)+"/versions", func(page []azureKVKeyItem) { versionItems = append(versionItems, page...) }); err != nil {
			return reducers.CloudKMSSnapshot{}, err
		}
		for _, version := range versionItems {
			vname, vid := azureKVKeyNameVersion(version.Kid)
			if vname != name || vid == "" {
				continue
			}
			status := canon.StatusDisabled
			if version.Attributes.Enabled {
				status = canon.StatusActive
			}
			// The list carries no key type; the version's bundle does.
			var bundle azureKVKeyBundle
			if err := s.get(ctx, token, s.link("/keys/"+url.PathEscape(name)+"/"+url.PathEscape(vid)), &bundle); err != nil {
				return reducers.CloudKMSSnapshot{}, err
			}
			id := "keys/" + name + "/" + vid
			created, deletion := bundle.dates(s.cfg.KeyDatesSince)
			if err := add(reducers.CloudKMSKey{KeyID: id, AlgorithmSpec: bundle.Key.algorithm(), Status: status, NativeID: version.Kid,
				CreatedAt: created, DeletedAt: deletion}); err != nil {
				return reducers.CloudKMSSnapshot{}, err
			}
		}
	}
	// A deleted key is listed under deletedkeys until it is purged: trstctl's
	// zeroize leaves it there, so its versions read as pending deletion.
	if _, err := sb.List(ctx, s.resource("deletedkeys")); err != nil {
		return reducers.CloudKMSSnapshot{}, fmt.Errorf("xrec azure key vault source: list deleted keys: %w", err)
	}
	var deleted []azureKVKeyItem
	if err := s.list(ctx, token, "/deletedkeys", func(page []azureKVKeyItem) { deleted = append(deleted, page...) }); err != nil {
		return reducers.CloudKMSSnapshot{}, err
	}
	for _, key := range deleted {
		name, _ := azureKVKeyNameVersion(key.Kid)
		if name == "" || key.Managed || !s.asserts(name, key.Tags, tenantID) {
			continue
		}
		// The deleted key's bundle names its version and key type.
		var bundle azureKVKeyBundle
		if err := s.get(ctx, token, s.link("/deletedkeys/"+url.PathEscape(name)), &bundle); err != nil {
			return reducers.CloudKMSSnapshot{}, err
		}
		bname, vid := azureKVKeyNameVersion(bundle.Key.Kid)
		if bname != name || vid == "" {
			continue
		}
		created, deletion := bundle.dates(s.cfg.KeyDatesSince)
		if err := add(reducers.CloudKMSKey{KeyID: "keys/" + name + "/" + vid, AlgorithmSpec: bundle.Key.algorithm(),
			Status: canon.StatusPendingDeletion, NativeID: bundle.Key.Kid, CreatedAt: created, DeletedAt: deletion}); err != nil {
			return reducers.CloudKMSSnapshot{}, err
		}
	}
	sort.Slice(snap.Keys, func(i, j int) bool { return snap.Keys[i].KeyID < snap.Keys[j].KeyID })
	return snap, nil
}

// azureKVKeyBundle is the part of a key bundle (or deleted key bundle) the
// source reads: the version's identifier and its public key's type.
type azureKVKeyBundle struct {
	Key azureKVJSONWebKey `json:"key"`
	// A168-L3: the version's created attribute, and a deleted key's
	// scheduled purge date.
	Attributes struct {
		Created int64 `json:"created"`
	} `json:"attributes"`
	ScheduledPurgeDate int64 `json:"scheduledPurgeDate"`
}

// dates are the bundle's asserted dates under since (A168-L3).
func (b azureKVKeyBundle) dates(since time.Time) (time.Time, time.Time) {
	var created, purge time.Time
	if b.Attributes.Created > 0 {
		created = time.Unix(b.Attributes.Created, 0).UTC()
	}
	if b.ScheduledPurgeDate > 0 {
		purge = time.Unix(b.ScheduledPurgeDate, 0).UTC()
	}
	return cloudKMSKeyDates(since, created, purge)
}

type azureKVJSONWebKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	N   string `json:"n"`
}

// algorithm spells the key the way trstctl's managed-key record does: an EC
// key by its curve, an RSA key by its modulus size.
func (k azureKVJSONWebKey) algorithm() string {
	switch strings.TrimSuffix(k.Kty, "-HSM") {
	case "EC":
		switch k.Crv {
		case "P-256":
			return "ECDSA-P256"
		case "P-384":
			return "ECDSA-P384"
		case "P-521":
			return "ECDSA-P521"
		}
		return "EC-" + k.Crv
	case "RSA":
		modulus, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.N, "="))
		if err != nil || len(modulus) == 0 {
			return "RSA"
		}
		for len(modulus) > 0 && modulus[0] == 0 {
			modulus = modulus[1:]
		}
		return "RSA-" + strconv.Itoa(len(modulus)*8)
	}
	return k.Kty
}

// link is a vault URL for path with the API version.
func (s *azureKVKeySource) link(path string) string {
	u := *s.vault
	u.Path = path
	u.RawQuery = url.Values{"api-version": {AzureKVSourceAPIVersion}}.Encode()
	return u.String()
}

// asserts: never a key tagged as another tenant's, and by default only
// trstctl's.
func (s *azureKVKeySource) asserts(name string, tags map[string]string, tenantID string) bool {
	if tenant := strings.TrimSpace(tags[azureKVTenantTag]); tenant != "" && tenant != strings.TrimSpace(tenantID) {
		return false
	}
	if s.cfg.AllCustomerKeys {
		return true
	}
	for _, prefix := range azureKVManagedPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// azureKVKeyNameVersion splits a key identifier
// (https://{vault}/keys|deletedkeys/{name}[/{version}]) into its name and
// version.
func azureKVKeyNameVersion(kid string) (string, string) {
	u, err := url.Parse(kid)
	if err != nil {
		return "", ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || (parts[0] != "keys" && parts[0] != "deletedkeys") {
		return "", ""
	}
	if len(parts) >= 3 {
		return parts[1], parts[2]
	}
	return parts[1], ""
}

// list GETs every page of a Key Vault list, following nextLink only on the
// vault's own host.
func (s *azureKVKeySource) list(ctx context.Context, token []byte, path string, visit func([]azureKVKeyItem)) error {
	next := *s.vault
	next.Path = path
	next.RawQuery = url.Values{"api-version": {AzureKVSourceAPIVersion}, "maxresults": {"25"}}.Encode()
	link := next.String()
	for page := 0; page < azureKVSourceMaxPages; page++ {
		var body struct {
			Value    []azureKVKeyItem `json:"value"`
			NextLink string           `json:"nextLink"`
		}
		if err := s.get(ctx, token, link, &body); err != nil {
			return err
		}
		visit(body.Value)
		if body.NextLink == "" {
			return nil
		}
		u, err := url.Parse(body.NextLink)
		if err != nil || u.Scheme != s.vault.Scheme || u.Host != s.vault.Host {
			return errors.New("xrec azure key vault source: a nextLink leaves the vault")
		}
		link = body.NextLink
	}
	return fmt.Errorf("xrec azure key vault source: %s: more than %d pages", path, azureKVSourceMaxPages)
}

func (s *azureKVKeySource) get(ctx context.Context, token []byte, link string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("xrec azure key vault source: GET: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, azureKVSourceMaxBody))
	if err != nil {
		return fmt.Errorf("xrec azure key vault source: read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("xrec azure key vault source: status %d (response body redacted)", resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("xrec azure key vault source: decode response: %w", err)
	}
	return nil
}

// resource names what the sandbox is asked to allow.
func (s *azureKVKeySource) resource(parts ...string) string {
	return s.cfg.AuthorityID + "/azure-kv/" + strings.Join(parts, "/")
}
