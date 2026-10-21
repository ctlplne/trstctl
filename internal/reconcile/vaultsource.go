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
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers"
	"trstctl.com/trstctl/internal/secrettext"
)

// Vault authority source (A10).
//
// Until A10 the "vault" reducer was registered with a nil source: a scheduled
// round naming it failed observation closed and logged. This adapter observes a
// HashiCorp Vault or OpenBao server over its HTTP API and projects what it
// asserts onto the shared canonical vocabulary:
//
//   - KV v2 secrets from the configured mounts, from METADATA only. The data
//     path is never requested: the observation records that a secret exists at
//     a path, its current version and when it was created or deleted, and
//     nothing about its value.
//   - PKI-issued certificates from the configured mounts: issuer name DER and
//     serial (the identity two authorities can agree on), key algorithm,
//     validity, subject and revocation standing.
//   - Transit keys from the configured mounts: name, key type and version
//     creation time.
//
// Every list and read passes through the observation sandbox first, so the
// read-only grant decides what may be asked before anything is dialed. The
// token is read from a file at each observation (operator-rotated, never held
// in config) and wiped after the request headers are built.

const (
	vaultSourceTimeout      = 30 * time.Second
	vaultSourceMaxBody      = 8 << 20
	vaultSourceMaxSecrets   = 20000
	vaultSourceMaxCerts     = 20000
	vaultSourceMaxKeys      = 5000
	vaultSourceMaxListDepth = 64
)

// VaultSourceConfig is the core-owned shape operator config maps onto. No XREC
// type leaks into config: cmd maps config.ReconcileAuthoritySource here.
type VaultSourceConfig struct {
	AuthorityID   string
	Address       string
	Namespace     string
	TokenFile     string
	KVMounts      []string
	PKIMounts     []string
	TransitMounts []string
	// AllowInsecureLoopback permits plain http and loopback dialing (lab,
	// sidecar); PrivateEndpointCIDRs widens the SSRF-safe dialer to operator
	// ranges. HTTPClient overrides the client entirely (tests).
	AllowInsecureLoopback bool
	PrivateEndpointCIDRs  []netip.Prefix
	HTTPClient            *http.Client
}

var errVaultSourceConfig = errors.New("xrec vault source: configuration")

type vaultSource struct {
	cfg    VaultSourceConfig
	client *http.Client
	base   string
}

func newVaultSource(cfg VaultSourceConfig) (*vaultSource, error) {
	cfg.AuthorityID = strings.TrimSpace(cfg.AuthorityID)
	if cfg.AuthorityID == "" {
		return nil, fmt.Errorf("%w: authority id required", errVaultSourceConfig)
	}
	address := strings.TrimRight(strings.TrimSpace(cfg.Address), "/")
	u, err := url.Parse(address)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("%w: address must be an http(s) URL", errVaultSourceConfig)
	}
	if u.Scheme == "http" && !cfg.AllowInsecureLoopback {
		return nil, fmt.Errorf("%w: plain http needs allow_insecure_loopback", errVaultSourceConfig)
	}
	if strings.TrimSpace(cfg.TokenFile) == "" {
		return nil, fmt.Errorf("%w: token file required", errVaultSourceConfig)
	}
	if len(cfg.KVMounts)+len(cfg.PKIMounts)+len(cfg.TransitMounts) == 0 {
		return nil, fmt.Errorf("%w: at least one mount required", errVaultSourceConfig)
	}
	client := cfg.HTTPClient
	if client == nil {
		opts := netsec.SafeClientOptions{AllowPrivateCIDRs: append([]netip.Prefix(nil), cfg.PrivateEndpointCIDRs...)}
		if cfg.AllowInsecureLoopback {
			opts.AllowPrivateCIDRs = append(opts.AllowPrivateCIDRs, netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"))
		}
		client = netsec.SafeClientWithOptions(vaultSourceTimeout, opts)
	}
	return &vaultSource{cfg: cfg, client: client, base: address}, nil
}

// VaultSnapshot implements reducers.VaultInventorySource.
func (v *vaultSource) VaultSnapshot(ctx context.Context, tenantID string, sb *reducers.ObservationSandbox) (reducers.VaultSnapshot, error) {
	if sb == nil {
		sb = reducers.NewObservationSandbox(reducers.ReadOnlyObservationGrant(v.cfg.AuthorityID), nil)
	}
	now := time.Now().UTC()
	snap := reducers.VaultSnapshot{Watermark: storeWatermark("vault:"+v.cfg.AuthorityID, now)}
	for _, mount := range v.cfg.KVMounts {
		refs, err := v.kvSecrets(ctx, sb, cleanMount(mount))
		if err != nil {
			return reducers.VaultSnapshot{}, err
		}
		snap.Secrets = append(snap.Secrets, refs...)
	}
	for _, mount := range v.cfg.PKIMounts {
		certs, err := v.pkiCertificates(ctx, sb, cleanMount(mount), now)
		if err != nil {
			return reducers.VaultSnapshot{}, err
		}
		snap.PKICertificates = append(snap.PKICertificates, certs...)
	}
	for _, mount := range v.cfg.TransitMounts {
		keys, err := v.transitKeys(ctx, sb, cleanMount(mount))
		if err != nil {
			return reducers.VaultSnapshot{}, err
		}
		snap.Keys = append(snap.Keys, keys...)
	}
	_ = tenantID // one Vault per authority; the tenant scopes the round, not the server
	return snap, nil
}

// --- KV v2 ---------------------------------------------------------------

type vaultKVMetadata struct {
	CreatedTime    string `json:"created_time"`
	UpdatedTime    string `json:"updated_time"`
	CurrentVersion int    `json:"current_version"`
	Versions       map[string]struct {
		CreatedTime  string `json:"created_time"`
		DeletionTime string `json:"deletion_time"`
		Destroyed    bool   `json:"destroyed"`
	} `json:"versions"`
}

func (v *vaultSource) kvSecrets(ctx context.Context, sb *reducers.ObservationSandbox, mount string) ([]reducers.VaultSecretRef, error) {
	paths, err := v.kvListRecursive(ctx, sb, mount, "", 0, nil)
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	out := make([]reducers.VaultSecretRef, 0, len(paths))
	for _, p := range paths {
		if _, err := sb.Describe(ctx, v.resource("kv", mount, "metadata", p)); err != nil {
			return nil, fmt.Errorf("xrec vault source: kv %s/%s: %w", mount, p, err)
		}
		var env struct {
			Data vaultKVMetadata `json:"data"`
		}
		if err := v.getJSON(ctx, v.endpoint(mount, "metadata", p), &env); err != nil {
			return nil, fmt.Errorf("xrec vault source: kv metadata %s/%s: %w", mount, p, err)
		}
		md := env.Data
		ref := reducers.VaultSecretRef{
			Namespace:                mount,
			Path:                     p,
			Status:                   canon.StatusActive,
			CreatedAt:                parseVaultTime(md.CreatedTime),
			ProviderVersionID:        strconv.Itoa(md.CurrentVersion),
			ProviderNativeResourceID: mount + "/data/" + p,
		}
		if cur, ok := md.Versions[strconv.Itoa(md.CurrentVersion)]; ok {
			if t := parseVaultTime(cur.CreatedTime); !t.IsZero() {
				ref.CreatedAt = t
			}
			switch {
			case cur.Destroyed:
				// Destroyed: the data is gone for good; the path remains.
				ref.Status = canon.StatusDisabled
				ref.DeletedAt = parseVaultTime(cur.DeletionTime)
			case cur.DeletionTime != "":
				// Soft-deleted: recoverable until destroyed.
				ref.Status = canon.StatusPendingDeletion
				ref.DeletedAt = parseVaultTime(cur.DeletionTime)
			}
		}
		out = append(out, ref)
	}
	return out, nil
}

func (v *vaultSource) kvListRecursive(ctx context.Context, sb *reducers.ObservationSandbox, mount, prefix string, depth int, acc []string) ([]string, error) {
	if depth > vaultSourceMaxListDepth {
		return nil, fmt.Errorf("xrec vault source: kv %s/%s: listing deeper than %d levels", mount, prefix, vaultSourceMaxListDepth)
	}
	if _, err := sb.List(ctx, v.resource("kv", mount, "metadata", prefix)); err != nil {
		return nil, fmt.Errorf("xrec vault source: kv list %s/%s: %w", mount, prefix, err)
	}
	keys, err := v.list(ctx, v.endpoint(mount, "metadata", prefix))
	if err != nil {
		return nil, fmt.Errorf("xrec vault source: kv list %s/%s: %w", mount, prefix, err)
	}
	for _, k := range keys {
		if strings.HasSuffix(k, "/") {
			acc, err = v.kvListRecursive(ctx, sb, mount, joinPath(prefix, strings.TrimSuffix(k, "/")), depth+1, acc)
			if err != nil {
				return nil, err
			}
			continue
		}
		acc = append(acc, joinPath(prefix, k))
		if len(acc) > vaultSourceMaxSecrets {
			return nil, fmt.Errorf("xrec vault source: kv %s lists more than %d secrets", mount, vaultSourceMaxSecrets)
		}
	}
	return acc, nil
}

// --- PKI ------------------------------------------------------------------

func (v *vaultSource) pkiCertificates(ctx context.Context, sb *reducers.ObservationSandbox, mount string, now time.Time) ([]reducers.VaultPKICertificate, error) {
	if _, err := sb.List(ctx, v.resource("pki", mount, "certs", "")); err != nil {
		return nil, fmt.Errorf("xrec vault source: pki list %s: %w", mount, err)
	}
	serials, err := v.list(ctx, v.endpoint(mount, "certs", ""))
	if err != nil {
		return nil, fmt.Errorf("xrec vault source: pki list %s: %w", mount, err)
	}
	if len(serials) > vaultSourceMaxCerts {
		return nil, fmt.Errorf("xrec vault source: pki %s lists more than %d certificates", mount, vaultSourceMaxCerts)
	}
	sort.Strings(serials)
	out := make([]reducers.VaultPKICertificate, 0, len(serials))
	for _, serial := range serials {
		if _, err := sb.Describe(ctx, v.resource("pki", mount, "cert", serial)); err != nil {
			return nil, fmt.Errorf("xrec vault source: pki cert %s/%s: %w", mount, serial, err)
		}
		var env struct {
			Data struct {
				Certificate    string `json:"certificate"`
				RevocationTime int64  `json:"revocation_time"`
			} `json:"data"`
		}
		if err := v.getJSON(ctx, v.endpoint(mount, "cert", serial), &env); err != nil {
			return nil, fmt.Errorf("xrec vault source: pki cert %s/%s: %w", mount, serial, err)
		}
		facts, err := crypto.CertificateFactsFromPEM([]byte(env.Data.Certificate))
		if err != nil {
			return nil, fmt.Errorf("xrec vault source: pki cert %s/%s: %w", mount, serial, err)
		}
		status := canon.StatusActive
		switch {
		case env.Data.RevocationTime > 0:
			status = canon.StatusRevoked
		case !facts.NotAfter.IsZero() && facts.NotAfter.Before(now):
			status = canon.StatusExpired
		}
		out = append(out, reducers.VaultPKICertificate{
			IssuerNameDER: facts.IssuerNameDER,
			SerialHex:     facts.SerialHex,
			Algorithm:     facts.Algorithm,
			Status:        status,
			NotBefore:     facts.NotBefore,
			NotAfter:      facts.NotAfter,
			SubjectDN:     facts.SubjectDN,
			NativeID:      mount + "/cert/" + serial,
		})
	}
	return out, nil
}

// --- Transit --------------------------------------------------------------

func (v *vaultSource) transitKeys(ctx context.Context, sb *reducers.ObservationSandbox, mount string) ([]reducers.VaultKey, error) {
	if _, err := sb.List(ctx, v.resource("transit", mount, "keys", "")); err != nil {
		return nil, fmt.Errorf("xrec vault source: transit list %s: %w", mount, err)
	}
	names, err := v.list(ctx, v.endpoint(mount, "keys", ""))
	if err != nil {
		return nil, fmt.Errorf("xrec vault source: transit list %s: %w", mount, err)
	}
	if len(names) > vaultSourceMaxKeys {
		return nil, fmt.Errorf("xrec vault source: transit %s lists more than %d keys", mount, vaultSourceMaxKeys)
	}
	sort.Strings(names)
	out := make([]reducers.VaultKey, 0, len(names))
	for _, name := range names {
		if _, err := sb.Describe(ctx, v.resource("transit", mount, "keys", name)); err != nil {
			return nil, fmt.Errorf("xrec vault source: transit key %s/%s: %w", mount, name, err)
		}
		var env struct {
			Data struct {
				Type          string                     `json:"type"`
				LatestVersion int                        `json:"latest_version"`
				Keys          map[string]json.RawMessage `json:"keys"`
			} `json:"data"`
		}
		if err := v.getJSON(ctx, v.endpoint(mount, "keys", name), &env); err != nil {
			return nil, fmt.Errorf("xrec vault source: transit key %s/%s: %w", mount, name, err)
		}
		key := reducers.VaultKey{
			LogicalID: mount + "/" + name,
			Algorithm: firstNonEmpty(strings.TrimSpace(env.Data.Type), "unknown"),
			Status:    canon.StatusActive,
			NativeID:  mount + "/keys/" + name + "#v" + strconv.Itoa(env.Data.LatestVersion),
		}
		if raw, ok := env.Data.Keys[strconv.Itoa(env.Data.LatestVersion)]; ok {
			key.CreatedAt = transitVersionCreated(raw)
		}
		out = append(out, key)
	}
	return out, nil
}

// transitVersionCreated reads a Transit key version's creation time: symmetric
// keys publish a unix timestamp, asymmetric keys an object with creation_time.
func transitVersionCreated(raw json.RawMessage) time.Time {
	var unix int64
	if err := json.Unmarshal(raw, &unix); err == nil && unix > 0 {
		return time.Unix(unix, 0).UTC()
	}
	var obj struct {
		CreationTime string `json:"creation_time"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return parseVaultTime(obj.CreationTime)
	}
	return time.Time{}
}

// --- HTTP -----------------------------------------------------------------

func (v *vaultSource) list(ctx context.Context, endpoint string) ([]string, error) {
	var env struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	status, err := v.doJSON(ctx, endpoint+"?list=true", &env)
	if status == http.StatusNotFound {
		// Vault answers 404 for an empty listing.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return env.Data.Keys, nil
}

func (v *vaultSource) getJSON(ctx context.Context, endpoint string, out any) error {
	_, err := v.doJSON(ctx, endpoint, out)
	return err
}

func (v *vaultSource) doJSON(ctx context.Context, endpoint string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	tok, err := v.token()
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Vault-Token", secrettext.String(tok))
	secret.Wipe(tok)
	if ns := strings.TrimSpace(v.cfg.Namespace); ns != "" {
		req.Header.Set("X-Vault-Namespace", ns)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, vaultSourceMaxBody+1))
	if err != nil {
		return resp.StatusCode, err
	}
	if len(body) > vaultSourceMaxBody {
		return resp.StatusCode, fmt.Errorf("response larger than %d bytes", vaultSourceMaxBody)
	}
	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, fmt.Errorf("vault answered 404")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, fmt.Errorf("vault answered %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return resp.StatusCode, fmt.Errorf("decode vault response: %w", err)
	}
	return resp.StatusCode, nil
}

// token reads the operator's token file for this request. The bytes are the
// caller's to wipe.
func (v *vaultSource) token() ([]byte, error) {
	raw, err := os.ReadFile(v.cfg.TokenFile) // #nosec G304 -- operator-configured token file from the reviewed config (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("xrec vault source: token file: %w", err)
	}
	tok := bytes.TrimSpace(raw)
	if len(tok) == 0 {
		secret.Wipe(raw)
		return nil, errors.New("xrec vault source: token file is empty")
	}
	out := append([]byte(nil), tok...)
	secret.Wipe(raw)
	return out, nil
}

func (v *vaultSource) endpoint(mount, kind, path string) string {
	parts := []string{"v1", mount, kind}
	for _, part := range strings.Split(strings.Trim(path, "/"), "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	escaped := make([]string, 0, len(parts))
	for _, part := range parts {
		escaped = append(escaped, url.PathEscape(part))
	}
	return v.base + "/" + strings.Join(escaped, "/")
}

// resource names what the sandbox is asked to allow; it is scoped under the
// authority id so a grant for one Vault authority never covers another.
func (v *vaultSource) resource(family, mount, kind, path string) string {
	return v.cfg.AuthorityID + "/" + family + "/" + mount + "/" + kind + "/" + strings.Trim(path, "/")
}

func cleanMount(mount string) string {
	return strings.Trim(strings.TrimSpace(mount), "/")
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "/" + name
}

func parseVaultTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
