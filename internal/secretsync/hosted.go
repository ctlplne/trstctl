// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/synctarget"
)

// A241: the hosted secret-sync targets. Each is one vendor's API for
// environment variables or secrets, described by a hostedVendor: how a value
// is set, how the names a destination holds are listed, what can be read back
// and how a key is deleted. One engine, HostedSyncPusher, runs them all, so a
// per-secret sync job pushes through it and a scoped sync (A237) lists, reads
// back and deletes through it. Bindings, endpoints and key rules come from
// internal/synctarget, shared with config validation.

// ReadBack is what a destination returns of a stored value.
type ReadBack string

const (
	// ReadBackValue: the API returns the value; the engine hashes and wipes it.
	ReadBackValue ReadBack = "value"
	// ReadBackDigest: the API returns a digest of the value, never the value.
	ReadBackDigest ReadBack = "digest"
	// ReadBackReceiptOnly: the API never returns a secret's value. A key's
	// presence is listed; the delivery receipt is the only evidence of what
	// it holds, so drift outside the sync can't be seen.
	ReadBackReceiptOnly ReadBack = "receipt-only"
)

// Proof is how far a target's catalog entry has been proven.
const (
	// ProofLocal: proven against the vendor's own software, run locally or
	// on a CI runner.
	ProofLocal = "locally-proven"
	// ProofStandIn: proven against a stand-in built from the vendor's API
	// documentation only.
	ProofStandIn = "stand-in-only"
)

// hostedVendor is one hosted target's API. put, list and remove are required;
// read is required unless the target is receipt-only (where presence comes
// from list). Errors never carry response bodies: vendors may echo values.
type hostedVendor struct {
	name         string
	deliveryMode string
	authMode     string
	wireFormat   string
	readBack     ReadBack
	proof        string
	// headers sets authentication and any fixed headers on every request.
	headers func(p *HostedSyncPusher, req *http.Request)
	// sign, when set, signs each request over its headers and body (an API
	// that authenticates requests rather than bearers).
	sign func(p *HostedSyncPusher, req *http.Request, body []byte) error
	put  func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error
	list func(ctx context.Context, p *HostedSyncPusher) ([]string, error)
	// read returns whether the key exists and, for ReadBackValue, the value
	// (the engine wipes it) or, for ReadBackDigest, the digest bytes.
	read   func(ctx context.Context, p *HostedSyncPusher, key string) (bool, []byte, error)
	remove func(ctx context.Context, p *HostedSyncPusher, key string) error
	// digestOf, for ReadBackDigest, is the vendor's digest of a value, in the
	// form read returns; nil means hex SHA-256.
	digestOf func(value []byte) string
}

// hostedVendors is every hosted target's API, by config type.
var hostedVendors = map[string]*hostedVendor{
	"heroku":                    herokuVendor,
	"render":                    renderVendor,
	"railway":                   railwayVendor,
	"fly":                       flyVendor,
	"digitalocean-app-platform": digitalOceanVendor,
	"northflank":                northflankVendor,
	"qovery":                    qoveryVendor,
	"cloud66":                   cloud66Vendor,
	"laravel-forge":             forgeVendor,
	"circleci":                  circleCIVendor,
	"travis-ci":                 travisVendor,
	"bitbucket":                 bitbucketVendor,
	"teamcity":                  teamCityVendor,
	"spacelift":                 spaceliftVendor,
	"humanitec":                 humanitecVendor,
	"rundeck":                   rundeckVendor,
	"checkly":                   checklyVendor,
	"windmill":                  windmillVendor,
	"zabbix":                    zabbixVendor,
	"portainer":                 portainerVendor,
	"devin":                     devinVendor,
	"daytona":                   daytonaVendor,
	"ona":                       onaVendor,
	"trigger-dev":               triggerVendor,
	"cloudflare-workers":        cloudflareWorkersVendor,
	"cloudflare-pages":          cloudflarePagesVendor,
	"cloudflare-secrets-store":  cloudflareSecretsStoreVendor,
	"azure-app-configuration":   azureAppConfigVendor,
	"oci-vault":                 ociVaultVendor,
	"ovh-secret-manager":        ovhVendor,
	"databricks-secrets":        databricksVendor,
	"supabase-secrets":          supabaseVendor,
	"camunda":                   camundaVendor,
}

// HostedSyncConfig configures one hosted destination.
type HostedSyncConfig struct {
	Type string
	// Endpoint overrides the vendor's API base (a self-hosted target's is
	// required).
	Endpoint   string
	HTTPClient HTTPDoer
	Token      []byte
	Username   string
	Binding    string
}

// HostedSyncPusher delivers to, lists, reads back and deletes from one bound
// hosted destination.
type HostedSyncPusher struct {
	target   synctarget.Target
	vendor   *hostedVendor
	binding  synctarget.Binding
	endpoint string
	doer     HTTPDoer
	token    *secret.Buffer
	username string
}

// NewHostedSyncPusher validates the binding and locks the token.
func NewHostedSyncPusher(cfg HostedSyncConfig) (*HostedSyncPusher, error) {
	target, ok := synctarget.Lookup(cfg.Type)
	vendor := hostedVendors[cfg.Type]
	if !ok || vendor == nil {
		return nil, fmt.Errorf("secretsync: %q is not a hosted secret-sync target", cfg.Type)
	}
	binding, err := synctarget.ParseBinding(cfg.Type, cfg.Binding)
	if err != nil {
		return nil, fmt.Errorf("secretsync: %w", err)
	}
	if len(cfg.Token) == 0 {
		return nil, fmt.Errorf("secretsync: %s needs its token", target.Name)
	}
	if target.Credential == synctarget.UserAndToken && strings.TrimSpace(cfg.Username) == "" {
		return nil, fmt.Errorf("secretsync: %s needs its username", target.Name)
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint == "" {
		endpoint = target.Endpoint
	}
	if endpoint == "" {
		return nil, fmt.Errorf("secretsync: %s has no fixed API base; its endpoint is required", target.Name)
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = netsec.HardenedClient(30 * time.Second)
	}
	token, err := secret.NewFrom(cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("secretsync: lock %s token: %w", target.Name, err)
	}
	return &HostedSyncPusher{target: target, vendor: vendor, binding: binding, endpoint: endpoint,
		doer: doer, token: token, username: strings.TrimSpace(cfg.Username)}, nil
}

// Close wipes the token.
func (p *HostedSyncPusher) Close() { destroySecretBuffer(&p.token) }

// Push sets key to value, creating the key when the destination lacks it.
func (p *HostedSyncPusher) Push(ctx context.Context, key string, value []byte) error {
	if err := p.target.ValidKey(key); err != nil {
		return fmt.Errorf("secretsync: %w", err)
	}
	return p.vendor.put(ctx, p, key, value)
}

// ScopedKeys: every hosted target lists its keys.
func (p *HostedSyncPusher) ScopedKeys() bool { return true }

// FlatKeys reports whether the destination holds variable names rather than
// paths; a scoped sync's destination prefix is then a name prefix.
func (p *HostedSyncPusher) FlatKeys() bool { return p.target.Keys == synctarget.FlatKeys }

// ValidKey reports whether the destination can hold key.
func (p *HostedSyncPusher) ValidKey(key string) error { return p.target.ValidKey(key) }

// ReadsBack reports whether a stored value can be compared; a receipt-only
// destination can't.
func (p *HostedSyncPusher) ReadsBack() bool { return p.vendor.readBack != ReadBackReceiptOnly }

// DigestOf is the digest ReadDigest returns for a destination holding value.
func (p *HostedSyncPusher) DigestOf(value []byte) string {
	if p.vendor.readBack == ReadBackDigest && p.vendor.digestOf != nil {
		return p.vendor.digestOf(value)
	}
	return crypto.SHA256Hex(value)
}

// ListKeys returns the names under prefix, sorted. A flat destination's
// prefix is a name prefix; a path destination's is a folder.
func (p *HostedSyncPusher) ListKeys(ctx context.Context, prefix string, limit int) ([]string, error) {
	names, err := p.vendor.list(ctx, p)
	if err != nil {
		return nil, err
	}
	if prefix != "" && p.target.Keys == synctarget.PathKeys {
		prefix = strings.TrimSuffix(prefix, "/") + "/"
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		if strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if limit > 0 && len(out) > limit {
		return nil, ErrScopedListLimit
	}
	return out, nil
}

// ReadDigest reports whether key exists and the digest of what it holds; a
// receipt-only destination answers presence with an empty digest.
func (p *HostedSyncPusher) ReadDigest(ctx context.Context, key string) (bool, string, error) {
	if p.vendor.readBack == ReadBackReceiptOnly {
		names, err := p.vendor.list(ctx, p)
		if err != nil {
			return false, "", err
		}
		return slices.Contains(names, key), "", nil
	}
	exists, got, err := p.vendor.read(ctx, p, key)
	if err != nil || !exists {
		secret.Wipe(got)
		return exists, "", err
	}
	if p.vendor.readBack == ReadBackDigest {
		return true, string(got), nil
	}
	defer secret.Wipe(got)
	return true, crypto.SHA256Hex(got), nil
}

// Delete removes key; one already gone is not an error.
func (p *HostedSyncPusher) Delete(ctx context.Context, key string) error {
	return p.vendor.remove(ctx, p, key)
}

// ReconcilesReceiver: a destination that reads back can settle a lost result.
func (p *HostedSyncPusher) ReconcilesReceiver() bool { return p.ReadsBack() }

// ReconcileOperation compares the destination with this command's value.
func (p *HostedSyncPusher) ReconcileOperation(ctx context.Context, key string, value []byte) (ReceiverReconciliation, error) {
	if !p.ReadsBack() {
		return ReceiverStateUnknown, nil
	}
	exists, digest, err := p.ReadDigest(ctx, key)
	if err != nil {
		return ReceiverStateUnknown, err
	}
	if exists && digest != "" && crypto.ConstantTimeEqual([]byte(digest), []byte(p.DigestOf(value))) {
		return ReceiverStateMatches, nil
	}
	return ReceiverStateDiffers, nil
}

// send makes one request to path (relative to the endpoint, already escaped)
// and decodes a 2xx JSON answer into out. The caller wipes body.
func (p *HostedSyncPusher) send(ctx context.Context, method, path string, body []byte, out any) error {
	req, err := p.request(ctx, method, path, body, "application/json")
	if err != nil {
		return err
	}
	return readJSON2xx(p.doer, req, out)
}

func (p *HostedSyncPusher) request(ctx context.Context, method, path string, body []byte, contentType string) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.endpoint+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	p.vendor.headers(p, req)
	if p.vendor.sign != nil {
		if err := p.vendor.sign(p, req, body); err != nil {
			return nil, fmt.Errorf("secretsync: %s request signature: %w", p.target.Name, err)
		}
	}
	return req, nil
}

// sendForHeader is send for an API that pages through a response header:
// it decodes the 2xx JSON answer into out and returns that header's value.
func (p *HostedSyncPusher) sendForHeader(ctx context.Context, req *http.Request, out any, header string) (string, error) {
	resp, err := p.doer.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := secret.ReadBounded(resp.Body, cloudhttp.MaxBodyBytes)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(raw)
	if resp.StatusCode/100 != 2 {
		return "", &responseStatusError{code: resp.StatusCode}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return "", fmt.Errorf("secretsync: decode %s %s response: %w", req.Method, req.URL.Path, err)
		}
	}
	return resp.Header.Get(header), nil
}

// notFound reports a 404 answer.
func notFound(err error) bool { return statusCode(err) == http.StatusNotFound }

// hostedError names the operation without any response body.
func hostedError(p *HostedSyncPusher, op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("secretsync: %s %s: %w", p.target.Name, op, err)
}

// bearerHeaders authenticates with "Authorization: Bearer <token>".
func bearerHeaders(p *HostedSyncPusher, req *http.Request) { setBearer(req, p.token.Bytes()) }

var errHostedValueNotText = errors.New("secretsync: this destination holds text; the secret must be UTF-8")

// HostedReadBack is what a hosted target type reads back ("" if typ is not
// one). The server's per-call adapter answers the scoped questions from it.
func HostedReadBack(typ string) ReadBack {
	if vendor := hostedVendors[typ]; vendor != nil {
		return vendor.readBack
	}
	return ""
}

// HostedDigestOf is the digest a hosted target of type typ reads back for a
// destination holding value.
func HostedDigestOf(typ string, value []byte) string {
	if vendor := hostedVendors[typ]; vendor != nil && vendor.readBack == ReadBackDigest && vendor.digestOf != nil {
		return vendor.digestOf(value)
	}
	return crypto.SHA256Hex(value)
}
