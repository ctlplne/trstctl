// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/hostedkey"
)

// hostedKeyID is a vendor's identifier for one key, as a revocation reference
// carries it after the bound target ("<binding>/<id>").
// Convex's IDs are the issued names, which carry the role's underscores.
var hostedKeyID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,200}$`)

// hostedKeyVendor is one hosted service's key API (A240): a key is minted
// under the canonical binding a role names (internal/hostedkey), carries a
// name the provider derives from the lease or rotation command, is shown once
// at creation, and is deleted by its vendor ID. HostedKeyBackend turns any
// vendor into a lease issuer and a two-phase static rotator: the successor is
// minted beside the predecessor, and both work until the predecessor is
// retired by deletion.
type hostedKeyVendor interface {
	// mint creates a key named name under binding and returns its vendor ID
	// and the credential document a consumer reads (the key and whatever
	// else it needs to use it).
	mint(ctx context.Context, api hostedAPI, binding, name string) (id string, credential []byte, err error)
	// named lists the IDs of live keys under binding that carry name, so a
	// retry after an uncertain mint deletes the earlier attempt's key first.
	named(ctx context.Context, api hostedAPI, binding, name string) ([]string, error)
	// nameOf reads the name of the live key with id under binding, so
	// revocation deletes only keys this provider issued; found is false when
	// the key is already gone.
	nameOf(ctx context.Context, api hostedAPI, binding, id string) (name string, found bool, err error)
	// remove deletes the key; one already gone is not an error.
	remove(ctx context.Context, api hostedAPI, binding, id string) error
	// verify proves a credential document authenticates, or returns
	// ErrNoSelfProof when the vendor offers no side-effect-free check.
	verify(ctx context.Context, api hostedAPI, credential []byte) error
}

// hostedKeyVendors are the vendors by provider type, with the vendors' key
// name rules (the longest name, and the separator its characters allow).
var hostedKeyVendors = map[string]struct {
	open    func(admin *secret.Buffer) hostedKeyVendor
	nameMax int
	nameSep string
}{
	"openrouter": {func(admin *secret.Buffer) hostedKeyVendor { return openRouterVendor{management: admin} }, 100, "-"},
	"fireworks":  {func(admin *secret.Buffer) hostedKeyVendor { return fireworksVendor{admin: admin} }, 100, "-"},
	"litellm":    {func(admin *secret.Buffer) hostedKeyVendor { return liteLLMVendor{master: admin} }, 100, "-"},
	// Supabase key names are ^[a-z_][a-z0-9_]+$, 4 to 64 characters.
	"supabase": {func(admin *secret.Buffer) hostedKeyVendor { return supabaseVendor{token: admin} }, 64, "_"},
	"convex":   {func(admin *secret.Buffer) hostedKeyVendor { return convexVendor{token: admin} }, 100, "-"},
	"dbt":      {func(admin *secret.Buffer) hostedKeyVendor { return dbtVendor{token: admin} }, 100, "-"},
	// Cloudflare token names are at most 120 characters.
	"cloudflare":    {func(admin *secret.Buffer) hostedKeyVendor { return cloudflareVendor{admin: admin} }, 120, "-"},
	"cloudflare-r2": {func(admin *secret.Buffer) hostedKeyVendor { return cloudflareVendor{admin: admin, r2: true} }, 120, "-"},
}

// HostedKeyConfig configures a hosted API key provider (A240): a lease, or
// each static rotation, is a new key of the target the role is bound to,
// created with the administrator's credential and named for the lease or
// command; revocation, or retiring a rotation's predecessor, deletes it, and
// the vendor refuses it from then on. Rotation is two-phase.
type HostedKeyConfig struct {
	// Endpoint is the vendor API's URL (internal/hostedkey describes each).
	Endpoint string
	// AdminKey creates, lists and deletes the bound targets' keys.
	AdminKey []byte
	// RoleBindings maps each allowed role to its binding, in the grammar
	// internal/hostedkey gives the provider.
	RoleBindings          map[string]string
	UsernamePrefix        string
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
}

// HostedKeyBackend issues, rotates and deletes one vendor's keys.
type HostedKeyBackend struct {
	provider string
	vendor   hostedKeyVendor
	api      hostedAPI
	admin    *secret.Buffer
	bindings map[string]string
	prefix   string
	nameMax  int
	nameSep  string
}

// NewHostedKeyBackend validates cfg for provider, one of
// hostedkey.Types().
func NewHostedKeyBackend(provider string, cfg HostedKeyConfig) (*HostedKeyBackend, error) {
	spec, ok := hostedKeyVendors[provider]
	if !ok {
		return nil, fmt.Errorf("dynsecret: %q is not a hosted API key provider", provider)
	}
	api, err := newHostedAPI(provider, cfg.Endpoint, cfg.AllowInsecureLoopback, cfg.HTTPClient)
	if err != nil {
		return nil, err
	}
	if len(cfg.AdminKey) == 0 {
		return nil, fmt.Errorf("dynsecret %s: the administrator's credential (api_key_ref) is required", provider)
	}
	if prefix := sanitizeFragment(cfg.UsernamePrefix, defaultDynsecretPrefix); spec.nameSep == "_" && prefix[0] >= '0' && prefix[0] <= '9' {
		return nil, fmt.Errorf("dynsecret %s: username_prefix must start with a letter, as the vendor's key names do", provider)
	}
	b := &HostedKeyBackend{provider: provider, api: api, bindings: map[string]string{}, prefix: cfg.UsernamePrefix, nameMax: spec.nameMax, nameSep: spec.nameSep}
	for role, binding := range cfg.RoleBindings {
		canonical, err := hostedkey.ParseBinding(provider, binding)
		if err != nil {
			return nil, fmt.Errorf("dynsecret %s: role %q: %w", provider, role, err)
		}
		b.bindings[role] = canonical
	}
	if len(b.bindings) == 0 {
		return nil, fmt.Errorf("dynsecret %s: every allowed role needs a binding in role_bindings", provider)
	}
	if b.admin, err = secret.NewFrom(cfg.AdminKey); err != nil {
		return nil, err
	}
	b.vendor = spec.open(b.admin)
	return b, nil
}

// Create implements Backend.
func (b *HostedKeyBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend: a lease, or each static
// rotation, mints a key named for the lease or command. The vendor shows the
// key only once, so a retry first deletes any key already carrying that
// name: an uncertain attempt leaves one key, not two.
func (b *HostedKeyBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	binding, ok := b.bindings[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret %s: role %q has no binding", b.provider, req.Role)
	}
	name, err := scopedNameForRequest(b.prefix, req, b.nameMax, b.nameSep)
	if err != nil {
		return "", nil, err
	}
	earlier, err := b.vendor.named(ctx, b.api, binding, name)
	if err != nil {
		return "", nil, fmt.Errorf("dynsecret %s: look for an earlier attempt's key: %w", b.provider, err)
	}
	for _, id := range earlier {
		if err := b.vendor.remove(ctx, b.api, binding, id); err != nil {
			return "", nil, fmt.Errorf("dynsecret %s: replace an earlier attempt's key: %w", b.provider, err)
		}
	}
	id, credential, err := b.vendor.mint(ctx, b.api, binding, name)
	if err != nil {
		return "", nil, err
	}
	if !hostedKeyID.MatchString(id) {
		secret.Wipe(credential)
		return "", nil, fmt.Errorf("dynsecret %s: the vendor returned an unusable key ID", b.provider)
	}
	return binding + "/" + id, credential, nil
}

// Revoke implements Backend: the key is deleted after its name is checked, so
// a reference to a key someone else created is refused; one already gone
// counts as revoked.
func (b *HostedKeyBackend) Revoke(ctx context.Context, ref string) error {
	cut := strings.LastIndex(ref, "/")
	refused := fmt.Errorf("dynsecret %s: refusing %q, which names no key of a bound target", b.provider, ref)
	if cut <= 0 {
		return refused
	}
	binding, id := ref[:cut], ref[cut+1:]
	if !hostedKeyID.MatchString(id) || !b.bound(binding) {
		return refused
	}
	name, found, err := b.vendor.nameOf(ctx, b.api, binding, id)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if !issuedPrincipalNameWith(b.prefix, name, b.nameSep[0]) {
		return fmt.Errorf("dynsecret %s: refusing to delete key %s, which this provider did not create", b.provider, id)
	}
	return b.vendor.remove(ctx, b.api, binding, id)
}

func (b *HostedKeyBackend) bound(binding string) bool {
	for _, candidate := range b.bindings {
		if candidate == binding {
			return true
		}
	}
	return false
}

// VerifyCredential proves a key with the vendor's own check (A240), or
// returns ErrNoSelfProof where the vendor offers none.
func (b *HostedKeyBackend) VerifyCredential(ctx context.Context, credential []byte) error {
	return b.vendor.verify(ctx, b.api, credential)
}

// Close wipes the administrator's credential.
func (b *HostedKeyBackend) Close() {
	b.admin.Destroy()
}

// hostedJSON calls the vendor and decodes a successful response into out;
// 200 and the listed statuses succeed, and any other status is an error
// naming only the status.
func hostedJSON(ctx context.Context, api hostedAPI, method, path string, body any, authenticate func(http.Header) error, out any, ok ...int) (int, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return 0, err
		}
	}
	status, response, err := api.call(ctx, method, path, payload, authenticate)
	if err != nil {
		return 0, err
	}
	defer secret.Wipe(response)
	accepted := status == http.StatusOK
	for _, code := range ok {
		accepted = accepted || status == code
	}
	if !accepted {
		return status, fmt.Errorf("dynsecret %s: %s %s: HTTP %d", api.name, method, strings.SplitN(path, "?", 2)[0], status)
	}
	if out != nil && status != http.StatusNotFound && len(response) > 0 {
		if err := json.Unmarshal(response, out); err != nil {
			return status, errors.New("dynsecret " + api.name + ": the response is not the expected JSON")
		}
	}
	return status, nil
}

// credentialField reads one secret field of a credential document.
func credentialField(provider string, credential []byte, field string) ([]byte, error) {
	var parsed map[string]secret.JSONBytes
	if err := json.Unmarshal(credential, &parsed); err != nil || len(parsed[field]) == 0 {
		for _, value := range parsed {
			secret.Wipe(value)
		}
		return nil, fmt.Errorf("dynsecret %s: the credential carries no %s", provider, field)
	}
	for name, value := range parsed {
		if name != field {
			secret.Wipe(value)
		}
	}
	return parsed[field], nil
}
