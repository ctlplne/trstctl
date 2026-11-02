// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

var (
	datadogServiceAccount = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	datadogScope          = regexp.MustCompile(`^[a-z][a-z0-9_]{0,79}$`)
	datadogKeyID          = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// DatadogKind is what a Datadog role binding issues.
type DatadogKind struct {
	// ServiceAccount is empty for an API key, and names the service account
	// an application key belongs to.
	ServiceAccount string
	// Scopes are an application key's authorization scopes; none means the
	// service account's full access, which the binding must not ask for.
	Scopes []string
}

// ParseDatadogBinding reads a role binding: "api_key", or
// "application_key <service-account-id> <scope>,<scope>" for an application key
// of that service account restricted to the named scopes.
func ParseDatadogBinding(binding string) (DatadogKind, error) {
	fields := strings.Fields(binding)
	switch {
	case len(fields) == 1 && fields[0] == "api_key":
		return DatadogKind{}, nil
	case len(fields) == 3 && fields[0] == "application_key":
		if !datadogServiceAccount.MatchString(fields[1]) {
			return DatadogKind{}, fmt.Errorf("%q is not a service account ID", fields[1])
		}
		var scopes []string
		for _, scope := range strings.Split(fields[2], ",") {
			if !datadogScope.MatchString(scope) {
				return DatadogKind{}, fmt.Errorf("%q is not an authorization scope", scope)
			}
			scopes = append(scopes, scope)
		}
		return DatadogKind{ServiceAccount: fields[1], Scopes: scopes}, nil
	default:
		return DatadogKind{}, errors.New(`expected "api_key" or "application_key <service-account-id> <scope>,<scope>"`)
	}
}

// DatadogConfig configures the Datadog key provider (A240): a lease, or each
// static rotation, is a new API key or a scoped service-account application
// key, created through the Datadog API; revocation (or retiring a rotation's
// predecessor) deletes it, and Datadog refuses it from then on. Rotation is
// two-phase: the predecessor keeps working until it is retired.
type DatadogConfig struct {
	// Endpoint is the site's API, https://api.datadoghq.com (or another site).
	Endpoint string
	// APIKey and ApplicationKey authenticate the administrator: an
	// application key allowed api_keys_write and service-account key
	// management.
	APIKey                []byte
	ApplicationKey        []byte
	RoleBindings          map[string]string
	UsernamePrefix        string
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
}

// DatadogBackend issues and deletes Datadog keys.
type DatadogBackend struct {
	api            hostedAPI
	apiKey         *secret.Buffer
	applicationKey *secret.Buffer
	kinds          map[string]DatadogKind
	prefix         string
}

// NewDatadogBackend validates cfg.
func NewDatadogBackend(cfg DatadogConfig) (*DatadogBackend, error) {
	api, err := newHostedAPI("datadog", cfg.Endpoint, cfg.AllowInsecureLoopback, cfg.HTTPClient)
	if err != nil {
		return nil, err
	}
	if len(cfg.APIKey) == 0 || len(cfg.ApplicationKey) == 0 {
		return nil, errors.New("dynsecret datadog: the administrator API and application keys are required")
	}
	b := &DatadogBackend{api: api, kinds: map[string]DatadogKind{}, prefix: cfg.UsernamePrefix}
	for role, binding := range cfg.RoleBindings {
		kind, err := ParseDatadogBinding(binding)
		if err != nil {
			return nil, fmt.Errorf("dynsecret datadog: role %q: %w", role, err)
		}
		b.kinds[role] = kind
	}
	if len(b.kinds) == 0 {
		return nil, errors.New("dynsecret datadog: every allowed role needs a key kind in role_bindings")
	}
	if b.apiKey, err = secret.NewFrom(cfg.APIKey); err != nil {
		return nil, err
	}
	if b.applicationKey, err = secret.NewFrom(cfg.ApplicationKey); err != nil {
		b.apiKey.Destroy()
		return nil, err
	}
	return b, nil
}

// Create implements Backend.
func (b *DatadogBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// collection is the key collection a kind's keys live in.
func (k DatadogKind) collection() string {
	if k.ServiceAccount == "" {
		return "/api/v2/api_keys"
	}
	return "/api/v2/service_accounts/" + k.ServiceAccount + "/application_keys"
}

// CreateCredential implements RequestBackend. The key's name derives from the
// lease (or the rotation command), and Datadog shows a key only once, so a
// retry first deletes any key already carrying that name before creating it
// again: an uncertain attempt leaves one key, not two.
func (b *DatadogBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	kind, ok := b.kinds[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret datadog: role %q has no key kind", req.Role)
	}
	name, err := scopedNameForRequest(b.prefix, req, 100, "-")
	if err != nil {
		return "", nil, err
	}
	if err := b.deleteNamed(ctx, kind, name); err != nil {
		return "", nil, fmt.Errorf("dynsecret datadog: replace an earlier attempt's key: %w", err)
	}
	attributes := map[string]any{"name": name}
	keyType := "api_keys"
	if kind.ServiceAccount != "" {
		keyType, attributes["scopes"] = "application_keys", kind.Scopes
	}
	body, err := json.Marshal(map[string]any{"data": map[string]any{"type": keyType, "attributes": attributes}})
	if err != nil {
		return "", nil, err
	}
	status, response, err := b.call(ctx, http.MethodPost, kind.collection(), body)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(response)
	if status != http.StatusCreated && status != http.StatusOK {
		return "", nil, fmt.Errorf("dynsecret datadog: create key: HTTP %d", status)
	}
	var created struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				Key secret.JSONBytes `json:"key"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response, &created); err != nil || !datadogKeyID.MatchString(created.Data.ID) || len(created.Data.Attributes.Key) == 0 {
		return "", nil, errors.New("dynsecret datadog: the create response carries no key")
	}
	defer secret.Wipe(created.Data.Attributes.Key)
	field := "api_key"
	if kind.ServiceAccount != "" {
		field = "application_key"
	}
	credential, err := json.Marshal(map[string]any{ // #nosec G117 -- the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200)
		field: created.Data.Attributes.Key, "key_id": created.Data.ID, "site": b.api.endpoint,
	})
	if err != nil {
		return "", nil, err
	}
	return b.reference(kind, created.Data.ID), credential, nil
}

// reference names a key: "api_key/<id>" or "<service-account>/<id>".
func (b *DatadogBackend) reference(kind DatadogKind, id string) string {
	if kind.ServiceAccount == "" {
		return "api_key/" + id
	}
	return kind.ServiceAccount + "/" + id
}

// Revoke implements Backend: the key is deleted after its name is checked, so
// a reference to a key someone else created is refused; a key already gone
// counts as revoked.
func (b *DatadogBackend) Revoke(ctx context.Context, ref string) error {
	owner, id, ok := strings.Cut(ref, "/")
	if !ok || !datadogKeyID.MatchString(id) {
		return fmt.Errorf("dynsecret datadog: refusing %q, which names no key this provider issued", ref)
	}
	kind := DatadogKind{}
	if owner != "api_key" {
		bound := false
		for _, configured := range b.kinds {
			bound = bound || configured.ServiceAccount == owner
		}
		if !bound {
			return fmt.Errorf("dynsecret datadog: refusing %q, which names no service account this provider uses", ref)
		}
		kind.ServiceAccount = owner
	}
	status, response, err := b.call(ctx, http.MethodGet, kind.collection()+"/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	defer secret.Wipe(response)
	if status == http.StatusNotFound {
		return nil
	}
	var current struct {
		Data struct {
			Attributes struct {
				Name string `json:"name"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if status != http.StatusOK || json.Unmarshal(response, &current) != nil {
		return fmt.Errorf("dynsecret datadog: read key: HTTP %d", status)
	}
	if !issuedPrincipalNameWith(b.prefix, current.Data.Attributes.Name, '-') {
		return fmt.Errorf("dynsecret datadog: refusing to delete key %s, which this provider did not create", id)
	}
	return b.delete(ctx, kind, id)
}

func (b *DatadogBackend) delete(ctx context.Context, kind DatadogKind, id string) error {
	status, response, err := b.call(ctx, http.MethodDelete, kind.collection()+"/"+url.PathEscape(id), nil)
	secret.Wipe(response)
	if err != nil {
		return err
	}
	if status/100 != 2 && status != http.StatusNotFound {
		return fmt.Errorf("dynsecret datadog: delete key: HTTP %d", status)
	}
	return nil
}

// deleteNamed deletes keys that already carry name: the leftovers of an
// attempt whose response was lost.
func (b *DatadogBackend) deleteNamed(ctx context.Context, kind DatadogKind, name string) error {
	status, response, err := b.call(ctx, http.MethodGet, kind.collection()+"?filter="+url.QueryEscape(name)+"&page[size]=100", nil)
	if err != nil {
		return err
	}
	defer secret.Wipe(response)
	if status != http.StatusOK {
		return fmt.Errorf("list keys: HTTP %d", status)
	}
	var listed struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Name string `json:"name"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response, &listed); err != nil {
		return errors.New("list keys: the response is not a key list")
	}
	for _, key := range listed.Data {
		if key.Attributes.Name == name && datadogKeyID.MatchString(key.ID) {
			if err := b.delete(ctx, kind, key.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// VerifyCredential proves an API key is valid (GET /api/v1/validate). An
// application key's permitted calls are the scopes the operator chose, so it
// has no side-effect-free proof: ErrNoSelfProof.
func (b *DatadogBackend) VerifyCredential(ctx context.Context, credential []byte) error {
	var parsed struct {
		APIKey         secret.JSONBytes `json:"api_key"`
		ApplicationKey secret.JSONBytes `json:"application_key"`
		KeyID          string           `json:"key_id"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil {
		return errors.New("dynsecret datadog: the credential is not a Datadog key")
	}
	defer secret.Wipe(parsed.APIKey)
	defer secret.Wipe(parsed.ApplicationKey)
	if len(parsed.APIKey) == 0 {
		if len(parsed.ApplicationKey) != 0 {
			return ErrNoSelfProof
		}
		return errors.New("dynsecret datadog: the credential carries no key")
	}
	status, response, err := b.api.call(ctx, http.MethodGet, "/api/v1/validate", nil, func(header http.Header) error {
		header.Set("DD-API-KEY", string(parsed.APIKey))
		return nil
	})
	secret.Wipe(response)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("dynsecret datadog: the key does not validate: HTTP %d", status)
	}
	return nil
}

// call authenticates as the administrator.
func (b *DatadogBackend) call(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	return b.api.call(ctx, method, path, body, func(header http.Header) error {
		return b.apiKey.Use(func(apiKey []byte) error {
			return b.applicationKey.Use(func(applicationKey []byte) error {
				header.Set("DD-API-KEY", string(apiKey))
				header.Set("DD-APPLICATION-KEY", string(applicationKey))
				return nil
			})
		})
	})
}

// Close wipes the administrator keys.
func (b *DatadogBackend) Close() {
	b.apiKey.Destroy()
	b.applicationKey.Destroy()
}
