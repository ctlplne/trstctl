// SPDX-License-Identifier: MPL-2.0

package secretsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	terraformCloudVariablesMediaType = "application/vnd.api+json"
	terraformCloudMaxVariablePages   = 100
	vaultKVV2MaxCASAttempts          = 4
)

// TerraformCloudOpenTofuConfig configures the native Terraform Cloud Variables
// API used by both Terraform and OpenTofu workspaces. Secret values are always
// created as sensitive variables; Category chooses Terraform input variables or
// environment variables.
type TerraformCloudOpenTofuConfig struct {
	Endpoint    string
	HTTPClient  HTTPDoer
	WorkspaceID string
	Token       []byte
	Category    string
	HCL         bool
	Description string
}

// TerraformCloudOpenTofuPusher writes one sensitive workspace variable through
// Terraform Cloud's JSON:API contract. A stable, non-secret operation digest in
// the description lets an outbox replay recognize a write whose HTTP response was
// lost even though Terraform Cloud deliberately hides sensitive values on reads.
type TerraformCloudOpenTofuPusher struct {
	endpoint          string
	doer              HTTPDoer
	workspaceID       string
	token             *secret.Buffer
	category          string
	hcl               bool
	descriptionPrefix string
}

// NewTerraformCloudOpenTofuPusher constructs a provider-native workspace
// variable pusher. The token is copied into locked memory and destroyed by Close.
func NewTerraformCloudOpenTofuPusher(cfg TerraformCloudOpenTofuConfig) (*TerraformCloudOpenTofuPusher, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" || strings.TrimSpace(cfg.WorkspaceID) == "" || len(cfg.Token) == 0 {
		return nil, errors.New("secretsync: Terraform Cloud endpoint, workspace id, and token are required")
	}
	category := strings.ToLower(strings.TrimSpace(cfg.Category))
	if category == "" {
		category = "terraform"
	}
	if category != "terraform" && category != "env" {
		return nil, errors.New("secretsync: Terraform Cloud variable category must be terraform or env")
	}
	if category == "env" && cfg.HCL {
		return nil, errors.New("secretsync: Terraform Cloud HCL evaluation is valid only for terraform variables")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = netsec.SafeClient(30 * time.Second)
	}
	token, err := secret.NewFrom(cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("secretsync: lock Terraform Cloud token: %w", err)
	}
	description := strings.TrimSpace(cfg.Description)
	if description == "" {
		description = "Managed by trstctl secret sync"
	}
	return &TerraformCloudOpenTofuPusher{
		endpoint:          strings.TrimRight(cfg.Endpoint, "/"),
		doer:              doer,
		workspaceID:       strings.TrimSpace(cfg.WorkspaceID),
		token:             token,
		category:          category,
		hcl:               cfg.HCL,
		descriptionPrefix: description,
	}, nil
}

type terraformCloudVariable struct {
	ID          string
	Key         string
	Description string
	Category    string
	HCL         bool
	Sensitive   bool
}

// Push performs a metadata read before every write, updates an existing variable
// by its provider id, and creates only when no key/category match exists.
func (p *TerraformCloudOpenTofuPusher) Push(ctx context.Context, key string, value []byte) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("secretsync: Terraform Cloud variable key is required")
	}
	if !utf8.Valid(value) {
		return errors.New("secretsync: Terraform Cloud variable value must be valid UTF-8")
	}
	marker := p.operationDescription(ctx)
	existing, err := p.findVariable(ctx, key)
	if err != nil {
		return err
	}
	if existing != nil {
		if p.isCompletedReplay(ctx, existing, marker) {
			return nil
		}
		return p.writeVariable(ctx, http.MethodPatch, existing.ID, key, marker, value)
	}
	err = p.writeVariable(ctx, http.MethodPost, "", key, marker, value)
	if statusCode(err) != http.StatusConflict && statusCode(err) != http.StatusUnprocessableEntity {
		return err
	}
	// Terraform Cloud rejects a create raced by another writer with 409/422.
	// Re-read provider state, then either recognize our completed operation or
	// update the exact provider resource that won the race.
	existing, readErr := p.findVariable(ctx, key)
	if readErr != nil {
		return readErr
	}
	if existing == nil {
		return err
	}
	if p.isCompletedReplay(ctx, existing, marker) {
		return nil
	}
	return p.writeVariable(ctx, http.MethodPatch, existing.ID, key, marker, value)
}

func (p *TerraformCloudOpenTofuPusher) isCompletedReplay(ctx context.Context, variable *terraformCloudVariable, marker string) bool {
	return operationIDFromContext(ctx) != "" && variable.Description == marker &&
		variable.Sensitive && variable.HCL == p.hcl
}

func (p *TerraformCloudOpenTofuPusher) operationDescription(ctx context.Context) string {
	operationID := operationIDFromContext(ctx)
	if operationID == "" {
		return p.descriptionPrefix
	}
	return p.descriptionPrefix + "; operation-sha256=" + crypto.SHA256Hex([]byte(operationID))
}

func (p *TerraformCloudOpenTofuPusher) variablesPath() string {
	return "/api/v2/workspaces/" + pathEscape(p.workspaceID) + "/vars"
}

func (p *TerraformCloudOpenTofuPusher) findVariable(ctx context.Context, key string) (*terraformCloudVariable, error) {
	basePath := p.variablesPath()
	var matched *terraformCloudVariable
	for page := 1; page <= terraformCloudMaxVariablePages; page++ {
		query := url.Values{}
		query.Set("page[number]", strconv.Itoa(page))
		query.Set("page[size]", "100")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+basePath+"?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		p.authorize(req)
		var response struct {
			Data []struct {
				ID         string `json:"id"`
				Type       string `json:"type"`
				Attributes struct {
					Key         string `json:"key"`
					Description string `json:"description"`
					Category    string `json:"category"`
					HCL         bool   `json:"hcl"`
					Sensitive   bool   `json:"sensitive"`
				} `json:"attributes"`
			} `json:"data"`
			Meta struct {
				Pagination struct {
					CurrentPage int `json:"current-page"`
					TotalPages  int `json:"total-pages"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		if err := readJSON2xx(p.doer, req, &response); err != nil {
			return nil, fmt.Errorf("secretsync: list Terraform Cloud workspace variables: %w", err)
		}
		for _, item := range response.Data {
			if item.Type != "vars" || item.Attributes.Key != key || item.Attributes.Category != p.category {
				continue
			}
			if item.ID == "" {
				return nil, errors.New("secretsync: Terraform Cloud returned a matching variable without an id")
			}
			if matched != nil && matched.ID != item.ID {
				return nil, fmt.Errorf("secretsync: Terraform Cloud returned duplicate %s variable metadata for key %q", p.category, key)
			}
			matched = &terraformCloudVariable{
				ID: item.ID, Key: item.Attributes.Key, Description: item.Attributes.Description,
				Category: item.Attributes.Category, HCL: item.Attributes.HCL, Sensitive: item.Attributes.Sensitive,
			}
		}
		totalPages := response.Meta.Pagination.TotalPages
		if totalPages <= 0 {
			totalPages = 1
		}
		if page >= totalPages {
			return matched, nil
		}
	}
	return nil, fmt.Errorf("secretsync: Terraform Cloud variable listing exceeded %d pages", terraformCloudMaxVariablePages)
}

func (p *TerraformCloudOpenTofuPusher) writeVariable(ctx context.Context, method, id, key, description string, value []byte) error {
	type attributes struct {
		Key         string           `json:"key"`
		Value       secret.JSONBytes `json:"value"`
		Description string           `json:"description"`
		Category    string           `json:"category"`
		HCL         bool             `json:"hcl"`
		Sensitive   bool             `json:"sensitive"`
	}
	payload := struct {
		Data struct {
			ID         string     `json:"id,omitempty"`
			Type       string     `json:"type"`
			Attributes attributes `json:"attributes"`
		} `json:"data"`
	}{}
	payload.Data.ID = id
	payload.Data.Type = "vars"
	payload.Data.Attributes = attributes{
		Key: key, Value: secret.JSONBytes(value), Description: description,
		Category: p.category, HCL: p.hcl, Sensitive: true,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("secretsync: encode Terraform Cloud variable: %w", err)
	}
	defer secret.Wipe(body)
	path := p.variablesPath()
	if id != "" {
		path += "/" + pathEscape(id)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	p.authorize(req)
	req.Header.Set("Content-Type", terraformCloudVariablesMediaType)
	if err := expect2xx(p.doer, req); err != nil {
		return fmt.Errorf("secretsync: write Terraform Cloud workspace variable: %w", err)
	}
	return nil
}

func (p *TerraformCloudOpenTofuPusher) authorize(req *http.Request) {
	req.Header.Set("Accept", terraformCloudVariablesMediaType)
	req.Header.Set("Content-Type", terraformCloudVariablesMediaType)
	setBearer(req, secretBufferBytes(p.token))
}

// Close destroys the retained Terraform Cloud token.
func (p *TerraformCloudOpenTofuPusher) Close() { destroySecretBuffer(&p.token) }

// VaultKVV2Config configures a provider-native HashiCorp Vault/OpenBao KV v2
// destination. PathPrefix is joined with each delivery key; Field is the JSON
// field updated without deleting sibling fields at that path.
type VaultKVV2Config struct {
	Endpoint   string
	HTTPClient HTTPDoer
	Token      []byte
	Mount      string
	PathPrefix string
	Field      string
	Namespace  string
}

// VaultKVV2Pusher uses KV v2 read-before-write and check-and-set versions so a
// retry cannot silently overwrite a concurrent writer.
type VaultKVV2Pusher struct {
	endpoint   string
	doer       HTTPDoer
	token      *secret.Buffer
	mount      string
	pathPrefix string
	field      string
	namespace  string
}

// NewVaultKVV2Pusher constructs a Vault KV v2 pusher with locked token memory.
func NewVaultKVV2Pusher(cfg VaultKVV2Config) (*VaultKVV2Pusher, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" || strings.TrimSpace(cfg.Mount) == "" || len(cfg.Token) == 0 {
		return nil, errors.New("secretsync: Vault KV v2 endpoint, mount, and token are required")
	}
	mount, err := normalizedVaultPath(cfg.Mount, false)
	if err != nil {
		return nil, fmt.Errorf("secretsync: Vault KV v2 mount: %w", err)
	}
	prefix, err := normalizedVaultPath(cfg.PathPrefix, true)
	if err != nil {
		return nil, fmt.Errorf("secretsync: Vault KV v2 path prefix: %w", err)
	}
	field := strings.TrimSpace(cfg.Field)
	if field == "" {
		field = "value"
	}
	if strings.ContainsRune(field, '\x00') {
		return nil, errors.New("secretsync: Vault KV v2 field contains a NUL byte")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = netsec.SafeClient(30 * time.Second)
	}
	token, err := secret.NewFrom(cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("secretsync: lock Vault KV v2 token: %w", err)
	}
	return &VaultKVV2Pusher{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"), doer: doer, token: token,
		mount: mount, pathPrefix: prefix, field: field, namespace: strings.TrimSpace(cfg.Namespace),
	}, nil
}

type vaultKVV2State struct {
	version int
	data    map[string]json.RawMessage
}

func (s *vaultKVV2State) wipe() {
	if s == nil {
		return
	}
	for key, value := range s.data {
		secret.Wipe(value)
		delete(s.data, key)
	}
	s.version = 0
}

// Push preserves all sibling fields, uses the observed KV version as options.cas,
// and resolves a lost-response or concurrent-write conflict by reading back before
// attempting another bounded CAS.
func (p *VaultKVV2Pusher) Push(ctx context.Context, key string, value []byte) error {
	if !utf8.Valid(value) {
		return errors.New("secretsync: Vault KV v2 value must be valid UTF-8")
	}
	path, err := normalizedVaultPath(key, false)
	if err != nil {
		return fmt.Errorf("secretsync: Vault KV v2 delivery key: %w", err)
	}
	state, err := p.read(ctx, path)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < vaultKVV2MaxCASAttempts; attempt++ {
		matches, matchErr := p.valueMatches(state, value)
		if matchErr != nil {
			state.wipe()
			return matchErr
		}
		if matches {
			state.wipe()
			return nil
		}
		observedVersion := state.version
		writeErr := p.write(ctx, path, state, value)
		state.wipe()
		if writeErr == nil {
			return nil
		}
		if !isVaultCASStatus(writeErr) {
			return writeErr
		}
		next, readErr := p.read(ctx, path)
		if readErr != nil {
			return readErr
		}
		matches, matchErr = p.valueMatches(next, value)
		if matchErr != nil {
			next.wipe()
			return matchErr
		}
		if matches {
			next.wipe()
			return nil
		}
		if next.version == observedVersion {
			next.wipe()
			return writeErr
		}
		state = next
	}
	state.wipe()
	return fmt.Errorf("secretsync: Vault KV v2 CAS changed during %d bounded attempts", vaultKVV2MaxCASAttempts)
}

func (p *VaultKVV2Pusher) read(ctx context.Context, path string) (*vaultKVV2State, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+p.dataPath(path), nil)
	if err != nil {
		return nil, err
	}
	p.authorize(req)
	var response struct {
		Data struct {
			Data     map[string]json.RawMessage `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	err = readJSON2xx(p.doer, req, &response)
	if statusCode(err) == http.StatusNotFound {
		return &vaultKVV2State{data: map[string]json.RawMessage{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("secretsync: read Vault KV v2 path metadata: %w", err)
	}
	if response.Data.Metadata.Version <= 0 {
		state := &vaultKVV2State{data: response.Data.Data}
		state.wipe()
		return nil, errors.New("secretsync: Vault KV v2 read omitted a positive metadata version")
	}
	if response.Data.Data == nil {
		response.Data.Data = map[string]json.RawMessage{}
	}
	return &vaultKVV2State{version: response.Data.Metadata.Version, data: response.Data.Data}, nil
}

func (p *VaultKVV2Pusher) valueMatches(state *vaultKVV2State, value []byte) (bool, error) {
	raw, ok := state.data[p.field]
	if !ok {
		return false, nil
	}
	var current secret.JSONBytes
	if err := json.Unmarshal(raw, &current); err != nil {
		// KV fields can legally contain non-string JSON. That is not a match, but
		// the raw field remains preserved until this target replaces only its field.
		return false, nil
	}
	defer secret.Wipe(current)
	return crypto.ConstantTimeEqual(current, value), nil
}

func (p *VaultKVV2Pusher) write(ctx context.Context, path string, state *vaultKVV2State, value []byte) error {
	data := make(map[string]json.RawMessage, len(state.data)+1)
	defer func() {
		for key, item := range data {
			secret.Wipe(item)
			delete(data, key)
		}
	}()
	for key, item := range state.data {
		data[key] = bytes.Clone(item)
	}
	encoded, err := secret.JSONBytes(value).MarshalJSON()
	if err != nil {
		return fmt.Errorf("secretsync: encode Vault KV v2 field: %w", err)
	}
	data[p.field] = json.RawMessage(encoded)
	payload := struct {
		Options struct {
			CAS int `json:"cas"`
		} `json:"options"`
		Data map[string]json.RawMessage `json:"data"`
	}{Data: data}
	payload.Options.CAS = state.version
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("secretsync: encode Vault KV v2 CAS write: %w", err)
	}
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+p.dataPath(path), bytes.NewReader(body))
	if err != nil {
		return err
	}
	p.authorize(req)
	req.Header.Set("Content-Type", "application/json")
	if err := expect2xx(p.doer, req); err != nil {
		return fmt.Errorf("secretsync: write Vault KV v2 path with CAS: %w", err)
	}
	return nil
}

func (p *VaultKVV2Pusher) dataPath(path string) string {
	parts := []string{"v1"}
	parts = append(parts, strings.Split(p.mount, "/")...)
	parts = append(parts, "data")
	if p.pathPrefix != "" {
		parts = append(parts, strings.Split(p.pathPrefix, "/")...)
	}
	parts = append(parts, strings.Split(path, "/")...)
	for index := range parts {
		parts[index] = pathEscape(parts[index])
	}
	return "/" + strings.Join(parts, "/")
}

func (p *VaultKVV2Pusher) authorize(req *http.Request) {
	if token := secretBufferBytes(p.token); len(token) > 0 {
		req.Header.Set("X-Vault-Token", secrettext.String(token))
	}
	if p.namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.namespace)
	}
}

func isVaultCASStatus(err error) bool {
	switch statusCode(err) {
	case http.StatusBadRequest, http.StatusConflict, http.StatusPreconditionFailed:
		return true
	default:
		return false
	}
}

func normalizedVaultPath(raw string, allowEmpty bool) (string, error) {
	value := strings.Trim(strings.TrimSpace(raw), "/")
	if value == "" {
		if allowEmpty {
			return "", nil
		}
		return "", errors.New("path is required")
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("path must not contain empty or dot path components")
		}
		if strings.ContainsAny(part, "\x00\\") {
			return "", errors.New("path contains an invalid NUL or backslash")
		}
	}
	return strings.Join(parts, "/"), nil
}

// Close destroys the retained Vault token.
func (p *VaultKVV2Pusher) Close() { destroySecretBuffer(&p.token) }
