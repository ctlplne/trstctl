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
	openAIProject        = regexp.MustCompile(`^proj_[A-Za-z0-9]{1,64}$`)
	openAIServiceAccount = regexp.MustCompile(`^svc_acct_[A-Za-z0-9]{1,64}$`)
)

// openAIListPages bounds the service-account pages a retry reads looking for
// its earlier attempt.
const openAIListPages = 20

// OpenAIConfig configures the OpenAI service-account key provider (A240):
// each allowed role is bound to a project, and a lease (or each static
// rotation) is a new service account in that project, whose API key OpenAI
// returns once at creation. Revocation, or retiring a rotation's predecessor,
// deletes the service account and its key with it. Rotation is two-phase.
type OpenAIConfig struct {
	// Endpoint is the API, https://api.openai.com.
	Endpoint string
	// AdminKey is an organization admin key, allowed to manage the bound
	// projects' service accounts.
	AdminKey              []byte
	RoleBindings          map[string]string
	UsernamePrefix        string
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
}

// OpenAIBackend issues and deletes project service accounts.
type OpenAIBackend struct {
	api      hostedAPI
	adminKey *secret.Buffer
	projects map[string]string
	prefix   string
}

// NewOpenAIBackend validates cfg.
func NewOpenAIBackend(cfg OpenAIConfig) (*OpenAIBackend, error) {
	api, err := newHostedAPI("openai", cfg.Endpoint, cfg.AllowInsecureLoopback, cfg.HTTPClient)
	if err != nil {
		return nil, err
	}
	if len(cfg.AdminKey) == 0 {
		return nil, errors.New("dynsecret openai: the organization admin key is required")
	}
	b := &OpenAIBackend{api: api, projects: map[string]string{}, prefix: cfg.UsernamePrefix}
	for role, project := range cfg.RoleBindings {
		if !openAIProject.MatchString(strings.TrimSpace(project)) {
			return nil, fmt.Errorf("dynsecret openai: role %q is not bound to a project ID", role)
		}
		b.projects[role] = strings.TrimSpace(project)
	}
	if len(b.projects) == 0 {
		return nil, errors.New("dynsecret openai: every allowed role needs its project in role_bindings")
	}
	if b.adminKey, err = secret.NewFrom(cfg.AdminKey); err != nil {
		return nil, err
	}
	return b, nil
}

// Create implements Backend.
func (b *OpenAIBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

func openAIServiceAccounts(project string) string {
	return "/v1/organization/projects/" + url.PathEscape(project) + "/service_accounts"
}

// CreateCredential implements RequestBackend. The service account's name
// derives from the lease (or the rotation command), and OpenAI shows its key
// only at creation, so a retry first deletes any service account already
// carrying that name: an uncertain attempt leaves one key, not two.
func (b *OpenAIBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	project, ok := b.projects[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret openai: role %q has no project", req.Role)
	}
	name, err := scopedNameForRequest(b.prefix, req, 100, "-")
	if err != nil {
		return "", nil, err
	}
	if err := b.deleteNamed(ctx, project, name); err != nil {
		return "", nil, fmt.Errorf("dynsecret openai: replace an earlier attempt's service account: %w", err)
	}
	body, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		return "", nil, err
	}
	status, response, err := b.api.call(ctx, http.MethodPost, openAIServiceAccounts(project), body, bearerFrom(b.adminKey))
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(response)
	if status != http.StatusOK && status != http.StatusCreated {
		return "", nil, fmt.Errorf("dynsecret openai: create the service account: HTTP %d", status)
	}
	var created struct {
		ID     string `json:"id"`
		APIKey struct {
			Value secret.JSONBytes `json:"value"`
			ID    string           `json:"id"`
		} `json:"api_key"`
	}
	if err := json.Unmarshal(response, &created); err != nil || !openAIServiceAccount.MatchString(created.ID) || len(created.APIKey.Value) == 0 {
		return "", nil, errors.New("dynsecret openai: the create response carries no service account key")
	}
	defer secret.Wipe(created.APIKey.Value)
	credential, err := json.Marshal(map[string]any{ // #nosec G117 -- the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200)
		"api_key": created.APIKey.Value, "service_account_id": created.ID, "project_id": project,
	})
	if err != nil {
		return "", nil, err
	}
	return project + "/" + created.ID, credential, nil
}

// Revoke implements Backend: the service account is deleted after its name is
// checked, so a reference to one someone else created is refused; one already
// gone counts as revoked.
func (b *OpenAIBackend) Revoke(ctx context.Context, ref string) error {
	project, id, ok := strings.Cut(ref, "/")
	if !ok || !openAIServiceAccount.MatchString(id) || !b.boundProject(project) {
		return fmt.Errorf("dynsecret openai: refusing %q, which names no service account of a bound project", ref)
	}
	status, response, err := b.api.call(ctx, http.MethodGet, openAIServiceAccounts(project)+"/"+url.PathEscape(id), nil, bearerFrom(b.adminKey))
	if err != nil {
		return err
	}
	defer secret.Wipe(response)
	if status == http.StatusNotFound {
		return nil
	}
	var current struct {
		Name string `json:"name"`
	}
	if status != http.StatusOK || json.Unmarshal(response, &current) != nil {
		return fmt.Errorf("dynsecret openai: read the service account: HTTP %d", status)
	}
	if !issuedPrincipalNameWith(b.prefix, current.Name, '-') {
		return fmt.Errorf("dynsecret openai: refusing to delete service account %s, which this provider did not create", id)
	}
	return b.delete(ctx, project, id)
}

func (b *OpenAIBackend) boundProject(project string) bool {
	for _, bound := range b.projects {
		if bound == project {
			return true
		}
	}
	return false
}

func (b *OpenAIBackend) delete(ctx context.Context, project, id string) error {
	status, response, err := b.api.call(ctx, http.MethodDelete, openAIServiceAccounts(project)+"/"+url.PathEscape(id), nil, bearerFrom(b.adminKey))
	secret.Wipe(response)
	if err != nil {
		return err
	}
	if status/100 != 2 && status != http.StatusNotFound {
		return fmt.Errorf("dynsecret openai: delete the service account: HTTP %d", status)
	}
	return nil
}

// deleteNamed deletes the project's service accounts that already carry name:
// the leftovers of an attempt whose response was lost.
func (b *OpenAIBackend) deleteNamed(ctx context.Context, project, name string) error {
	after := ""
	for page := 0; page < openAIListPages; page++ {
		path := openAIServiceAccounts(project) + "?limit=100"
		if after != "" {
			path += "&after=" + url.QueryEscape(after)
		}
		status, response, err := b.api.call(ctx, http.MethodGet, path, nil, bearerFrom(b.adminKey))
		if err != nil {
			return err
		}
		var listed struct {
			Data []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"data"`
			HasMore bool   `json:"has_more"`
			LastID  string `json:"last_id"`
		}
		decodeErr := json.Unmarshal(response, &listed)
		secret.Wipe(response)
		if status != http.StatusOK || decodeErr != nil {
			return fmt.Errorf("list service accounts: HTTP %d", status)
		}
		for _, account := range listed.Data {
			if account.Name == name && openAIServiceAccount.MatchString(account.ID) {
				if err := b.delete(ctx, project, account.ID); err != nil {
					return err
				}
			}
		}
		if !listed.HasMore || listed.LastID == "" {
			return nil
		}
		after = listed.LastID
	}
	return fmt.Errorf("list service accounts: more than %d pages", openAIListPages)
}

// VerifyCredential proves a key authenticates: GET /v1/models with it.
func (b *OpenAIBackend) VerifyCredential(ctx context.Context, credential []byte) error {
	var parsed struct {
		APIKey secret.JSONBytes `json:"api_key"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || len(parsed.APIKey) == 0 {
		return errors.New("dynsecret openai: the credential carries no API key")
	}
	defer secret.Wipe(parsed.APIKey)
	status, response, err := b.api.call(ctx, http.MethodGet, "/v1/models", nil, bearerValue(parsed.APIKey))
	secret.Wipe(response)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("dynsecret openai: the key does not authenticate: HTTP %d", status)
	}
	return nil
}

// Close wipes the admin key.
func (b *OpenAIBackend) Close() { b.adminKey.Destroy() }
