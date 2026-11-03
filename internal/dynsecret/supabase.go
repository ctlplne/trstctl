// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// supabaseKeyName is the Management API's rule for API key names.
var supabaseKeyName = regexp.MustCompile(`^[a-z_][a-z0-9_]{3,63}$`)

// supabaseVendor creates secret API keys in the bound project through the
// Management API and deletes them by ID (A240). Supabase documents no
// side-effect-free check of a secret key, so verification reports not
// available.
type supabaseVendor struct {
	token *secret.Buffer
}

func supabaseKeys(project string) string {
	return "/v1/projects/" + url.PathEscape(project) + "/api-keys"
}

type supabaseKey struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

func (s supabaseVendor) mint(ctx context.Context, api hostedAPI, project, name string) (string, []byte, error) {
	if !supabaseKeyName.MatchString(name) {
		return "", nil, errors.New("dynsecret supabase: the key name does not fit Supabase's naming rule")
	}
	var created struct {
		ID     string           `json:"id"`
		APIKey secret.JSONBytes `json:"api_key"`
	}
	request := map[string]any{"type": "secret", "name": name, "description": "Issued by trstctl"}
	if _, err := hostedJSON(ctx, api, http.MethodPost, supabaseKeys(project)+"?reveal=true", request, bearerFrom(s.token), &created, http.StatusCreated); err != nil {
		return "", nil, err
	}
	defer secret.Wipe(created.APIKey)
	if created.ID == "" || len(created.APIKey) == 0 {
		return "", nil, errors.New("dynsecret supabase: the create response carries no key")
	}
	credential, err := json.Marshal(map[string]any{ // #nosec G117 -- the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200)
		"api_key": created.APIKey, "key_id": created.ID, "project_ref": project,
	})
	if err != nil {
		return "", nil, err
	}
	return created.ID, credential, nil
}

func (s supabaseVendor) named(ctx context.Context, api hostedAPI, project, name string) ([]string, error) {
	var keys []supabaseKey
	if _, err := hostedJSON(ctx, api, http.MethodGet, supabaseKeys(project), nil, bearerFrom(s.token), &keys); err != nil {
		return nil, err
	}
	var ids []string
	for _, key := range keys {
		if key.Name == name && key.Type == "secret" && key.ID != "" {
			ids = append(ids, key.ID)
		}
	}
	return ids, nil
}

// nameOf reads the key; a publishable or legacy key reports no name, so
// revocation never deletes one.
func (s supabaseVendor) nameOf(ctx context.Context, api hostedAPI, project, id string) (string, bool, error) {
	var key supabaseKey
	status, err := hostedJSON(ctx, api, http.MethodGet, supabaseKeys(project)+"/"+url.PathEscape(id), nil, bearerFrom(s.token), &key, http.StatusNotFound)
	if err != nil || status == http.StatusNotFound {
		return "", false, err
	}
	if key.Type != "secret" {
		return "", true, nil
	}
	return key.Name, true, nil
}

func (s supabaseVendor) remove(ctx context.Context, api hostedAPI, project, id string) error {
	_, err := hostedJSON(ctx, api, http.MethodDelete, supabaseKeys(project)+"/"+url.PathEscape(id)+"?reason=rotating_key", nil, bearerFrom(s.token), nil, http.StatusNotFound)
	return err
}

// verify: Supabase documents no side-effect-free check of a secret key.
func (supabaseVendor) verify(context.Context, hostedAPI, []byte) error {
	return ErrNoSelfProof
}
