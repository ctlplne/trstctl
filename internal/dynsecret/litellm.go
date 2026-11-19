// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// liteLLMVendor generates LiteLLM proxy virtual keys with the master key,
// aliased for the lease or command and limited to the role's models
// ("all-models" or "models:<name>,<name>"), and deletes them by token hash
// (A240).
type liteLLMVendor struct {
	master *secret.Buffer
}

func (l liteLLMVendor) mint(ctx context.Context, api hostedAPI, binding, name string) (string, []byte, error) {
	request := map[string]any{"key_alias": name}
	if models, ok := strings.CutPrefix(binding, "models:"); ok {
		request["models"] = strings.Split(models, ",")
	}
	var created struct {
		Key   vendorCredentialField `json:"key"`
		Token vendorCredentialField `json:"token"`
	}
	defer func() {
		secret.Wipe(created.Key.value)
		secret.Wipe(created.Token.value)
	}()
	if _, err := hostedJSON(ctx, api, http.MethodPost, "/key/generate", request, bearerFrom(l.master), &created); err != nil {
		return "", nil, err
	}
	if len(created.Key.value) == 0 || len(created.Token.value) == 0 {
		return "", nil, errors.New("dynsecret litellm: the generate response carries no key")
	}
	hash := crypto.SHA256Hex(created.Key.value)
	if !crypto.ConstantTimeEqual(created.Token.value, created.Key.value) &&
		!crypto.ConstantTimeEqual(created.Token.value, []byte(hash)) {
		return "", nil, errors.New("dynsecret litellm: generate response has conflicting key identity")
	}
	id, err := publicVendorID(api.name, []byte(hash), created.Key.value)
	if err != nil {
		return "", nil, err
	}
	credential, err := json.Marshal(map[string]any{ // #nosec G117 -- the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200)
		"api_key": created.Key.value, "key_hash": id,
	})
	if err != nil {
		return "", nil, err
	}
	return id, credential, nil
}

func (l liteLLMVendor) named(ctx context.Context, api hostedAPI, _ string, name string) ([]string, error) {
	var listed struct {
		Keys uniqueVendorField[[]struct {
			Token    vendorCredentialField     `json:"token"`
			Key      vendorCredentialField     `json:"key"`
			KeyAlias uniqueVendorField[string] `json:"key_alias"`
		}] `json:"keys"`
	}
	defer func() {
		for _, key := range listed.Keys.value {
			secret.Wipe(key.Token.value)
			secret.Wipe(key.Key.value)
		}
	}()
	path := "/key/list?return_full_object=true&key_alias=" + url.QueryEscape(name)
	if _, err := hostedJSON(ctx, api, http.MethodGet, path, nil, bearerFrom(l.master), &listed); err != nil {
		return nil, err
	}
	var ids []string
	for _, key := range listed.Keys.value {
		if key.KeyAlias.value == name {
			id, err := publicVendorID(api.name, key.Token.value, key.Key.value)
			if err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (l liteLLMVendor) nameOf(ctx context.Context, api hostedAPI, _ string, id string) (string, bool, error) {
	if !validVendorManagementID("litellm", []byte(id)) {
		return "", false, errors.New("dynsecret litellm: unusable management identifier")
	}
	var info struct {
		Info uniqueVendorField[struct {
			KeyAlias uniqueVendorField[string] `json:"key_alias"`
		}] `json:"info"`
	}
	status, err := hostedJSON(ctx, api, http.MethodGet, "/key/info?key="+url.QueryEscape(id), nil, bearerFrom(l.master), &info, http.StatusNotFound)
	if err != nil || status == http.StatusNotFound {
		return "", false, err
	}
	return info.Info.value.KeyAlias.value, true, nil
}

func (l liteLLMVendor) remove(ctx context.Context, api hostedAPI, _ string, id string) error {
	if !validVendorManagementID("litellm", []byte(id)) {
		return errors.New("dynsecret litellm: unusable management identifier")
	}
	_, err := hostedJSON(ctx, api, http.MethodPost, "/key/delete", map[string]any{"keys": []string{id}}, bearerFrom(l.master), nil, http.StatusNotFound)
	return err
}

// verify asks GET /key/info with the key itself, which answers with the key's
// own details only while it is live.
func (liteLLMVendor) verify(ctx context.Context, api hostedAPI, credential []byte) error {
	key, err := credentialField("litellm", credential, "api_key")
	if err != nil {
		return err
	}
	defer secret.Wipe(key)
	_, err = hostedJSON(ctx, api, http.MethodGet, "/key/info", nil, bearerValue(key), nil)
	return err
}
