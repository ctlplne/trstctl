// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

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
		Key   secret.JSONBytes `json:"key"`
		Token string           `json:"token"`
	}
	if _, err := hostedJSON(ctx, api, http.MethodPost, "/key/generate", request, bearerFrom(l.master), &created); err != nil {
		return "", nil, err
	}
	defer secret.Wipe(created.Key)
	if len(created.Key) == 0 || created.Token == "" {
		return "", nil, errors.New("dynsecret litellm: the generate response carries no key")
	}
	credential, err := json.Marshal(map[string]any{ // #nosec G117 -- the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200)
		"api_key": created.Key, "key_hash": created.Token,
	})
	if err != nil {
		return "", nil, err
	}
	return created.Token, credential, nil
}

func (l liteLLMVendor) named(ctx context.Context, api hostedAPI, _ string, name string) ([]string, error) {
	var listed struct {
		Keys []struct {
			Token    string `json:"token"`
			KeyAlias string `json:"key_alias"`
		} `json:"keys"`
	}
	path := "/key/list?return_full_object=true&key_alias=" + url.QueryEscape(name)
	if _, err := hostedJSON(ctx, api, http.MethodGet, path, nil, bearerFrom(l.master), &listed); err != nil {
		return nil, err
	}
	var ids []string
	for _, key := range listed.Keys {
		if key.KeyAlias == name && key.Token != "" {
			ids = append(ids, key.Token)
		}
	}
	return ids, nil
}

func (l liteLLMVendor) nameOf(ctx context.Context, api hostedAPI, _ string, id string) (string, bool, error) {
	var info struct {
		Info struct {
			KeyAlias string `json:"key_alias"`
		} `json:"info"`
	}
	status, err := hostedJSON(ctx, api, http.MethodGet, "/key/info?key="+url.QueryEscape(id), nil, bearerFrom(l.master), &info, http.StatusNotFound)
	if err != nil || status == http.StatusNotFound {
		return "", false, err
	}
	return info.Info.KeyAlias, true, nil
}

func (l liteLLMVendor) remove(ctx context.Context, api hostedAPI, _ string, id string) error {
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
