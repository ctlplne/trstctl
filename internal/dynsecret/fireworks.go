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

// fireworksVendor creates Fireworks AI API keys for the bound user
// ("<account-id>:<user-id>") with an account administrator's key, and
// deletes them by key ID (A240). Fireworks returns a key's value only at
// creation.
type fireworksVendor struct {
	admin *secret.Buffer
}

func fireworksKeys(binding string) string {
	account, user, _ := strings.Cut(binding, ":")
	return "/v1/accounts/" + url.PathEscape(account) + "/users/" + url.PathEscape(user) + "/apiKeys"
}

type fireworksKey struct {
	KeyID       string `json:"keyId"`
	DisplayName string `json:"displayName"`
}

func (f fireworksVendor) list(ctx context.Context, api hostedAPI, binding string) ([]fireworksKey, error) {
	var listed struct {
		APIKeys []fireworksKey `json:"apiKeys"`
	}
	_, err := hostedJSON(ctx, api, http.MethodGet, fireworksKeys(binding), nil, bearerFrom(f.admin), &listed)
	return listed.APIKeys, err
}

func (f fireworksVendor) mint(ctx context.Context, api hostedAPI, binding, name string) (string, []byte, error) {
	var created struct {
		KeyID string           `json:"keyId"`
		Key   secret.JSONBytes `json:"key"`
	}
	request := map[string]any{"apiKey": map[string]any{"displayName": name}}
	if _, err := hostedJSON(ctx, api, http.MethodPost, fireworksKeys(binding), request, bearerFrom(f.admin), &created); err != nil {
		return "", nil, err
	}
	defer secret.Wipe(created.Key)
	if created.KeyID == "" || len(created.Key) == 0 {
		return "", nil, errors.New("dynsecret fireworks: the create response carries no key")
	}
	account, _, _ := strings.Cut(binding, ":")
	credential, err := json.Marshal(map[string]any{ // #nosec G117 -- the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200)
		"api_key": created.Key, "key_id": created.KeyID, "account_id": account,
	})
	if err != nil {
		return "", nil, err
	}
	return created.KeyID, credential, nil
}

func (f fireworksVendor) named(ctx context.Context, api hostedAPI, binding, name string) ([]string, error) {
	keys, err := f.list(ctx, api, binding)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, key := range keys {
		if key.DisplayName == name && key.KeyID != "" {
			ids = append(ids, key.KeyID)
		}
	}
	return ids, nil
}

// nameOf reads the key's display name from the user's key list: the REST API
// has no single-key read.
func (f fireworksVendor) nameOf(ctx context.Context, api hostedAPI, binding, id string) (string, bool, error) {
	keys, err := f.list(ctx, api, binding)
	if err != nil {
		return "", false, err
	}
	for _, key := range keys {
		if key.KeyID == id {
			return key.DisplayName, true, nil
		}
	}
	return "", false, nil
}

func (f fireworksVendor) remove(ctx context.Context, api hostedAPI, binding, id string) error {
	_, err := hostedJSON(ctx, api, http.MethodPost, fireworksKeys(binding)+":delete", map[string]string{"keyId": id}, bearerFrom(f.admin), nil, http.StatusNotFound)
	return err
}

// verify lists the accounts the key can see, a documented read that answers
// only for a live key.
func (fireworksVendor) verify(ctx context.Context, api hostedAPI, credential []byte) error {
	key, err := credentialField("fireworks", credential, "api_key")
	if err != nil {
		return err
	}
	defer secret.Wipe(key)
	_, err = hostedJSON(ctx, api, http.MethodGet, "/v1/accounts", nil, bearerValue(key), nil)
	return err
}
