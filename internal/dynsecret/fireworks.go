// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
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
	KeyID       vendorCredentialField     `json:"keyId"`
	Key         vendorCredentialField     `json:"key"`
	DisplayName uniqueVendorField[string] `json:"displayName"`
}

func (f fireworksVendor) list(ctx context.Context, api hostedAPI, binding string) ([]fireworksKey, error) {
	var listed struct {
		APIKeys uniqueVendorField[[]fireworksKey] `json:"apiKeys"`
	}
	if _, err := hostedJSON(ctx, api, http.MethodGet, fireworksKeys(binding), nil, bearerFrom(f.admin), &listed); err != nil {
		wipeFireworksKeys(listed.APIKeys.value)
		return nil, err
	}
	return listed.APIKeys.value, nil
}

func wipeFireworksKeys(keys []fireworksKey) {
	for _, key := range keys {
		secret.Wipe(key.KeyID.value)
		secret.Wipe(key.Key.value)
	}
}

func (f fireworksVendor) mint(ctx context.Context, api hostedAPI, binding, name string) (string, []byte, error) {
	var created fireworksKey
	defer func() {
		secret.Wipe(created.Key.value)
		secret.Wipe(created.KeyID.value)
	}()
	request := map[string]any{"apiKey": map[string]any{"displayName": name}}
	if _, err := hostedJSON(ctx, api, http.MethodPost, fireworksKeys(binding), request, bearerFrom(f.admin), &created); err != nil {
		return "", nil, err
	}
	if len(created.Key.value) == 0 {
		return "", nil, errors.New("dynsecret fireworks: the create response carries no key")
	}
	id, err := publicVendorID(api.name, created.KeyID.value, created.Key.value)
	if err != nil {
		return "", nil, err
	}
	account, _, _ := strings.Cut(binding, ":")
	credential, err := json.Marshal(map[string]any{ // #nosec G117 -- the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200)
		"api_key": created.Key.value, "key_id": id, "account_id": account,
	})
	if err != nil {
		return "", nil, err
	}
	return id, credential, nil
}

func (f fireworksVendor) named(ctx context.Context, api hostedAPI, binding, name string) ([]string, error) {
	keys, err := f.list(ctx, api, binding)
	if err != nil {
		return nil, err
	}
	defer wipeFireworksKeys(keys)
	var ids []string
	for _, key := range keys {
		if key.DisplayName.value == name {
			id, err := publicVendorID(api.name, key.KeyID.value, key.Key.value)
			if err != nil {
				return nil, err
			}
			ids = append(ids, id)
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
	defer wipeFireworksKeys(keys)
	for _, key := range keys {
		if bytes.Equal(key.KeyID.value, []byte(id)) {
			if _, err := publicVendorID(api.name, key.KeyID.value, key.Key.value); err != nil {
				return "", false, err
			}
			return key.DisplayName.value, true, nil
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
