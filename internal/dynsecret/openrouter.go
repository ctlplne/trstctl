// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// openRouterListPages bounds the key pages a retry reads looking for its
// earlier attempt (100 keys a page).
const openRouterListPages = 20

// openRouterVendor creates OpenRouter API keys with a management key, held to
// the role's credit limit ("unlimited" or "limit-<USD>"), and deletes them by
// hash (A240).
type openRouterVendor struct {
	management *secret.Buffer
}

func (o openRouterVendor) mint(ctx context.Context, api hostedAPI, binding, name string) (string, []byte, error) {
	request := map[string]any{"name": name}
	if amount, ok := strings.CutPrefix(binding, "limit-"); ok {
		limit, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			return "", nil, err
		}
		request["limit"] = limit
	}
	// The reference puts the key at the top level ("shown only once"); the
	// rotation guide shows it under data, so both are read.
	var created struct {
		Key  vendorCredentialField `json:"key"`
		Data uniqueVendorField[struct {
			Hash vendorCredentialField `json:"hash"`
			Key  vendorCredentialField `json:"key"`
		}] `json:"data"`
	}
	data := &created.Data.value
	defer func() {
		secret.Wipe(created.Key.value)
		secret.Wipe(data.Key.value)
		secret.Wipe(data.Hash.value)
	}()
	if _, err := hostedJSON(ctx, api, http.MethodPost, "/keys", request, bearerFrom(o.management), &created, http.StatusCreated); err != nil {
		return "", nil, err
	}
	key := created.Key.value
	if len(key) == 0 {
		key = data.Key.value
	}
	if len(key) == 0 {
		return "", nil, errors.New("dynsecret openrouter: the create response carries no key")
	}
	id, err := publicVendorID(api.name, data.Hash.value, created.Key.value, data.Key.value)
	if err != nil {
		return "", nil, err
	}
	credential, err := json.Marshal(map[string]any{ // #nosec G117 -- the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200)
		"api_key": key, "key_hash": id,
	})
	if err != nil {
		return "", nil, err
	}
	return id, credential, nil
}

func (o openRouterVendor) named(ctx context.Context, api hostedAPI, _ string, name string) ([]string, error) {
	var ids []string
	for page := 0; page < openRouterListPages; page++ {
		matches, count, err := o.earlierAttemptPage(ctx, api, name, page*100)
		if err != nil {
			return nil, err
		}
		ids = append(ids, matches...)
		if count < 100 {
			return ids, nil
		}
	}
	return nil, fmt.Errorf("dynsecret openrouter: more than %d keys to search for an earlier attempt", openRouterListPages*100)
}

func (o openRouterVendor) earlierAttemptPage(ctx context.Context, api hostedAPI, name string, offset int) ([]string, int, error) {
	var listed struct {
		Data uniqueVendorField[[]struct {
			Hash vendorCredentialField     `json:"hash"`
			Name uniqueVendorField[string] `json:"name"`
			Key  vendorCredentialField     `json:"key"`
		}] `json:"data"`
	}
	defer func() {
		for _, key := range listed.Data.value {
			secret.Wipe(key.Hash.value)
			secret.Wipe(key.Key.value)
		}
	}()
	if _, err := hostedJSON(ctx, api, http.MethodGet, "/keys?offset="+strconv.Itoa(offset), nil, bearerFrom(o.management), &listed); err != nil {
		return nil, 0, err
	}
	var ids []string
	for _, key := range listed.Data.value {
		if key.Name.value == name {
			id, err := publicVendorID(api.name, key.Hash.value, key.Key.value)
			if err != nil {
				return nil, 0, err
			}
			ids = append(ids, id)
		}
	}
	return ids, len(listed.Data.value), nil
}

func (o openRouterVendor) nameOf(ctx context.Context, api hostedAPI, _ string, id string) (string, bool, error) {
	var current struct {
		Data struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	status, err := hostedJSON(ctx, api, http.MethodGet, "/keys/"+url.PathEscape(id), nil, bearerFrom(o.management), &current, http.StatusNotFound)
	if err != nil || status == http.StatusNotFound {
		return "", false, err
	}
	return current.Data.Name, true, nil
}

func (o openRouterVendor) remove(ctx context.Context, api hostedAPI, _ string, id string) error {
	_, err := hostedJSON(ctx, api, http.MethodDelete, "/keys/"+url.PathEscape(id), nil, bearerFrom(o.management), nil, http.StatusNotFound)
	return err
}

// verify asks GET /key with the key itself, which answers with the key's own
// details and only for a live key.
func (openRouterVendor) verify(ctx context.Context, api hostedAPI, credential []byte) error {
	key, err := credentialField("openrouter", credential, "api_key")
	if err != nil {
		return err
	}
	defer secret.Wipe(key)
	_, err = hostedJSON(ctx, api, http.MethodGet, "/key", nil, bearerValue(key), nil)
	return err
}
