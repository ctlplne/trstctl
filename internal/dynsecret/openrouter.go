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
		Key  secret.JSONBytes `json:"key"`
		Data struct {
			Hash string           `json:"hash"`
			Key  secret.JSONBytes `json:"key"`
		} `json:"data"`
	}
	if _, err := hostedJSON(ctx, api, http.MethodPost, "/keys", request, bearerFrom(o.management), &created, http.StatusCreated); err != nil {
		return "", nil, err
	}
	defer secret.Wipe(created.Key)
	defer secret.Wipe(created.Data.Key)
	key := created.Key
	if len(key) == 0 {
		key = created.Data.Key
	}
	if len(key) == 0 || created.Data.Hash == "" {
		return "", nil, errors.New("dynsecret openrouter: the create response carries no key")
	}
	credential, err := json.Marshal(map[string]any{ // #nosec G117 -- the new key is this provider's output: the outbox seals it and only its readers open it (CWE-200)
		"api_key": key, "key_hash": created.Data.Hash,
	})
	if err != nil {
		return "", nil, err
	}
	return created.Data.Hash, credential, nil
}

func (o openRouterVendor) named(ctx context.Context, api hostedAPI, _ string, name string) ([]string, error) {
	var ids []string
	for page := 0; page < openRouterListPages; page++ {
		var listed struct {
			Data []struct {
				Hash string `json:"hash"`
				Name string `json:"name"`
			} `json:"data"`
		}
		if _, err := hostedJSON(ctx, api, http.MethodGet, "/keys?offset="+strconv.Itoa(page*100), nil, bearerFrom(o.management), &listed); err != nil {
			return nil, err
		}
		for _, key := range listed.Data {
			if key.Name == name {
				ids = append(ids, key.Hash)
			}
		}
		if len(listed.Data) < 100 {
			return ids, nil
		}
	}
	return nil, fmt.Errorf("dynsecret openrouter: more than %d keys to search for an earlier attempt", openRouterListPages*100)
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
