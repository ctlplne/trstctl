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
	"time"

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
	const maxPages = 100
	path := fireworksKeys(binding)
	var keys []fireworksKey
	seenTokens := make(map[string]bool)
	pageToken := ""
	for page := 0; page < maxPages; page++ {
		query := "?pageSize=100"
		if pageToken != "" {
			query += "&pageToken=" + url.QueryEscape(pageToken)
		}
		var listed struct {
			APIKeys       uniqueVendorField[[]fireworksKey] `json:"apiKeys"`
			NextPageToken uniqueVendorField[string]         `json:"nextPageToken"`
			TotalSize     uniqueVendorField[int]            `json:"totalSize"`
		}
		if _, err := hostedJSON(ctx, api, http.MethodGet, path+query, nil, bearerFrom(f.admin), &listed); err != nil {
			wipeFireworksKeys(listed.APIKeys.value)
			wipeFireworksKeys(keys)
			return nil, err
		}
		if !listed.APIKeys.seen {
			wipeFireworksKeys(keys)
			return nil, errors.New("dynsecret fireworks: key listing omitted apiKeys")
		}
		keys = append(keys, listed.APIKeys.value...)
		if listed.NextPageToken.value == "" {
			if listed.TotalSize.seen && listed.TotalSize.value != len(keys) {
				wipeFireworksKeys(keys)
				return nil, errors.New("dynsecret fireworks: incomplete key listing")
			}
			return keys, nil
		}
		if len(listed.NextPageToken.value) > 4096 || seenTokens[listed.NextPageToken.value] {
			wipeFireworksKeys(keys)
			return nil, errors.New("dynsecret fireworks: repeated or oversized page token")
		}
		seenTokens[listed.NextPageToken.value] = true
		pageToken = listed.NextPageToken.value
	}
	wipeFireworksKeys(keys)
	return nil, errors.New("dynsecret fireworks: key listing exceeds page bound")
}

func wipeFireworksKeys(keys []fireworksKey) {
	for _, key := range keys {
		secret.Wipe(key.KeyID.value)
		secret.Wipe(key.Key.value)
	}
}

func (f fireworksVendor) mint(ctx context.Context, api hostedAPI, binding, name string) (string, []byte, error) {
	return f.mintWithTTL(ctx, api, binding, name, 0)
}

func (f fireworksVendor) mintWithTTL(ctx context.Context, api hostedAPI, binding, name string, ttl time.Duration) (string, []byte, error) {
	if ttl < 0 || ttl > 365*24*time.Hour {
		return "", nil, errors.New("dynsecret fireworks: TTL must be within the vendor's one-year limit")
	}
	var created fireworksKey
	defer func() {
		secret.Wipe(created.Key.value)
		secret.Wipe(created.KeyID.value)
	}()
	key := map[string]any{"displayName": name}
	if ttl > 0 {
		key["expireTime"] = time.Now().Add(ttl).UTC().Format(time.RFC3339Nano)
	}
	request := map[string]any{"apiKey": key}
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
