// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/hostedkey"
)

// dbtActive is a service token's state while it works (2 is deleted).
const dbtActive = 1

// dbtVendor creates dbt platform service tokens with one permission grant
// ("<account-id>:<permission-set>[:<project-id>]") using an administrator's
// service token, and deletes them by ID (A240).
type dbtVendor struct {
	token *secret.Buffer
}

func dbtTokens(binding string) string {
	account, _, _ := strings.Cut(binding, ":")
	return "/api/v3/accounts/" + account + "/service-tokens/"
}

func (d dbtVendor) mint(ctx context.Context, api hostedAPI, binding, name string) (string, []byte, error) {
	parts := strings.Split(binding, ":")
	grant := map[string]any{"permission_set": parts[1]}
	if len(parts) == 3 {
		project, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return "", nil, err
		}
		grant["project_id"] = project
	}
	var created struct {
		Data uniqueVendorField[dbtToken] `json:"data"`
	}
	token := &created.Data.value
	defer func() { secret.Wipe(token.TokenString.value) }()
	request := map[string]any{"name": name, "permission_grants": []any{grant}}
	if _, err := hostedJSON(ctx, api, http.MethodPost, dbtTokens(binding), request, bearerFrom(d.token), &created, http.StatusCreated); err != nil {
		return "", nil, err
	}
	if len(token.TokenString.value) == 0 {
		return "", nil, errors.New("dynsecret dbt: the create response carries no token")
	}
	candidate := strconv.AppendInt(nil, token.ID.value, 10)
	defer secret.Wipe(candidate)
	id, err := publicVendorID(api.name, candidate, token.TokenString.value)
	if err != nil {
		return "", nil, err
	}
	credential, err := json.Marshal(map[string]any{ // #nosec G117 -- the new token is this provider's output: the outbox seals it and only its readers open it (CWE-200)
		"token": token.TokenString.value, "token_id": id, "account_id": parts[0],
	})
	if err != nil {
		return "", nil, err
	}
	return id, credential, nil
}

type dbtToken struct {
	ID          uniqueVendorField[int64]  `json:"id"`
	Name        uniqueVendorField[string] `json:"name"`
	State       uniqueVendorField[int]    `json:"state"`
	TokenString vendorCredentialField     `json:"token_string"`
}

func (d dbtVendor) named(ctx context.Context, api hostedAPI, binding, name string) ([]string, error) {
	var listed struct {
		Data uniqueVendorField[[]dbtToken] `json:"data"`
	}
	defer func() {
		for _, token := range listed.Data.value {
			secret.Wipe(token.TokenString.value)
		}
	}()
	if _, err := hostedJSON(ctx, api, http.MethodGet, dbtTokens(binding), nil, bearerFrom(d.token), &listed); err != nil {
		return nil, err
	}
	var ids []string
	for _, token := range listed.Data.value {
		if token.Name.value == name && token.State.value == dbtActive {
			candidate := strconv.AppendInt(nil, token.ID.value, 10)
			id, err := publicVendorID(api.name, candidate, token.TokenString.value)
			secret.Wipe(candidate)
			if err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// nameOf reads the token; a deleted one (state 2) counts as gone.
func (d dbtVendor) nameOf(ctx context.Context, api hostedAPI, binding, id string) (string, bool, error) {
	if !hostedkey.NumericID(id) {
		return "", false, errors.New("dynsecret dbt: a service token ID is a number")
	}
	var current struct {
		Data uniqueVendorField[dbtToken] `json:"data"`
	}
	defer func() { secret.Wipe(current.Data.value.TokenString.value) }()
	status, err := hostedJSON(ctx, api, http.MethodGet, dbtTokens(binding)+id+"/", nil, bearerFrom(d.token), &current, http.StatusNotFound)
	if err != nil || status == http.StatusNotFound || current.Data.value.State.value != dbtActive {
		return "", false, err
	}
	entry := current.Data.value
	if entry.ID.seen && strconv.FormatInt(entry.ID.value, 10) != id {
		return "", false, errors.New("dynsecret dbt: lookup returned a different management identity")
	}
	if err := validatePublicVendorID(api.name, []byte(id), entry.TokenString.value); err != nil {
		return "", false, err
	}
	return current.Data.value.Name.value, true, nil
}

func (d dbtVendor) remove(ctx context.Context, api hostedAPI, binding, id string) error {
	if !hostedkey.NumericID(id) {
		return errors.New("dynsecret dbt: a service token ID is a number")
	}
	_, err := hostedJSON(ctx, api, http.MethodDelete, dbtTokens(binding)+id+"/", nil, bearerFrom(d.token), nil, http.StatusNoContent, http.StatusNotFound)
	return err
}

// verify lists the accounts the token can reach, which answers only for a
// live token.
func (dbtVendor) verify(ctx context.Context, api hostedAPI, credential []byte) error {
	token, err := credentialField("dbt", credential, "token")
	if err != nil {
		return err
	}
	defer secret.Wipe(token)
	_, err = hostedJSON(ctx, api, http.MethodGet, "/api/v3/accounts/", nil, bearerValue(token), nil)
	return err
}
