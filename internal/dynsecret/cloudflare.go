// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// cloudflareID is a Cloudflare account or token ID.
var cloudflareID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// cloudflareListPages bounds the token pages a retry reads looking for its
// earlier attempt (50 tokens a page).
const cloudflareListPages = 40

// cloudflareVendor creates Cloudflare API tokens that copy a template
// token's policies and condition ("user:<template-id>" or
// "account:<account-id>:<template-id>"), so the operator decides their
// authority once, in the dashboard; it deletes them by ID (A240). Creating a
// successor and deleting the predecessor keeps both working until
// retirement, where Cloudflare's own roll would end the old value at once.
// With r2 the credential is the token's R2 S3 pair: the access key ID is the
// token's ID and the secret access key the SHA-256 of its value.
type cloudflareVendor struct {
	admin *secret.Buffer
	r2    bool
}

// cloudflareTarget splits a canonical binding into the tokens path, the
// template's ID and the account (empty for user tokens).
func cloudflareTarget(binding string) (path, template, account string) {
	parts := strings.Split(binding, ":")
	if parts[0] == "account" {
		return "/accounts/" + parts[1] + "/tokens", parts[2], parts[1]
	}
	return "/user/tokens", parts[1], ""
}

// cloudflareEnvelope is Cloudflare's response wrapper.
type cloudflareEnvelope[T any] struct {
	Success    bool `json:"success"`
	Result     T    `json:"result"`
	ResultInfo struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type cloudflarePolicy struct {
	Effect           string            `json:"effect"`
	PermissionGroups []json.RawMessage `json:"permission_groups"`
	Resources        json.RawMessage   `json:"resources"`
}

type cloudflareTokenIdentity struct {
	ID    vendorCredentialField     `json:"id"`
	Value vendorCredentialField     `json:"value"`
	Name  uniqueVendorField[string] `json:"name"`
}

func (token cloudflareTokenIdentity) wipe() {
	secret.Wipe(token.ID.value)
	secret.Wipe(token.Value.value)
}

func (c cloudflareVendor) mint(ctx context.Context, api hostedAPI, binding, name string) (string, []byte, error) {
	path, template, account := cloudflareTarget(binding)
	var current cloudflareEnvelope[struct {
		Policies  []cloudflarePolicy `json:"policies"`
		Condition json.RawMessage    `json:"condition"`
	}]
	if _, err := hostedJSON(ctx, api, http.MethodGet, path+"/"+template, nil, bearerFrom(c.admin), &current); err != nil {
		return "", nil, fmt.Errorf("dynsecret %s: read the template token: %w", api.name, err)
	}
	if !current.Success || len(current.Result.Policies) == 0 {
		return "", nil, fmt.Errorf("dynsecret %s: the template token has no policies to copy", api.name)
	}
	// Only the policy fields a create takes: the template's policy IDs and
	// permission group names are its own.
	policies := make([]map[string]any, 0, len(current.Result.Policies))
	for _, policy := range current.Result.Policies {
		groups := make([]map[string]json.RawMessage, 0, len(policy.PermissionGroups))
		for _, raw := range policy.PermissionGroups {
			var group map[string]json.RawMessage
			if err := json.Unmarshal(raw, &group); err != nil || len(group["id"]) == 0 {
				return "", nil, fmt.Errorf("dynsecret %s: the template token's permission group has no ID", api.name)
			}
			kept := map[string]json.RawMessage{"id": group["id"]}
			if meta, ok := group["meta"]; ok {
				kept["meta"] = meta
			}
			groups = append(groups, kept)
		}
		policies = append(policies, map[string]any{"effect": policy.Effect, "permission_groups": groups, "resources": policy.Resources})
	}
	request := map[string]any{"name": name, "policies": policies}
	if len(current.Result.Condition) > 0 && string(current.Result.Condition) != "null" {
		request["condition"] = current.Result.Condition
	}
	var created cloudflareEnvelope[uniqueVendorField[cloudflareTokenIdentity]]
	token := &created.Result.value
	defer func() { token.wipe() }()
	if _, err := hostedJSON(ctx, api, http.MethodPost, path, request, bearerFrom(c.admin), &created); err != nil {
		return "", nil, err
	}
	if !created.Success || len(token.Value.value) == 0 {
		return "", nil, fmt.Errorf("dynsecret %s: the create response carries no token", api.name)
	}
	var secretKey secret.JSONBytes
	if c.r2 {
		digest := crypto.SHA256Sum(token.Value.value)
		defer secret.Wipe(digest)
		secretKey = make(secret.JSONBytes, hex.EncodedLen(len(digest)))
		hex.Encode(secretKey, digest)
		defer secret.Wipe(secretKey)
	}
	id, err := publicVendorID(api.name, token.ID.value, token.Value.value, secretKey)
	if err != nil {
		return "", nil, err
	}
	var document map[string]any
	if c.r2 {
		document = map[string]any{
			"access_key_id": id, "secret_access_key": secretKey,
			"endpoint": "https://" + account + ".r2.cloudflarestorage.com",
		}
	} else {
		document = map[string]any{"api_token": token.Value.value, "token_id": id}
		if account != "" {
			document["account_id"] = account
		}
	}
	credential, err := json.Marshal(document) // #nosec G117 -- the new token is this provider's output: the outbox seals it and only its readers open it (CWE-200)
	if err != nil {
		return "", nil, err
	}
	return id, credential, nil
}

func (c cloudflareVendor) named(ctx context.Context, api hostedAPI, binding, name string) ([]string, error) {
	path, _, _ := cloudflareTarget(binding)
	var ids []string
	for page := 1; page <= cloudflareListPages; page++ {
		matches, pages, err := c.earlierAttemptPage(ctx, api, path, name, page)
		if err != nil {
			return nil, err
		}
		ids = append(ids, matches...)
		if page >= pages {
			return ids, nil
		}
	}
	return nil, fmt.Errorf("dynsecret %s: more than %d tokens to search for an earlier attempt", api.name, cloudflareListPages*50)
}

func (c cloudflareVendor) earlierAttemptPage(ctx context.Context, api hostedAPI, path, name string, page int) ([]string, int, error) {
	var listed cloudflareEnvelope[uniqueVendorField[[]cloudflareTokenIdentity]]
	defer func() {
		for _, token := range listed.Result.value {
			token.wipe()
		}
	}()
	if _, err := hostedJSON(ctx, api, http.MethodGet, path+"?per_page=50&page="+strconv.Itoa(page), nil, bearerFrom(c.admin), &listed); err != nil {
		return nil, 0, err
	}
	var ids []string
	for _, token := range listed.Result.value {
		if token.Name.value == name {
			id, err := publicVendorID(api.name, token.ID.value, token.Value.value)
			if err != nil {
				return nil, 0, err
			}
			ids = append(ids, id)
		}
	}
	return ids, listed.ResultInfo.TotalPages, nil
}

func (c cloudflareVendor) nameOf(ctx context.Context, api hostedAPI, binding, id string) (string, bool, error) {
	if !validVendorManagementID("cloudflare", []byte(id)) {
		return "", false, errors.New("dynsecret cloudflare: unusable management identifier")
	}
	path, _, _ := cloudflareTarget(binding)
	var current cloudflareEnvelope[uniqueVendorField[cloudflareTokenIdentity]]
	defer func() { current.Result.value.wipe() }()
	status, err := hostedJSON(ctx, api, http.MethodGet, path+"/"+url.PathEscape(id), nil, bearerFrom(c.admin), &current, http.StatusNotFound)
	if err != nil || status == http.StatusNotFound {
		return "", false, err
	}
	if _, err := publicVendorID(api.name, []byte(id), current.Result.value.Value.value); err != nil {
		return "", false, err
	}
	return current.Result.value.Name.value, true, nil
}

func (c cloudflareVendor) remove(ctx context.Context, api hostedAPI, binding, id string) error {
	if !validVendorManagementID("cloudflare", []byte(id)) {
		return errors.New("dynsecret cloudflare: unusable management identifier")
	}
	path, _, _ := cloudflareTarget(binding)
	_, err := hostedJSON(ctx, api, http.MethodDelete, path+"/"+url.PathEscape(id), nil, bearerFrom(c.admin), nil, http.StatusNotFound)
	return err
}

// verify asks Cloudflare's token verification route with the token itself,
// which answers active only for a live token. An R2 pair carries no token
// value (only its digest), and its S3 endpoint is the account's own host, so
// R2 verification reports not available.
func (c cloudflareVendor) verify(ctx context.Context, api hostedAPI, credential []byte) error {
	if c.r2 {
		return ErrNoSelfProof
	}
	var parsed struct {
		TokenID   string `json:"token_id"`
		AccountID string `json:"account_id"`
	}
	_ = json.Unmarshal(credential, &parsed)
	// An account-owned token verifies at its account's route.
	path := "/user/tokens/verify"
	if parsed.AccountID != "" {
		if !cloudflareID.MatchString(parsed.AccountID) {
			return errors.New("dynsecret cloudflare: the credential's account ID is not an ID")
		}
		path = "/accounts/" + parsed.AccountID + "/tokens/verify"
	}
	token, err := credentialField(api.name, credential, "api_token")
	if err != nil {
		return err
	}
	defer secret.Wipe(token)
	var verified cloudflareEnvelope[struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}]
	if _, err := hostedJSON(ctx, api, http.MethodGet, path, nil, bearerValue(token), &verified); err != nil {
		return err
	}
	if !verified.Success || verified.Result.Status != "active" || (parsed.TokenID != "" && verified.Result.ID != parsed.TokenID) {
		return errors.New("dynsecret cloudflare: the token is not active")
	}
	return nil
}
