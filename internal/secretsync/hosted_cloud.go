// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// Cloud secret and configuration stores (A241).

// cloudflareCall sends one Cloudflare API v4 request; an answer whose
// envelope says success false fails without keeping its errors.
func cloudflareCall(ctx context.Context, p *HostedSyncPusher, method, path string, body []byte, result any) error {
	var envelope struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
	}
	if err := p.send(ctx, method, path, body, &envelope); err != nil {
		return err
	}
	defer secret.Wipe(envelope.Result)
	if !envelope.Success {
		return errors.New("the Cloudflare API answered success false")
	}
	if result == nil || len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		return nil
	}
	return json.Unmarshal(envelope.Result, result)
}

// Cloudflare Workers secrets: PUT creates or replaces one (a new Worker
// version), DELETE removes it; values are never returned.
var cloudflareWorkersVendor = &hostedVendor{
	name:         "Cloudflare Workers",
	deliveryMode: "Worker script secret PUT and DELETE over HTTPS (each change is a new Worker version)",
	authMode:     "Bearer API token (Workers Scripts edit) supplied by operator config",
	wireFormat:   `JSON {name, text, type: "secret_text"}`,
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		body := append([]byte(`{"name":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"text":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, `,"type":"secret_text"}`...)
		defer secret.Wipe(body)
		return hostedError(p, "set secret", cloudflareCall(ctx, p, http.MethodPut, workersPath(p, ""), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var got []struct {
			Name string `json:"name"`
		}
		if err := cloudflareCall(ctx, p, http.MethodGet, workersPath(p, ""), nil, &got); err != nil {
			return nil, hostedError(p, "list secrets", err)
		}
		names := make([]string, 0, len(got))
		for _, item := range got {
			names = append(names, item.Name)
		}
		return names, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return hostedError(p, "delete secret", ignoreNotFound(cloudflareCall(ctx, p, http.MethodDelete, workersPath(p, key), nil, nil)))
	},
}

func workersPath(p *HostedSyncPusher, key string) string {
	path := "/accounts/" + pathEscape(p.binding["account"]) + "/workers/scripts/" + pathEscape(p.binding["script"]) + "/secrets"
	if key != "" {
		path += "/" + pathEscape(key)
	}
	return path
}

// Cloudflare Pages project variables: one PATCH of the project's deployment
// config sets a secret_text variable for the bound environment (a null
// removes it); a secret's value is not returned. Applied on the next
// deployment.
var cloudflarePagesVendor = &hostedVendor{
	name:         "Cloudflare Pages",
	deliveryMode: "project deployment_configs PATCH over HTTPS (applied on the next deployment; null removes)",
	authMode:     "Bearer API token (Pages edit) supplied by operator config",
	wireFormat:   `JSON deployment_configs.<environment>.env_vars {NAME: {type: "secret_text", value}}`,
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		variable := append([]byte(`{"type":"secret_text","value":`), appendJSONValueBytes(nil, value)...)
		variable = append(variable, '}')
		defer secret.Wipe(variable)
		return pagesPatch(ctx, p, key, variable)
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var project struct {
			DeploymentConfigs map[string]struct {
				EnvVars map[string]struct {
					Type string `json:"type"`
				} `json:"env_vars"`
			} `json:"deployment_configs"`
		}
		if err := cloudflareCall(ctx, p, http.MethodGet, pagesPath(p), nil, &project); err != nil {
			return nil, hostedError(p, "read project", err)
		}
		var names []string
		for name := range project.DeploymentConfigs[pagesEnvironment(p)].EnvVars {
			names = append(names, name)
		}
		return names, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return pagesPatch(ctx, p, key, []byte("null"))
	},
}

func pagesPath(p *HostedSyncPusher) string {
	return "/accounts/" + pathEscape(p.binding["account"]) + "/pages/projects/" + pathEscape(p.binding["project"])
}

func pagesEnvironment(p *HostedSyncPusher) string {
	if env := p.binding["environment"]; env != "" {
		return env
	}
	return "production"
}

func pagesPatch(ctx context.Context, p *HostedSyncPusher, key string, variable []byte) error {
	body := append([]byte(`{"deployment_configs":{`), appendJSONValueBytes(nil, []byte(pagesEnvironment(p)))...)
	body = append(body, `:{"env_vars":{`...)
	body = appendJSONValueBytes(body, []byte(key))
	body = append(body, ':')
	body = append(body, variable...)
	body = append(body, `}}}}`...)
	defer secret.Wipe(body)
	return hostedError(p, "update project variables", cloudflareCall(ctx, p, http.MethodPatch, pagesPath(p), body, nil))
}

// Cloudflare Secrets Store: create (an array of one), PATCH the value by ID,
// DELETE by ID; the value is write-only.
var cloudflareSecretsStoreVendor = &hostedVendor{
	name:         "Cloudflare Secrets Store",
	deliveryMode: "account store secret POST, PATCH and DELETE over HTTPS",
	authMode:     "Bearer API token (Secrets Store edit) supplied by operator config",
	wireFormat:   `JSON [{name, value, scopes: ["workers"], comment}]`,
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		ids, err := secretsStoreIDs(ctx, p)
		if err != nil {
			return err
		}
		if id, ok := ids[key]; ok {
			body := jsonValueBody("value", value)
			defer secret.Wipe(body)
			return hostedError(p, "update secret", cloudflareCall(ctx, p, http.MethodPatch, secretsStorePath(p)+"/"+pathEscape(id), body, nil))
		}
		body := append([]byte(`[{"name":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, `,"scopes":["workers"],"comment":"managed by trstctl"}]`...)
		defer secret.Wipe(body)
		return hostedError(p, "create secret", cloudflareCall(ctx, p, http.MethodPost, secretsStorePath(p), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		ids, err := secretsStoreIDs(ctx, p)
		if err != nil {
			return nil, err
		}
		return mapKeys(ids), nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		ids, err := secretsStoreIDs(ctx, p)
		if err != nil {
			return err
		}
		id, ok := ids[key]
		if !ok {
			return nil
		}
		return hostedError(p, "delete secret", ignoreNotFound(cloudflareCall(ctx, p, http.MethodDelete, secretsStorePath(p)+"/"+pathEscape(id), nil, nil)))
	},
}

func secretsStorePath(p *HostedSyncPusher) string {
	return "/accounts/" + pathEscape(p.binding["account"]) + "/secrets_store/stores/" + pathEscape(p.binding["store"]) + "/secrets"
}

// secretsStoreIDs maps each secret name in the store to its ID, every page.
func secretsStoreIDs(ctx context.Context, p *HostedSyncPusher) (map[string]string, error) {
	ids := map[string]string{}
	for page := 1; page <= hostedPageLimit; page++ {
		var envelope struct {
			Success bool `json:"success"`
			Result  []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
			ResultInfo struct {
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
		}
		if err := p.send(ctx, http.MethodGet, secretsStorePath(p)+"?per_page=100&page="+strconv.Itoa(page), nil, &envelope); err != nil || !envelope.Success {
			if err == nil {
				err = errors.New("the Cloudflare API answered success false")
			}
			return nil, hostedError(p, "list secrets", err)
		}
		for _, item := range envelope.Result {
			ids[item.Name] = item.ID
		}
		if page >= envelope.ResultInfo.TotalPages {
			return ids, nil
		}
	}
	return nil, ErrScopedListLimit
}

// Azure App Configuration key-values (data plane, HMAC-SHA256 access-key
// signing): PUT upserts, DELETE removes, GET reads the value back, all under
// the bound label.
var azureAppConfigVendor = &hostedVendor{
	name:         "Azure App Configuration",
	deliveryMode: "key-value PUT and DELETE over HTTPS (data plane, api-version 1.0)",
	authMode:     "access key ID (username) and secret (token_ref), HMAC-SHA256 request signing",
	wireFormat:   "application/vnd.microsoft.appconfig.kv+json {value, content_type, tags}",
	readBack:     ReadBackValue,
	proof:        ProofStandIn,
	headers:      func(*HostedSyncPusher, *http.Request) {},
	sign:         signAzureAppConfig,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		body := append([]byte(`{"value":`), appendJSONValueBytes(nil, value)...)
		body = append(body, `,"content_type":"","tags":{"managed-by":"trstctl"}}`...)
		defer secret.Wipe(body)
		req, err := p.request(ctx, http.MethodPut, appConfigKVPath(p, key), body, "application/vnd.microsoft.appconfig.kv+json")
		if err != nil {
			return err
		}
		return hostedError(p, "set key-value", expect2xx(p.doer, req))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var names []string
		next := "/kv?key=*&label=" + url.QueryEscape(appConfigLabel(p)) + "&$select=key&api-version=1.0"
		for range hostedPageLimit {
			var page struct {
				Items []struct {
					Key string `json:"key"`
				} `json:"items"`
				NextLink string `json:"@nextLink"`
			}
			if err := p.send(ctx, http.MethodGet, next, nil, &page); err != nil {
				return nil, hostedError(p, "list key-values", err)
			}
			for _, item := range page.Items {
				names = append(names, item.Key)
			}
			if page.NextLink == "" {
				return names, nil
			}
			link, err := url.Parse(page.NextLink)
			if err != nil || link.IsAbs() {
				return nil, hostedError(p, "list key-values", errors.New("the next link is not a relative path"))
			}
			next = link.RequestURI()
		}
		return nil, ErrScopedListLimit
	},
	read: func(ctx context.Context, p *HostedSyncPusher, key string) (bool, []byte, error) {
		var got struct {
			Value secret.JSONBytes `json:"value"`
		}
		err := p.send(ctx, http.MethodGet, appConfigKVPath(p, key), nil, &got)
		if notFound(err) {
			return false, nil, nil
		}
		if err != nil {
			return false, nil, hostedError(p, "read key-value", err)
		}
		return true, got.Value, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return hostedError(p, "delete key-value", ignoreNotFound(p.send(ctx, http.MethodDelete, appConfigKVPath(p, key), nil, nil)))
	},
}

// appConfigLabel is the bound label; "\x00" (sent as %00) is no label.
func appConfigLabel(p *HostedSyncPusher) string {
	if label := p.binding["label"]; label != "" {
		return label
	}
	return "\x00"
}

func appConfigKVPath(p *HostedSyncPusher, key string) string {
	return "/kv/" + pathEscape(key) + "?label=" + url.QueryEscape(appConfigLabel(p)) + "&api-version=1.0"
}

// signAzureAppConfig adds App Configuration's HMAC-SHA256 authentication:
// the date, the body's SHA-256 and a signature over the method, path and
// query, and those headers, keyed by the decoded access key secret.
func signAzureAppConfig(p *HostedSyncPusher, req *http.Request, body []byte) error {
	date := time.Now().UTC().Format(http.TimeFormat)
	hash := base64.StdEncoding.EncodeToString(crypto.SHA256Sum(body))
	req.Header.Set("x-ms-date", date)
	req.Header.Set("x-ms-content-sha256", hash)
	key := make([]byte, base64.StdEncoding.DecodedLen(len(p.token.Bytes())))
	defer secret.Wipe(key)
	n, err := base64.StdEncoding.Decode(key, p.token.Bytes())
	if err != nil {
		return errors.New("the access key secret is not base64")
	}
	toSign := req.Method + "\n" + req.URL.RequestURI() + "\n" + date + ";" + req.URL.Host + ";" + hash
	signature := base64.StdEncoding.EncodeToString(crypto.HMACSHA256(key[:n], []byte(toSign)))
	req.Header.Set("Authorization", "HMAC-SHA256 Credential="+p.username+"&SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature="+signature)
	return nil
}

// OCI Vault secrets (vault management API, request signing): create, a new
// version by PUT, and scheduled deletion (OCI keeps a deleted secret for at
// least a day; a secret pending deletion is not listed, and a new value for
// its name first cancels the deletion). Reading a value takes the separate
// secret retrieval host, so the target is receipt-only.
var ociVaultVendor = &hostedVendor{
	name:         "OCI Vault",
	deliveryMode: "vault secret create, PUT of a new version, and scheduled deletion over HTTPS (request signing)",
	authMode:     "API signing key: key ID tenancy/user/fingerprint (username) and the PEM private key (token_ref)",
	wireFormat:   `JSON secretContent {contentType: "BASE64", content}`,
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers:      func(*HostedSyncPusher, *http.Request) {},
	sign:         signOCIRequest,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		secrets, err := ociSecrets(ctx, p, true)
		if err != nil {
			return err
		}
		content := make([]byte, base64.StdEncoding.EncodedLen(len(value)))
		base64.StdEncoding.Encode(content, value)
		defer secret.Wipe(content)
		if s, ok := secrets[key]; ok {
			if s.state == "PENDING_DELETION" {
				if err := p.send(ctx, http.MethodPost, "/secrets/"+pathEscape(s.id)+"/actions/cancelDeletion", []byte(`{}`), nil); err != nil {
					return hostedError(p, "cancel the secret's deletion", err)
				}
			}
			body := append([]byte(`{"secretContent":{"contentType":"BASE64","content":"`), content...)
			body = append(body, `"}}`...)
			defer secret.Wipe(body)
			return hostedError(p, "add a secret version", p.send(ctx, http.MethodPut, "/secrets/"+pathEscape(s.id), body, nil))
		}
		body := append([]byte(`{"compartmentId":`), appendJSONValueBytes(nil, []byte(p.binding["compartment"]))...)
		body = append(body, `,"vaultId":`...)
		body = appendJSONValueBytes(body, []byte(p.binding["vault"]))
		body = append(body, `,"keyId":`...)
		body = appendJSONValueBytes(body, []byte(p.binding["key"]))
		body = append(body, `,"secretName":`...)
		body = appendJSONValueBytes(body, []byte(key))
		body = append(body, `,"description":"managed by trstctl","secretContent":{"contentType":"BASE64","content":"`...)
		body = append(body, content...)
		body = append(body, `"}}`...)
		defer secret.Wipe(body)
		return hostedError(p, "create secret", p.send(ctx, http.MethodPost, "/secrets", body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		secrets, err := ociSecrets(ctx, p, false)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(secrets))
		for name := range secrets {
			names = append(names, name)
		}
		return names, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		secrets, err := ociSecrets(ctx, p, false)
		if err != nil {
			return err
		}
		s, ok := secrets[key]
		if !ok {
			return nil
		}
		when := time.Now().UTC().Add(25 * time.Hour).Format(time.RFC3339)
		body := []byte(`{"timeOfDeletion":"` + when + `"}`)
		return hostedError(p, "schedule the secret's deletion", ignoreNotFound(p.send(ctx, http.MethodPost, "/secrets/"+pathEscape(s.id)+"/actions/scheduleDeletion", body, nil)))
	},
}

type ociSecret struct{ id, state string }

// ociSecrets maps the vault's secret names to their IDs and lifecycle
// states, every page; a secret deleted or pending deletion is left out
// unless pending is set.
func ociSecrets(ctx context.Context, p *HostedSyncPusher, pending bool) (map[string]ociSecret, error) {
	out := map[string]ociSecret{}
	page := ""
	for range hostedPageLimit {
		path := "/secrets?compartmentId=" + url.QueryEscape(p.binding["compartment"]) + "&vaultId=" + url.QueryEscape(p.binding["vault"]) + "&limit=100"
		if page != "" {
			path += "&page=" + url.QueryEscape(page)
		}
		req, err := p.request(ctx, http.MethodGet, path, nil, "application/json")
		if err != nil {
			return nil, err
		}
		var got []struct {
			ID             string `json:"id"`
			SecretName     string `json:"secretName"`
			LifecycleState string `json:"lifecycleState"`
		}
		next, err := p.sendForHeader(ctx, req, &got, "opc-next-page")
		if err != nil {
			return nil, hostedError(p, "list secrets", err)
		}
		for _, item := range got {
			switch item.LifecycleState {
			case "DELETED":
			case "PENDING_DELETION":
				if pending {
					out[item.SecretName] = ociSecret{item.ID, item.LifecycleState}
				}
			default:
				out[item.SecretName] = ociSecret{item.ID, item.LifecycleState}
			}
		}
		if next == "" {
			return out, nil
		}
		page = next
	}
	return nil, ErrScopedListLimit
}

// signOCIRequest adds OCI's request signature (version 1, rsa-sha256): the
// date, and for a body its SHA-256, type and length, signed with the
// API key over (request-target), date, host and those body headers.
func signOCIRequest(p *HostedSyncPusher, req *http.Request, body []byte) error {
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	headers := []string{"(request-target)", "date", "host"}
	if req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch {
		if body == nil {
			body = []byte{}
		}
		req.Header.Set("x-content-sha256", base64.StdEncoding.EncodeToString(crypto.SHA256Sum(body)))
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		headers = append(headers, "x-content-sha256", "content-type", "content-length")
	}
	lines := make([]string, 0, len(headers))
	for _, h := range headers {
		switch h {
		case "(request-target)":
			lines = append(lines, "(request-target): "+strings.ToLower(req.Method)+" "+req.URL.RequestURI())
		case "host":
			lines = append(lines, "host: "+req.URL.Host)
		default:
			lines = append(lines, h+": "+req.Header.Get(h))
		}
	}
	signature, err := crypto.SignRSASHA256WithPEMKey(p.token.Bytes(), []byte(strings.Join(lines, "\n")))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", `Signature version="1",keyId="`+p.username+`",algorithm="rsa-sha256",headers="`+
		strings.Join(headers, " ")+`",signature="`+base64.StdEncoding.EncodeToString(signature)+`"`)
	return nil
}

// OVHcloud Secret Manager (OKMS v2): a secret is a path holding a JSON
// object; the value is its "value" field. Create, a new version, and
// DELETE (every version); GET with includeData reads the value back.
var ovhVendor = &hostedVendor{
	name:         "OVHcloud Secret Manager",
	deliveryMode: "OKMS secret create or new version, and DELETE, over HTTPS",
	authMode:     "Bearer personal access token supplied by operator config",
	wireFormat:   `JSON version.data {"value": <the secret>}`,
	readBack:     ReadBackValue,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		data := append([]byte(`{"value":`), appendJSONValueBytes(nil, value)...)
		data = append(data, '}')
		defer secret.Wipe(data)
		exists, _, err := ovhRead(ctx, p, key, false)
		if err != nil {
			return err
		}
		if exists {
			body := append([]byte(`{"data":`), data...)
			body = append(body, '}')
			defer secret.Wipe(body)
			return hostedError(p, "add a secret version", p.send(ctx, http.MethodPost, ovhPath(p, key)+"/version", body, nil))
		}
		body := append([]byte(`{"path":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"version":{"data":`...)
		body = append(body, data...)
		body = append(body, `}}`...)
		defer secret.Wipe(body)
		return hostedError(p, "create secret", p.send(ctx, http.MethodPost, ovhPath(p, ""), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var names []string
		cursor := ""
		for range hostedPageLimit {
			req, err := p.request(ctx, http.MethodGet, ovhPath(p, ""), nil, "application/json")
			if err != nil {
				return nil, err
			}
			req.Header.Set("X-Pagination-Size", "100")
			if cursor != "" {
				req.Header.Set("X-Pagination-Cursor", cursor)
			}
			var got []struct {
				Path string `json:"path"`
			}
			next, err := p.sendForHeader(ctx, req, &got, "X-Pagination-Cursor-Next")
			if err != nil {
				return nil, hostedError(p, "list secrets", err)
			}
			for _, item := range got {
				names = append(names, item.Path)
			}
			if next == "" {
				return names, nil
			}
			cursor = next
		}
		return nil, ErrScopedListLimit
	},
	read: func(ctx context.Context, p *HostedSyncPusher, key string) (bool, []byte, error) {
		return ovhRead(ctx, p, key, true)
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		return hostedError(p, "delete secret", ignoreNotFound(p.send(ctx, http.MethodDelete, ovhPath(p, key), nil, nil)))
	},
}

func ovhPath(p *HostedSyncPusher, key string) string {
	path := "/api/" + pathEscape(p.binding["okms"]) + "/v2/secret"
	if key != "" {
		parts := strings.Split(key, "/")
		for i, part := range parts {
			parts[i] = pathEscape(part)
		}
		path += "/" + strings.Join(parts, "/")
	}
	return path
}

// ovhRead reads a secret; with data, the current version's value field.
func ovhRead(ctx context.Context, p *HostedSyncPusher, key string, data bool) (bool, []byte, error) {
	path := ovhPath(p, key)
	if data {
		path += "?includeData=true"
	}
	var got struct {
		Version struct {
			Data struct {
				Value secret.JSONBytes `json:"value"`
			} `json:"data"`
		} `json:"version"`
	}
	err := p.send(ctx, http.MethodGet, path, nil, &got)
	if notFound(err) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, hostedError(p, "read secret", err)
	}
	if !data {
		secret.Wipe(got.Version.Data.Value)
		return true, nil, nil
	}
	return true, got.Version.Data.Value, nil
}

// Databricks secrets in a scope: put overwrites, delete removes, list names
// the keys. Reading a value back is DBUtils-only, so the target is
// receipt-only.
var databricksVendor = &hostedVendor{
	name:         "Databricks",
	deliveryMode: "workspace secrets put and delete in a scope over HTTPS (API 2.0)",
	authMode:     "Bearer personal access or OAuth token supplied by operator config",
	wireFormat:   "JSON {scope, key, string_value}",
	readBack:     ReadBackReceiptOnly,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		body := append([]byte(`{"scope":`), appendJSONValueBytes(nil, []byte(p.binding["scope"]))...)
		body = append(body, `,"key":`...)
		body = appendJSONValueBytes(body, []byte(key))
		body = append(body, `,"string_value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, '}')
		defer secret.Wipe(body)
		return hostedError(p, "put secret", p.send(ctx, http.MethodPost, "/api/2.0/secrets/put", body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		var got struct {
			Secrets []struct {
				Key string `json:"key"`
			} `json:"secrets"`
		}
		if err := p.send(ctx, http.MethodGet, "/api/2.0/secrets/list?scope="+url.QueryEscape(p.binding["scope"]), nil, &got); err != nil {
			return nil, hostedError(p, "list secrets", err)
		}
		names := make([]string, 0, len(got.Secrets))
		for _, item := range got.Secrets {
			names = append(names, item.Key)
		}
		return names, nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		names, err := p.vendor.list(ctx, p)
		if err != nil {
			return err
		}
		for _, name := range names {
			if strings.EqualFold(name, key) {
				body := append([]byte(`{"scope":`), appendJSONValueBytes(nil, []byte(p.binding["scope"]))...)
				body = append(body, `,"key":`...)
				body = appendJSONValueBytes(body, []byte(name))
				body = append(body, '}')
				return hostedError(p, "delete secret", ignoreNotFound(p.send(ctx, http.MethodPost, "/api/2.0/secrets/delete", body, nil)))
			}
		}
		return nil
	},
}

// Supabase Edge Function secrets (Management API): one POST upserts, a
// DELETE with the names removes, and the list returns each secret's SHA-256
// digest (hex), never its value.
var supabaseVendor = &hostedVendor{
	name:         "Supabase",
	deliveryMode: "project secrets POST (upsert) and DELETE over HTTPS (Management API)",
	authMode:     "Bearer personal access or OAuth token (secrets:write) supplied by operator config",
	wireFormat:   "JSON [{name, value}]",
	readBack:     ReadBackDigest,
	proof:        ProofStandIn,
	headers:      bearerHeaders,
	digestOf:     crypto.SHA256Hex,
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		body := append([]byte(`[{"name":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"value":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, `}]`...)
		defer secret.Wipe(body)
		return hostedError(p, "set secret", p.send(ctx, http.MethodPost, supabasePath(p), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		digests, err := supabaseDigests(ctx, p)
		if err != nil {
			return nil, err
		}
		return mapKeys(digests), nil
	},
	read: func(ctx context.Context, p *HostedSyncPusher, key string) (bool, []byte, error) {
		digests, err := supabaseDigests(ctx, p)
		if err != nil {
			return false, nil, err
		}
		digest, ok := digests[key]
		if !ok {
			return false, nil, nil
		}
		return true, []byte(strings.ToLower(digest)), nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		body := appendJSONValueBytes([]byte(`[`), []byte(key))
		body = append(body, ']')
		return hostedError(p, "delete secret", ignoreNotFound(p.send(ctx, http.MethodDelete, supabasePath(p), body, nil)))
	},
}

func supabasePath(p *HostedSyncPusher) string {
	return "/v1/projects/" + pathEscape(p.binding["project"]) + "/secrets"
}

func supabaseDigests(ctx context.Context, p *HostedSyncPusher) (map[string]string, error) {
	var got []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := p.send(ctx, http.MethodGet, supabasePath(p), nil, &got); err != nil {
		return nil, hostedError(p, "list secrets", err)
	}
	out := make(map[string]string, len(got))
	for _, item := range got {
		out[item.Name] = item.Value
	}
	return out, nil
}

// Camunda 8 SaaS cluster (connector) secrets: create (409 if present),
// PUT the value, DELETE; the list returns each value. Requests carry a
// token the API client's ID and secret are exchanged for per operation.
var camundaVendor = &hostedVendor{
	name:         "Camunda",
	deliveryMode: "cluster secret POST, PUT and DELETE over HTTPS (Administration API)",
	authMode:     "API client ID (username) and secret (token_ref) exchanged for a token per operation",
	wireFormat:   "JSON {secretName, secretValue}",
	readBack:     ReadBackValue,
	proof:        ProofStandIn,
	headers:      func(*HostedSyncPusher, *http.Request) {},
	put: func(ctx context.Context, p *HostedSyncPusher, key string, value []byte) error {
		if !utf8.Valid(value) {
			return errHostedValueNotText
		}
		token, err := camundaToken(ctx, p)
		if err != nil {
			return err
		}
		defer secret.Wipe(token)
		vars, err := camundaSecrets(ctx, p, token)
		if err != nil {
			return err
		}
		_, exists := vars[key]
		wipeJSONMap(vars)
		if exists {
			body := jsonValueBody("secretValue", value)
			defer secret.Wipe(body)
			return hostedError(p, "update secret", camundaCall(ctx, p, token, http.MethodPut, camundaPath(p, key), body, nil))
		}
		body := append([]byte(`{"secretName":`), appendJSONValueBytes(nil, []byte(key))...)
		body = append(body, `,"secretValue":`...)
		body = appendJSONValueBytes(body, value)
		body = append(body, '}')
		defer secret.Wipe(body)
		return hostedError(p, "create secret", camundaCall(ctx, p, token, http.MethodPost, camundaPath(p, ""), body, nil))
	},
	list: func(ctx context.Context, p *HostedSyncPusher) ([]string, error) {
		token, err := camundaToken(ctx, p)
		if err != nil {
			return nil, err
		}
		defer secret.Wipe(token)
		vars, err := camundaSecrets(ctx, p, token)
		if err != nil {
			return nil, err
		}
		defer wipeJSONMap(vars)
		names := make([]string, 0, len(vars))
		for name := range vars {
			names = append(names, name)
		}
		return names, nil
	},
	read: func(ctx context.Context, p *HostedSyncPusher, key string) (bool, []byte, error) {
		token, err := camundaToken(ctx, p)
		if err != nil {
			return false, nil, err
		}
		defer secret.Wipe(token)
		vars, err := camundaSecrets(ctx, p, token)
		if err != nil {
			return false, nil, err
		}
		defer wipeJSONMap(vars)
		value, ok := vars[key]
		if !ok {
			return false, nil, nil
		}
		return true, append([]byte(nil), value...), nil
	},
	remove: func(ctx context.Context, p *HostedSyncPusher, key string) error {
		token, err := camundaToken(ctx, p)
		if err != nil {
			return err
		}
		defer secret.Wipe(token)
		vars, err := camundaSecrets(ctx, p, token)
		if err != nil {
			return err
		}
		_, exists := vars[key]
		wipeJSONMap(vars)
		if !exists {
			return nil
		}
		return hostedError(p, "delete secret", ignoreNotFound(camundaCall(ctx, p, token, http.MethodDelete, camundaPath(p, key), nil, nil)))
	},
}

// camundaDefaultEndpoint is the Administration API; its tokens come from
// Camunda's login host. A target pointed elsewhere (a stand-in) takes its
// token from <endpoint>/oauth/token.
const (
	camundaDefaultEndpoint = "https://api.cloud.camunda.io"
	camundaLoginEndpoint   = "https://login.cloud.camunda.io/oauth/token"
)

func camundaPath(p *HostedSyncPusher, key string) string {
	path := "/clusters/" + pathEscape(p.binding["cluster"]) + "/secrets"
	if key != "" {
		path += "/" + pathEscape(key)
	}
	return path
}

// camundaToken exchanges the API client's ID and secret for an access token
// (client credentials, audience api.cloud.camunda.io), held only for this
// operation.
func camundaToken(ctx context.Context, p *HostedSyncPusher) ([]byte, error) {
	endpointURL := camundaLoginEndpoint
	if p.endpoint != camundaDefaultEndpoint {
		endpointURL = p.endpoint + "/oauth/token"
	}
	form := []byte("grant_type=client_credentials&audience=api.cloud.camunda.io&client_id=" + url.QueryEscape(p.username) + "&client_secret=")
	form = appendQueryEscapedBytes(form, p.token.Bytes())
	defer secret.Wipe(form)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(form))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var got struct {
		AccessToken secret.JSONBytes `json:"access_token"`
	}
	if err := readJSON2xx(p.doer, req, &got); err != nil || len(got.AccessToken) == 0 {
		secret.Wipe(got.AccessToken)
		if err == nil {
			err = errors.New("no access token in the answer")
		}
		return nil, hostedError(p, "exchange the client credentials", err)
	}
	return got.AccessToken, nil
}

func camundaCall(ctx context.Context, p *HostedSyncPusher, token []byte, method, path string, body []byte, out any) error {
	req, err := p.request(ctx, method, path, body, "application/json")
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	return readJSON2xx(p.doer, req, out)
}

func camundaSecrets(ctx context.Context, p *HostedSyncPusher, token []byte) (map[string]secret.JSONBytes, error) {
	var got map[string]secret.JSONBytes
	if err := camundaCall(ctx, p, token, http.MethodGet, camundaPath(p, ""), nil, &got); err != nil {
		return nil, hostedError(p, "list secrets", err)
	}
	if got == nil {
		got = map[string]secret.JSONBytes{}
	}
	return got, nil
}

// appendQueryEscapedBytes appends value form-escaped, without a Go string of
// it.
func appendQueryEscapedBytes(dst, value []byte) []byte {
	const hexDigits = "0123456789ABCDEF"
	for _, c := range value {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			dst = append(dst, c)
		default:
			dst = append(dst, '%', hexDigits[c>>4], hexDigits[c&15])
		}
	}
	return dst
}
