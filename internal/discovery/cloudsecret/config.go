// SPDX-License-Identifier: BUSL-1.1

package cloudsecret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// SourceConfig is the one schema admitted by the API and executed by the
// worker. Both callers use DecodeSourceConfig so an authorization check sees
// exactly the field names the worker will later execute.
type SourceConfig struct {
	Providers []ProviderConfig `json:"providers"`
}

type ProviderConfig struct {
	Provider             string   `json:"provider"`
	Region               string   `json:"region"`
	Endpoint             string   `json:"endpoint"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs"`
	VaultURL             string   `json:"vault_url"`
	APIVersion           string   `json:"api_version"`
	Mount                string   `json:"mount"`
	PathPrefix           string   `json:"path_prefix"`
	AccessKeyIDRef       string   `json:"access_key_id_ref"`
	SecretAccessKeyRef   string   `json:"secret_access_key_ref"`
	SessionTokenRef      string   `json:"session_token_ref"`
	TokenRef             string   `json:"token_ref"`
	Project              string   `json:"project"`
	Location             string   `json:"location"`
	TagKey               string   `json:"tag_key"`
	TagValue             string   `json:"tag_value"`
	LabelKey             string   `json:"label_key"`
	LabelValue           string   `json:"label_value"`
	NamePrefix           string   `json:"name_prefix"`
	InspectContent       bool     `json:"inspect_content"`
	GenericHighEntropy   bool     `json:"generic_high_entropy"`
	Owner                string   `json:"owner"`
	Repo                 string   `json:"repo"`
	Org                  string   `json:"org"`
	Environments         []string `json:"environments"`
	Group                string   `json:"group"`
	Stores               []string `json:"stores"`
	UserCodespaces       bool     `json:"user_codespaces"`
	Instance             bool     `json:"instance"`
	ClientID             string   `json:"client_id"`
	ClientSecretRef      string   `json:"client_secret_ref"`
	Account              string   `json:"account"`
	Login                string   `json:"login"`
	APIKeyRef            string   `json:"api_key_ref"`
	IdentityEndpoint     string   `json:"identity_endpoint"`
	Vaults               []string `json:"vaults"`
	Configs              []string `json:"configs"`
}

// DecodeSourceConfig refuses unknown, mis-cased, and duplicate keys before
// encoding/json can fold a key onto a struct field or discard an earlier value.
// The returned bytes contain only names verified against the typed schema.
func DecodeSourceConfig(raw []byte) (SourceConfig, json.RawMessage, error) {
	root, err := exactObject(raw, reflect.TypeFor[SourceConfig](), "config")
	if err != nil {
		return SourceConfig{}, nil, err
	}
	var providerRaw []json.RawMessage
	if err := json.Unmarshal(root["providers"], &providerRaw); err != nil {
		return SourceConfig{}, nil, fmt.Errorf("config.providers: %w", err)
	}
	providers := make([]map[string]json.RawMessage, 0, len(providerRaw))
	for i, item := range providerRaw {
		provider, err := exactObject(item, reflect.TypeFor[ProviderConfig](), fmt.Sprintf("config.providers[%d]", i))
		if err != nil {
			return SourceConfig{}, nil, err
		}
		providers = append(providers, provider)
	}
	canonicalProviders, err := json.Marshal(providers)
	if err != nil {
		return SourceConfig{}, nil, err
	}
	root["providers"] = canonicalProviders
	canonical, err := json.Marshal(root)
	if err != nil {
		return SourceConfig{}, nil, err
	}
	var cfg SourceConfig
	if err := json.Unmarshal(canonical, &cfg); err != nil {
		return SourceConfig{}, nil, fmt.Errorf("config: %w", err)
	}
	return cfg, canonical, nil
}

func exactObject(raw []byte, schema reflect.Type, path string) (map[string]json.RawMessage, error) {
	allowed := make(map[string]bool, schema.NumField())
	for i := 0; i < schema.NumField(); i++ {
		allowed[strings.Split(schema.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	opening, err := dec.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, fmt.Errorf("%s must be a JSON object", path)
	}
	result := make(map[string]json.RawMessage)
	seen := make(map[string]bool)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		name, ok := token.(string)
		if !ok || !allowed[name] {
			return nil, fmt.Errorf("%s has unknown or mis-cased field %q", path, name)
		}
		folded := strings.ToLower(name)
		if seen[folded] {
			return nil, fmt.Errorf("%s has duplicate field %q", path, name)
		}
		seen[folded] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("%s.%s: %w", path, name, err)
		}
		result[name] = value
	}
	if closing, err := dec.Token(); err != nil || closing != json.Delim('}') {
		return nil, fmt.Errorf("%s is incomplete", path)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s contains trailing JSON data", path)
	}
	return result, nil
}
