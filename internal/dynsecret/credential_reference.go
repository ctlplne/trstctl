// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/hostedkey"
)

// uniqueVendorField keeps encoding/json's field-name matching and refuses a
// second assignment, including escaped names and case-insensitive matches.
// Wrap recognized enclosing objects and lists as well as their fields so a
// later object cannot replace material before ID admission.
type uniqueVendorField[T any] struct {
	value T
	seen  bool
}

func (f *uniqueVendorField[T]) UnmarshalJSON(raw []byte) error {
	if f.seen {
		return errors.New("dynsecret: duplicate vendor response field")
	}
	f.seen = true
	return json.Unmarshal(raw, &f.value)
}

type vendorCredentialField = uniqueVendorField[secret.JSONBytes]

// Some list APIs intentionally omit the material represented by a row.
type optionalVendorCredentialField struct{ vendorCredentialField }

func (f *optionalVendorCredentialField) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(raw, []byte("null")) {
		raw = []byte(`""`)
	}
	return f.vendorCredentialField.UnmarshalJSON(raw)
}

func lowerHexID(id []byte, size int) bool {
	if len(id) != size {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validVendorManagementID(provider string, id []byte) bool {
	switch provider {
	case "cloudflare", "cloudflare-r2":
		return lowerHexID(id, 32)
	case "litellm":
		return lowerHexID(id, 64)
	case "dbt":
		if len(id) == 0 || len(id) > 19 || id[0] == '0' || len(id) == 19 && bytes.Compare(id, []byte("9223372036854775807")) > 0 {
			return false
		}
		for _, c := range id {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	default:
		return hostedKeyID.Match(id) && !bytes.Equal(id, []byte(".")) && !bytes.Equal(id, []byte(".."))
	}
}

// publicVendorID checks the actual ID and each complete known secret as bytes.
// A vendor can legitimately include public ID metadata in the credential
// document, so the comparison is against the values that authenticate.
func publicVendorID(provider string, candidate []byte, credentials ...[]byte) (string, error) {
	if err := validatePublicVendorID(provider, candidate, credentials...); err != nil {
		return "", err
	}
	return string(candidate), nil
}

func validatePublicVendorID(provider string, candidate []byte, credentials ...[]byte) error {
	if !validVendorManagementID(provider, candidate) {
		return fmt.Errorf("dynsecret %s: unusable management identifier", provider)
	}
	for _, credential := range credentials {
		if len(credential) != 0 && bytes.Contains(candidate, credential) {
			return fmt.Errorf("dynsecret %s: management identifier contains credential material", provider)
		}
	}
	return nil
}

// liteLLMManagementID accepts the vendor hash and the exact default legacy
// representation after the caller has validated the configured role binding.
func liteLLMManagementID(id []byte) (string, error) {
	if lowerHexID(id, 64) {
		return string(id), nil
	}
	encoded, ok := bytes.CutPrefix(id, []byte("sk-"))
	if !ok || len(encoded) != 22 {
		return "", errors.New("dynsecret litellm: unrecognized management identifier")
	}
	var decoded [16]byte
	defer secret.Wipe(decoded[:])
	if n, err := base64.RawURLEncoding.Strict().Decode(decoded[:], encoded); err != nil || n != len(decoded) {
		return "", errors.New("dynsecret litellm: unrecognized management identifier")
	}
	return crypto.SHA256Hex(id), nil
}

// HostedReferenceProviderType returns a configured provider type governed by
// the hosted management reference contract.
func HostedReferenceProviderType(provider Provider) string {
	if typed, ok := provider.(interface{ DynamicSecretProviderType() string }); ok {
		kind := typed.DynamicSecretProviderType()
		if _, ok := hostedkey.Providers[kind]; ok {
			return kind
		}
	}
	return ""
}

func hostedTargetBoundKind(kind string) bool {
	switch kind {
	case "openrouter", "cloudflare", "cloudflare-r2":
		return true
	default:
		return false
	}
}

// LegacyHostedCredentialDocument recognizes the credential fields written by
// hosted adapters before issued events recorded their provider type. The
// decoder remembers field presence and never saves the values.
func LegacyHostedCredentialDocument(document []byte) bool {
	var fields struct {
		KeyHash     credentialFieldPresent `json:"key_hash"`
		KeyID       credentialFieldPresent `json:"key_id"`
		AccountID   credentialFieldPresent `json:"account_id"`
		ProjectRef  credentialFieldPresent `json:"project_ref"`
		KeyName     credentialFieldPresent `json:"key_name"`
		TokenID     credentialFieldPresent `json:"token_id"`
		SecretID    credentialFieldPresent `json:"secret_id"`
		AccessKeyID credentialFieldPresent `json:"access_key_id"`
		Endpoint    credentialFieldPresent `json:"endpoint"`
	}
	return json.Unmarshal(document, &fields) == nil &&
		(bool(fields.KeyHash || fields.KeyName || fields.TokenID || fields.SecretID) ||
			bool(fields.KeyID && (fields.AccountID || fields.ProjectRef)) ||
			bool(fields.AccessKeyID && fields.Endpoint))
}

type credentialFieldPresent bool

func (field *credentialFieldPresent) UnmarshalJSON(_ []byte) error {
	*field = true
	return nil
}

// NormalizeHostedReference binds the management identifier to the configured
// role before translating a recognized legacy LiteLLM reference.
func NormalizeHostedReference(provider Provider, role, reference string) (string, error) {
	kind := HostedReferenceProviderType(provider)
	if kind == "" {
		return reference, nil
	}
	bound, ok := provider.(interface{ DynamicSecretBindsRole(string, string) bool })
	raw := reference
	if hostedTargetBoundKind(kind) && strings.HasPrefix(reference, "v2:") {
		_, _, parsed, err := opaqueBoundRefShape(reference)
		if err != nil {
			return "", err
		}
		raw = parsed
	}
	cut := strings.LastIndexByte(raw, '/')
	if !ok || cut <= 0 || !bound.DynamicSecretBindsRole(role, raw[:cut]) {
		return "", errors.New("dynsecret: hosted reference does not name the configured role binding")
	}
	id := []byte(raw[cut+1:])
	defer secret.Wipe(id)
	if kind != "litellm" {
		if err := validatePublicVendorID(kind, id); err != nil {
			return "", err
		}
		return reference, nil
	}
	canonical, err := liteLLMManagementID(id)
	if err != nil {
		return "", err
	}
	return raw[:cut] + "/" + canonical, nil
}

type hostedCredentialDocument struct {
	APIKey          vendorCredentialField `json:"api_key"`
	KeyHash         vendorCredentialField `json:"key_hash"`
	KeyID           vendorCredentialField `json:"key_id"`
	DeployKey       vendorCredentialField `json:"deploy_key"`
	KeyName         vendorCredentialField `json:"key_name"`
	Token           vendorCredentialField `json:"token"`
	TokenID         vendorCredentialField `json:"token_id"`
	APIToken        vendorCredentialField `json:"api_token"`
	SecretAccessKey vendorCredentialField `json:"secret_access_key"`
	AccessKeyID     vendorCredentialField `json:"access_key_id"`
	ClientSecret    vendorCredentialField `json:"client_secret"`
	SecretID        vendorCredentialField `json:"secret_id"`
}

func (d *hostedCredentialDocument) wipe() {
	for _, field := range []vendorCredentialField{d.APIKey, d.KeyHash, d.KeyID, d.DeployKey, d.KeyName,
		d.Token, d.TokenID, d.APIToken, d.SecretAccessKey, d.AccessKeyID, d.ClientSecret, d.SecretID} {
		secret.Wipe(field.value)
	}
}

func (d *hostedCredentialDocument) fields(kind string) (material, id []byte) {
	switch kind {
	case "litellm", "openrouter":
		return d.APIKey.value, d.KeyHash.value
	case "fireworks", "supabase":
		return d.APIKey.value, d.KeyID.value
	case "convex":
		return d.DeployKey.value, d.KeyName.value
	case "dbt":
		return d.Token.value, d.TokenID.value
	case "cloudflare":
		return d.APIToken.value, d.TokenID.value
	case "cloudflare-r2":
		return d.SecretAccessKey.value, d.AccessKeyID.value
	case "okta", "databricks":
		return d.ClientSecret.value, d.SecretID.value
	}
	return nil, nil
}

// ValidateIssuedHostedReference repeats the public-ID check at a publication
// boundary. The adapter checks source-only fields before constructing this
// document.
func ValidateIssuedHostedReference(provider Provider, role, reference string, credential []byte) error {
	kind := HostedReferenceProviderType(provider)
	if kind == "" {
		return nil
	}
	if hostedTargetBoundKind(kind) && !strings.HasPrefix(reference, "v2:") {
		return errors.New("dynsecret: newly issued hosted key lacks its target binding")
	}
	canonical, err := NormalizeHostedReference(provider, role, reference)
	if err != nil {
		return err
	}
	if canonical != reference {
		return errors.New("dynsecret: newly issued credential has a legacy reference")
	}
	var doc hostedCredentialDocument
	defer doc.wipe()
	if err := json.Unmarshal(credential, &doc); err != nil {
		return errors.New("dynsecret: hosted credential proof document is invalid")
	}
	material, id := doc.fields(kind)
	cut := strings.LastIndexByte(canonical, '/')
	if len(material) == 0 || !bytes.Equal(id, []byte(canonical[cut+1:])) {
		return errors.New("dynsecret: hosted reference does not match the issued credential proof")
	}
	if err := validatePublicVendorID(kind, id, material); err != nil {
		return err
	}
	if kind == "litellm" && !bytes.Equal(id, []byte(crypto.SHA256Hex(material))) {
		return errors.New("dynsecret: LiteLLM reference does not match its key hash")
	}
	return nil
}
