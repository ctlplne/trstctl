// SPDX-License-Identifier: MPL-2.0

package config

// secretJSONBytes stands in for internal/crypto/secret.JSONBytes: credential
// material that decodes from a plain JSON string but is held as wipeable bytes.
// The fixture declares it locally so this package type-checks without dragging the
// real internal/crypto/secret into testdata.
type secretJSONBytes []byte

// OIDC is the operator-supplied browser-login block. internal/config holds the
// inbound side of every provider credential, so it is in the provider-credential
// scope: a credential-NAMED string field is a fail-closed AN-8 violation, while the
// ordinary string knobs standing right beside it must stay clean. That contrast is
// the whole point of scoping internal/config by field name rather than with the
// //trstctl:keymaterial marker, which would flag Issuer/ClientID/RedirectURI too.
type OIDC struct {
	ClientSecret string // want "provider credential field must not use string"
	Issuer       string
	ClientID     string
	RedirectURI  string
}

// OIDCFixed is the remediated shape: the secret is byte-backed, so it is clean.
// This pins that secret.JSONBytes actually satisfies the rule, rather than the
// rule being satisfied only by deleting the field.
type OIDCFixed struct {
	ClientSecret secretJSONBytes
	Issuer       string
}

// ManagedKeysAWSKMS pins the byte-backed shape the real internal/config already
// uses for provider credentials. These must NOT be flagged — so the widened scope
// cannot be "satisfied" later by regressing them back to string, and the *_File
// path siblings (which are filenames, not secrets) stay plain strings.
type ManagedKeysAWSKMS struct {
	SecretAccessKey     []byte
	SessionToken        []byte
	AccessKeyID         string
	SecretAccessKeyFile string
	Region              string
}
