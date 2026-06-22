package badcreds

// Upstream CA integration packages (internal/ca/*) hold issuer API credentials.
// They are in the provider-credential scope (CRYPTO-003): a credential-named
// string field is a fail-closed AN-8 violation. ProfileName is a non-credential
// label and must stay clean.
type IssuerConfig struct {
	APIKey       string // want "provider credential field must not use string"
	ClientSecret string // want "provider credential field must not use string"
	SessionToken string // want "provider credential field must not use string"
	ProfileName  string
}
