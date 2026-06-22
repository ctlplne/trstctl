package badcreds

// DNS provider packages (internal/dns/*) hold ACME/zone-management provider
// credentials. They are in the provider-credential scope (CRYPTO-003), so a
// credential-named string field is a fail-closed AN-8 violation. A non-credential
// label (Zone) is left a plain string to prove the rule is targeted.
type ProviderConfig struct {
	APIToken        string // want "provider credential field must not use string"
	SecretAccessKey string // want "provider credential field must not use string"
	BearerToken     string // want "provider credential field must not use string"
	Zone            string
}
