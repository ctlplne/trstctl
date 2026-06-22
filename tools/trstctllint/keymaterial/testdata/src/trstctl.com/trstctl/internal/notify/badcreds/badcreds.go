package badcreds

// Notification provider packages (internal/notify/*) hold chat/pager webhook
// credentials. They are in the provider-credential scope (CRYPTO-003): a
// credential-named string field is a fail-closed AN-8 violation. The Channel
// label stays a plain string to prove the rule does not over-flag.
type WebhookConfig struct {
	BearerToken  string // want "provider credential field must not use string"
	ClientSecret string // want "provider credential field must not use string"
	AccessToken  string // want "provider credential field must not use string"
	Channel      string
}
