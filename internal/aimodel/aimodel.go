// Package aimodel is the pluggable AI model adapter (F76, S19b.1): trstctl's AI
// reasoning runs against a cloud model OR a local (Ollama/vLLM) model by config
// alone — essential for air-gapped / sovereign PKI buyers who cannot send
// credential data to a cloud LLM. A Redactor strips key/secret material at the
// boundary before any prompt reaches a model (AN-8), and the system degrades
// gracefully when no model is configured (everything else in trstctl still works).
package aimodel

import (
	"context"
	"errors"
	"regexp"
)

// Model is a model provider. Cloud and local providers both implement it, so the
// reasoning call is identical across deployments.
type Model interface {
	Name() string
	Complete(ctx context.Context, prompt string) (string, error)
}

// Redactor removes sensitive material from a prompt before it reaches a model.
type Redactor func(prompt string) string

// ErrNoModel is returned when reasoning is attempted with no model configured.
var ErrNoModel = errors.New("aimodel: no model configured (AI features disabled)")

// ErrResidualSecret is returned when, after boundary redaction, the prompt still
// contains a high-entropy run that looks like key material. The model send is
// refused rather than risk egressing a secret the redactor failed to recognize
// (the air-gapped / nothing-phones-home promise is fail-closed at this boundary).
var ErrResidualSecret = errors.New("aimodel: prompt withheld — residual secret-like material after redaction")

// ErrPIIBlocked is returned when the PII egress policy is in Block mode and the
// prompt still carries personal/identifying data after secret redaction. Rather
// than egress a partially-redacted prompt to an optional cloud model, the send is
// refused (PRIVACY-005). It only fires when an operator chose Block over redaction.
var ErrPIIBlocked = errors.New("aimodel: prompt withheld — personal/identifying data present and PII egress policy is block")

// Adapter wraps a Model with boundary redaction and graceful degradation.
type Adapter struct {
	model  Model
	redact Redactor
	// pii is the PRIVACY-005 personal-data egress policy. The zero value is
	// default-private (redact PII before egress); AllowPII consents to send it.
	pii PIIPolicy
}

// New constructs an Adapter. A nil model disables AI (Available reports false);
// a nil redactor uses DefaultRedactor. The PII egress policy defaults to
// default-private (personal/identifying data is redacted before any model send);
// use NewWithPII to consent to PII egress or to choose block-on-PII.
func New(model Model, redact Redactor) *Adapter {
	return NewWithPII(model, redact, PIIPolicy{})
}

// NewWithPII constructs an Adapter with an explicit PII egress policy (PRIVACY-005).
// A nil redactor uses DefaultRedactor. The zero-value PIIPolicy redacts
// personal/identifying data (emails, IPs, OIDC/SPIFFE subjects, hostnames, person
// names) before the prompt reaches the model; PIIPolicy{AllowPII:true} preserves
// it (explicit operator consent); PIIPolicy{Block:true} refuses the send when PII
// is present. The PII boundary runs AFTER secret redaction and BEFORE the
// residual-secret gate and the model send.
func NewWithPII(model Model, redact Redactor, pii PIIPolicy) *Adapter {
	if redact == nil {
		redact = DefaultRedactor
	}
	return &Adapter{model: model, redact: redact, pii: pii}
}

// Available reports whether a model is configured.
func (a *Adapter) Available() bool { return a.model != nil }

// ModelName returns the configured model's name, or "" if none.
func (a *Adapter) ModelName() string {
	if a.model == nil {
		return ""
	}
	return a.model.Name()
}

// Reason redacts the prompt and sends it to the model. With no model configured it
// returns ErrNoModel (callers degrade gracefully). The redacted prompt is what
// crosses the boundary, so no key material reaches the model or its logs. Two
// fail-closed checks follow secret redaction: (1) if the redacted prompt STILL
// contains a high-entropy run that looks like undisclosed key material, the send is
// refused with ErrResidualSecret (AN-8); (2) the PRIVACY-005 PII egress policy
// applies — by default personal/identifying data (emails, IPs, OIDC/SPIFFE
// subjects, hostnames, person names) is redacted before egress, and in Block mode
// the send is refused with ErrPIIBlocked when PII remains. PII handling is skipped
// only when an operator explicitly consented (PIIPolicy.AllowPII).
func (a *Adapter) Reason(ctx context.Context, prompt string) (string, error) {
	if a.model == nil {
		return "", ErrNoModel
	}
	redacted := a.redact(prompt)
	if ResidualSecret(redacted) {
		return "", ErrResidualSecret
	}
	if a.pii.piiActive() {
		if a.pii.Block && ContainsPII(redacted) {
			return "", ErrPIIBlocked
		}
		redacted = RedactPII(redacted)
	}
	return a.model.Complete(ctx, redacted)
}

// Redact exposes the boundary redaction (secret + PII per the configured policy)
// for callers that build prompts elsewhere. PII is redacted unless the policy
// consents (AllowPII); block mode is enforced only on the Reason egress path.
func (a *Adapter) Redact(prompt string) string {
	out := a.redact(prompt)
	if a.pii.piiActive() {
		out = RedactPII(out)
	}
	return out
}

// PIIEgressMode reports the operator-visible PII egress posture for status: one of
// "redact" (default-private), "block" (refuse on PII), or "allow" (operator
// consented to personal-data egress). It carries no secret/personal material.
func (a *Adapter) PIIEgressMode() string {
	switch {
	case a.pii.AllowPII:
		return "allow"
	case a.pii.Block:
		return "block"
	default:
		return "redact"
	}
}

// The boundary redactor is the last line of defense for the product's
// "self-hosted / air-gapped / nothing phones home" promise: with a CloudModel
// configured, anything it misses egresses to a third-party LLM in the prompt
// (SURFACE-004). Coverage is therefore deliberately broad — it errs toward
// over-redaction of anything that looks like key/secret material. Patterns are
// applied most-specific-first (PEM, JWT, keyed assignments, vendor key shapes)
// before the generic high-entropy sweep, so a structured secret is replaced by a
// descriptive marker rather than a bare [REDACTED].
var (
	// PEM blocks, case-insensitive header/footer (lowercase/mixed headers escaped
	// the old uppercase-only [A-Z0-9 ]+ class).
	pemBlock = regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----`)

	// Compact JWS / JWT (three base64url segments). Caught before the keyword and
	// entropy sweeps because the dotted structure breaks a single base64 run.
	jwt = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`)

	// HTTP bearer credentials: Authorization: Bearer <token> (any token shape).
	bearer = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`)

	// trstctl API tokens (trst_ prefix, base64url body) — the product's own token
	// shape, which must never reach a model.
	trstToken = regexp.MustCompile(`\btrst_[A-Za-z0-9_-]{16,}={0,2}`)

	// AWS-style access key IDs (AKIA/ASIA/AGPA/AIDA/AROA + 16 base32 chars) and
	// the longer secret-access-key shape. AKIDs are only 20 chars, so the generic
	// 40-char base64 floor never caught them.
	awsKeyID  = regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\b`)
	awsSecret = regexp.MustCompile(`(?i)(aws_?secret_?access_?key|secret_?access_?key)\s*[=:]\s*"?[A-Za-z0-9/+=]{30,}"?`)

	// Keyed secret assignments. The keyword set is broadened well past the original
	// {password,secret,api_key,token}; an optional closing quote is allowed after
	// the key so a JSON/YAML "key": "value" matches (the old \S+ stopped at the
	// closing structure and never reached the quoted value). The separator and the
	// value are constrained to the SAME line ([ \t], not \s) so a bare section
	// header like `credentials:\n` does not greedily swallow the next line's key.
	secretKV = regexp.MustCompile(`(?i)\b(passphrase|password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|private[_-]?key|secret[_-]?key|credential[s]?|auth[_-]?token|access[_-]?token|refresh[_-]?token|session[_-]?token|token|key)\b["']?[ \t]*[=:][ \t]*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|` + "`" + `[^` + "`" + `]*` + "`" + `|[^\s,;]+)`)

	// Common secret-bearing connection strings (postgres://user:pass@host, etc.):
	// redact the whole URI when it carries userinfo with a password.
	connString = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s/@]+:[^\s/@]+@[^\s]+`)

	// Generic high-entropy material, applied last. The base64 floor drops to 24
	// (catches 16/24-byte key encodings while staying clear of ordinary words),
	// and a dedicated hex pattern (>=32 hex = >=16 bytes) catches raw symmetric
	// keys like an AES-128/256 key that carry no base64 padding or +/ characters.
	longBase64 = regexp.MustCompile(`\b[A-Za-z0-9+/]{24,}={0,2}`)
	longHex    = regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`)
)

// DefaultRedactor strips key/secret material from a prompt before it crosses the
// model boundary (AN-8), replacing each shape with a descriptive [REDACTED-*]
// marker. It covers PEM private-key blocks, JWT/bearer credentials, the trst_ API
// token, AWS access keys, keyed secret/passphrase/credential assignments
// (including quoted JSON/YAML values), secret-bearing connection strings, and
// generic high-entropy base64/hex runs (raw symmetric keys). Patterns run
// most-specific-first so a structured secret is labeled, not just blanked, and
// the broad high-entropy sweep is the backstop. It is intentionally
// over-eager: a redacted-but-useless prompt is the safe failure mode, an
// egressed secret is not. ResidualSecret re-scans the output as a hard gate.
func DefaultRedactor(prompt string) string {
	out := pemBlock.ReplaceAllString(prompt, "[REDACTED-PEM]")
	out = jwt.ReplaceAllString(out, "[REDACTED-JWT]")
	out = trstToken.ReplaceAllString(out, "[REDACTED-TOKEN]")
	out = bearer.ReplaceAllString(out, "[REDACTED-BEARER]")
	out = awsSecret.ReplaceAllString(out, "[REDACTED-SECRET]")
	out = awsKeyID.ReplaceAllString(out, "[REDACTED-AWS-KEY]")
	out = connString.ReplaceAllString(out, "[REDACTED-URI]")
	out = secretKV.ReplaceAllString(out, "[REDACTED-SECRET]")
	out = longBase64.ReplaceAllString(out, "[REDACTED]")
	out = longHex.ReplaceAllString(out, "[REDACTED]")
	return out
}

// residualHighEntropy detects any high-entropy run that survived redaction — the
// detector behind the hard egress gate. It is deliberately a superset of the
// redactor's generic sweeps (base64/hex), so "redact then verify nothing
// high-entropy remains" holds even if a new secret shape is added without its own
// pattern.
var residualHighEntropy = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}|\b[0-9a-fA-F]{32,}\b|eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`)

// ResidualSecret reports whether a (already-redacted) prompt still contains a
// run that looks like undisclosed key material. It is the residual-entropy gate
// the Adapter applies before any model send: redact-then-refuse, so a CloudModel
// never receives a prompt that still matches a high-entropy detector. The
// [REDACTED] markers themselves are plain words and never match.
func ResidualSecret(prompt string) bool {
	return residualHighEntropy.MatchString(prompt)
}

// CloudModel and LocalModel are reference providers over a Completer seam (an HTTP
// client to a cloud API or a local Ollama/vLLM endpoint). The seam keeps them
// testable; live endpoints are exercised on the CI backstop.

// Completer performs one model completion (the HTTP call seam).
type Completer interface {
	Do(ctx context.Context, prompt string) (string, error)
}

// CloudModel is a cloud-hosted model provider.
type CloudModel struct {
	Provider string
	Client   Completer
}

// Name implements Model.
func (m CloudModel) Name() string { return "cloud:" + m.Provider }

// Complete implements Model.
func (m CloudModel) Complete(ctx context.Context, prompt string) (string, error) {
	return m.Client.Do(ctx, prompt)
}

// LocalModel is a local (Ollama/vLLM) model provider for air-gapped deployments.
type LocalModel struct {
	Runtime string // "ollama" | "vllm"
	Client  Completer
}

// Name implements Model.
func (m LocalModel) Name() string { return "local:" + m.Runtime }

// Complete implements Model.
func (m LocalModel) Complete(ctx context.Context, prompt string) (string, error) {
	return m.Client.Do(ctx, prompt)
}
