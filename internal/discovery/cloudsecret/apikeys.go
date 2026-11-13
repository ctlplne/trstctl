// SPDX-License-Identifier: BUSL-1.1

package cloudsecret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
)

// FindingKindAPIKey is emitted for an API key, token or private key found
// inside a secret value during explicit content inspection (A172). The
// finding carries the rule, the field, a masked display and a one-way
// fingerprint; the value never leaves the inspection.
const FindingKindAPIKey = "secret_store_api_key"

// maxCredentialsPerSecret bounds what one value can add to a run.
const maxCredentialsPerSecret = 64

const credentialFingerprintDomain = "trstctl.secret-store-credential.v1" // #nosec G101 -- a hash domain-separation tag, not a credential (CWE-798)

// Credential is one API key, token or private key found inside a secret
// value. Fingerprint is a domain-separated SHA-256 of the credential, equal
// wherever the same credential is stored, so copies across stores line up.
type Credential struct {
	Rule        string
	Kind        string
	Field       string
	Masked      string
	Fingerprint string
	Risk        int
	// Principal is the identity a value names about itself, such as a
	// service account key's client_email. Empty when the value names none.
	Principal string
	// Truncated reports that the value held more credentials than one
	// inspection records.
	Truncated bool
	// SPKISHA256 is, for a private key, the SHA-256 of its public key
	// (SubjectPublicKeyInfo DER), the hash a certificate for that key carries:
	// it links the stored key to its certificate (A172-L3). Empty for other
	// credentials and for an encrypted key.
	SPKISHA256 string
}

// SecretField is one named field of a structured secret value. Providers
// whose values are field maps pass them so a finding can name its field.
type SecretField struct {
	Name  string
	Value []byte
}

type credentialRule struct {
	id       string
	kind     string
	risk     int
	prefixes []string
	pattern  *regexp.Regexp
}

// credentialRules are prefix-anchored shapes with few false positives. There
// is deliberately no generic high-entropy rule: a secret store is full of
// random strings, and calling each one a credential would bury the real ones.
var credentialRules = []credentialRule{
	{id: "aws_access_key_id", kind: "api_key", risk: 40, prefixes: []string{"AKIA", "ASIA"},
		pattern: regexp.MustCompile(`\b((?:AKIA|ASIA)[A-Z0-9]{16})\b`)},
	{id: "aws_secret_access_key", kind: "api_key", risk: 70,
		pattern: regexp.MustCompile(`(?i)aws_?secret_?access_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+]|$)`)},
	{id: "github_personal_access_token", kind: "personal_access_token", risk: 60, prefixes: []string{"github_pat_", "ghp_"},
		pattern: regexp.MustCompile(`\b(github_pat_[A-Za-z0-9_]{50,255}|ghp_[A-Za-z0-9]{36,251})\b`)},
	{id: "github_app_token", kind: "api_token", risk: 50, prefixes: []string{"gho_", "ghu_", "ghs_", "ghr_"},
		pattern: regexp.MustCompile(`\b(gh[ousr]_[A-Za-z0-9]{36,251})\b`)},
	{id: "gitlab_token", kind: "personal_access_token", risk: 60, prefixes: []string{"glpat-", "gldt-", "glrt-"},
		pattern: regexp.MustCompile(`\b(gl(?:pat|dt|rt)-[A-Za-z0-9_\-]{20,64})`)},
	{id: "slack_token", kind: "api_token", risk: 60, prefixes: []string{"xoxa-", "xoxb-", "xoxo-", "xoxp-", "xoxr-", "xoxs-", "xapp-"},
		pattern: regexp.MustCompile(`\b(xox[abopsr]-[A-Za-z0-9-]{10,250}|xapp-[0-9]+-[A-Za-z0-9-]{10,250})`)},
	{id: "slack_webhook_url", kind: "api_token", risk: 50, prefixes: []string{"https://hooks.slack.com/services/"},
		pattern: regexp.MustCompile(`(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})`)},
	{id: "stripe_secret_key", kind: "api_key", risk: 70, prefixes: []string{"sk_live_", "rk_live_"},
		pattern: regexp.MustCompile(`\b((?:sk|rk)_live_[A-Za-z0-9]{16,247})`)},
	{id: "google_api_key", kind: "api_key", risk: 50, prefixes: []string{"AIza"},
		pattern: regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})`)},
	{id: "npm_token", kind: "api_token", risk: 60, prefixes: []string{"npm_"},
		pattern: regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`)},
	{id: "sendgrid_api_key", kind: "api_key", risk: 60, prefixes: []string{"SG."},
		pattern: regexp.MustCompile(`\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})`)},
	{id: "trstctl_api_token", kind: "api_token", risk: 60, prefixes: []string{"trst_"},
		pattern: regexp.MustCompile(`\b(trst_[A-Za-z0-9_\-]{16,256})`)},
	{id: "jwt", kind: "api_token", risk: 40, prefixes: []string{"eyJ"},
		pattern: regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})`)},
	{id: "private_key_pem", kind: "private_key", risk: 70, pattern: privateKeyPEM},
}

var (
	privateKeyPEM       = regexp.MustCompile(`(-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----)`)
	awsSecretFieldName  = regexp.MustCompile(`(?i)secret_?access_?key`)
	awsSecretFieldValue = regexp.MustCompile(`^[A-Za-z0-9/+]{40}$`)
)

// inspectCredentials finds the credentials inside one secret value. A field
// map (from the provider, or a flat JSON object value) is searched field by
// field so each finding names its field; anything else is searched whole.
func inspectCredentials(provider string, s Secret) []Found {
	fields, owned := credentialFields(s)
	if owned {
		defer func() {
			for _, f := range fields {
				secret.Wipe(f.Value)
			}
		}()
	}
	var creds []Credential
	seen := map[string]bool{}
	add := func(c Credential) {
		key := c.Field + "\x00" + c.Fingerprint
		if seen[key] {
			return
		}
		seen[key] = true
		creds = append(creds, c)
	}
	if c, ok := serviceAccountKey(fields); ok {
		add(c)
	}
	for _, f := range fields {
		if f.Name != "" && awsSecretFieldName.MatchString(f.Name) && awsSecretFieldValue.Match(bytes.TrimSpace(f.Value)) {
			add(newCredential("aws_secret_access_key", "api_key", 70, nil, f.Name, bytes.TrimSpace(f.Value)))
		}
		for _, rule := range credentialRules {
			for _, m := range rule.pattern.FindAllSubmatchIndex(f.Value, -1) {
				if len(m) < 4 || m[2] < 0 {
					continue
				}
				add(newCredential(rule.id, rule.kind, rule.risk, rule.prefixes, f.Name, f.Value[m[2]:m[3]]))
			}
		}
	}
	truncated := len(creds) > maxCredentialsPerSecret
	if truncated {
		creds = creds[:maxCredentialsPerSecret]
	}
	out := make([]Found, 0, len(creds))
	for i := range creds {
		c := creds[i]
		c.Truncated = truncated
		meta := cloneMap(s.Metadata)
		meta["content_inspected"] = "true"
		out = append(out, Found{
			Kind: FindingKindAPIKey, Provider: provider, ResourceID: nonempty(s.ResourceID, s.Name),
			SecretName: s.Name, Location: s.Location, Provenance: s.Provenance, Metadata: meta, Credential: &c,
		})
	}
	return out
}

// LocatedCredential is a credential and where its match lies in the text it
// was found in, as a half-open byte range [Start, End).
type LocatedCredential struct {
	Credential
	Start, End int
}

// CredentialsStartingIn matches text with the rules a secret-store value is
// matched with and returns the credentials whose match starts in
// text[from:to] (A172-L1): a leaked secret's line, read from a scanned tree,
// is fingerprinted exactly as a stored copy of the same credential is, so the
// two line up. text may run past to, so a PEM block that starts on the line
// is matched whole. At most maxCredentialsPerSecret are returned.
func CredentialsStartingIn(text []byte, from, to int) []LocatedCredential {
	if from < 0 {
		from = 0
	}
	if to > len(text) {
		to = len(text)
	}
	var out []LocatedCredential
	seen := map[string]bool{}
	for _, rule := range credentialRules {
		for _, m := range rule.pattern.FindAllSubmatchIndex(text, -1) {
			if len(m) < 4 || m[2] < from || m[2] >= to {
				continue
			}
			c := newCredential(rule.id, rule.kind, rule.risk, rule.prefixes, "", text[m[2]:m[3]])
			key := c.Fingerprint + "\x00" + strconv.Itoa(m[2])
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, LocatedCredential{Credential: c, Start: m[2], End: m[3]})
			if len(out) == maxCredentialsPerSecret {
				return out
			}
		}
	}
	return out
}

// credentialFields returns the fields to search: the provider's, a flat JSON
// object's string fields (owned copies the caller wipes), or the whole value.
func credentialFields(s Secret) ([]SecretField, bool) {
	if len(s.Fields) > 0 {
		out := append([]SecretField(nil), s.Fields...)
		sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out, false
	}
	trimmed := bytes.TrimSpace(s.Value)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return []SecretField{{Value: s.Value}}, false
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return []SecretField{{Value: s.Value}}, false
	}
	out := make([]SecretField, 0, len(raw))
	for name, v := range raw {
		value := []byte(v)
		if len(v) > 0 && v[0] == '"' {
			var decoded secretjson.StringBytes
			if json.Unmarshal(v, &decoded) == nil {
				value = []byte(decoded)
				secret.Wipe(v)
			}
		}
		out = append(out, SecretField{Name: name, Value: value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, true
}

// serviceAccountKey recognizes a Google service account key file stored as a
// value: the credential is its private key, and it names its principal.
func serviceAccountKey(fields []SecretField) (Credential, bool) {
	var kind, email, key []byte
	for _, f := range fields {
		switch f.Name {
		case "type":
			kind = f.Value
		case "client_email":
			email = f.Value
		case "private_key":
			key = f.Value
		}
	}
	if !bytes.Equal(kind, []byte("service_account")) || len(email) == 0 || len(key) == 0 {
		return Credential{}, false
	}
	// Fingerprint the PEM block itself, as the private-key rule would, so the
	// key is one finding that also names its principal.
	if m := privateKeyPEM.FindSubmatchIndex(key); len(m) >= 4 && m[2] >= 0 {
		key = key[m[2]:m[3]]
	}
	c := newCredential("gcp_service_account_key", "api_key", 70, nil, "private_key", key)
	c.Principal = string(email)
	c.Masked = "service account " + c.Principal
	return c, true
}

func newCredential(rule, kind string, risk int, prefixes []string, field string, match []byte) Credential {
	c := Credential{
		Rule: rule, Kind: kind, Risk: risk, Field: field,
		Masked: maskCredential(rule, prefixes, match), Fingerprint: credentialFingerprint(match),
	}
	if rule == "private_key_pem" || rule == "gcp_service_account_key" {
		c.SPKISHA256 = privateKeySPKISHA256(match)
	}
	return c
}

// privateKeySPKISHA256 is the SHA-256 of a PEM private key's public key, read
// behind the crypto boundary (AN-3), or "" when the key is encrypted or not
// one the boundary can read.
func privateKeySPKISHA256(pemKey []byte) string {
	info, err := crypto.InspectPrivateKey(pemKey)
	if err != nil || info.Encrypted || info.FingerprintBasis != "public-spki-sha256" {
		return ""
	}
	return info.FingerprintSHA256
}

// credentialFingerprint is the one-way identity of a credential: SHA-256 over
// a domain tag and the credential bytes. Every rule matches a long random
// value, so the digest cannot be walked back to it.
func credentialFingerprint(match []byte) string {
	buf := make([]byte, 0, len(credentialFingerprintDomain)+1+len(match))
	buf = append(buf, credentialFingerprintDomain...)
	buf = append(buf, 0)
	buf = append(buf, match...)
	defer secret.Wipe(buf)
	return crypto.SHA256Hex(buf)
}

// maskCredential shows only what is public about a credential: its
// well-known prefix and its length, or a PEM block's BEGIN line.
func maskCredential(rule string, prefixes []string, match []byte) string {
	if rule == "private_key_pem" {
		if i := bytes.IndexByte(match, '\n'); i > 0 {
			return string(bytes.TrimSpace(match[:i]))
		}
		end := bytes.Index(match, []byte("KEY-----"))
		if end > 0 {
			return string(match[:end+len("KEY-----")])
		}
		return "PEM private key"
	}
	for _, p := range prefixes {
		if bytes.HasPrefix(match, []byte(p)) {
			return fmt.Sprintf("%s…(%d chars)", p, len(match))
		}
	}
	return fmt.Sprintf("…(%d chars)", len(match))
}
