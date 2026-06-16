package aimodel

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// secretShape is one realistic secret embedded in a plausible prompt line. The
// secret column is the substring that MUST NOT survive redaction; the cases below
// are the nine shapes the SURFACE-004 boundary-redactor probe exercised (the
// auditor's executed probe found 8 of 9 surviving the old three-regex redactor),
// plus the trst_ trstctl API token shape and a few additional realistic shapes.
type secretShape struct {
	name   string
	prompt string
	secret string // the high-value substring that must be gone after redaction
}

// surfaceProbeShapes is the permanent, in-tree reconstruction of the SURFACE-004
// probe ($REPO/.surface_probe, deleted by the auditor). Every entry's secret must
// be replaced by DefaultRedactor — this is the regression wall that keeps a future
// edit from re-narrowing the redactor.
var surfaceProbeShapes = []secretShape{
	// --- the 9 SURFACE-004 probe shapes ---
	{
		name:   "json_secret_field",
		prompt: `the config is {"client_secret": "S3cr3tVlue123XX", "id": "app"}`,
		secret: "S3cr3tVlue123XX",
	},
	{
		name:   "short_hex_aes_key",
		prompt: "the AES-128 key is 0123456789abcdef0123456789abcdef in hex",
		secret: "0123456789abcdef0123456789abcdef",
	},
	{
		name:   "bare_aws_akid",
		prompt: "use key AKIAIOSFODNN7EXAMPLE for access to the bucket",
		secret: "AKIAIOSFODNN7EXAMPLE",
	},
	{
		name:   "pem_lowercase_header",
		prompt: "key follows:\n-----begin rsa private key-----\nMIIabcSECRETbodymaterial\n-----end rsa private key-----\ndone",
		secret: "MIIabcSECRETbodymaterial",
	},
	{
		name:   "secret_newline_value",
		prompt: "credentials:\npassword: hunter2horsebattery\nuser: admin",
		secret: "hunter2horsebattery",
	},
	{
		name:   "passphrase_keyword",
		prompt: "passphrase=correct-horse-battery-staple for the keystore",
		secret: "correct-horse-battery-staple",
	},
	{
		name:   "private_key_keyword",
		prompt: "config has private_key=MIGkShortVal123abc set",
		secret: "MIGkShortVal123abc",
	},
	{
		name:   "credential_keyword",
		prompt: "credential=topsecretcredXYZ123 was rotated",
		secret: "topsecretcredXYZ123",
	},
	{
		name:   "jwt_bearer",
		prompt: "Authorization: Bearer eyJhbGciOi.eyJzdWIiOi.SflKxwRJSMxyz was sent",
		secret: "eyJhbGciOi.eyJzdWIiOi.SflKxwRJSMxyz",
	},

	// --- additional realistic shapes (per the fix spec: trst_ tokens, bearer,
	// connection strings, access keys, client secret, base64 blobs) ---
	{
		name:   "trstctl_api_token",
		prompt: "export TRSTCTL_TOKEN=trst_AbCdEf0123456789_GhIjKlMnOp and run",
		secret: "trst_AbCdEf0123456789_GhIjKlMnOp",
	},
	{
		name:   "bearer_opaque",
		prompt: "set header Authorization: Bearer sk-proj-9aZ8yX7wV6uT5sR4qP3oN2 please",
		secret: "sk-proj-9aZ8yX7wV6uT5sR4qP3oN2",
	},
	{
		name:   "postgres_conn_string",
		prompt: "DSN is postgres://admin:Sup3rSecretDbPw@db.internal:5432/trstctl now",
		secret: "Sup3rSecretDbPw",
	},
	{
		name:   "aws_secret_access_key",
		prompt: "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY in profile",
		secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	},
	{
		name:   "client_secret_assignment",
		prompt: "OIDC client_secret: 'gho_16C7e42F292c6912E7710c838347Ae178B4a' loaded",
		secret: "gho_16C7e42F292c6912E7710c838347Ae178B4a",
	},
	{
		name:   "long_base64_blob",
		prompt: "the wrapped key blob is YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5 here",
		secret: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5",
	},
	{
		name:   "uppercase_pem_block",
		prompt: "ctx:\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIKxSECRETBYTES09az\n-----END EC PRIVATE KEY-----\nexplain",
		secret: "MHcCAQEEIKxSECRETBYTES09az",
	},
	{
		name:   "api_key_quoted_json",
		prompt: `payload {"api_key":"AIzaSyD-EXAMPLEexamplekey1234567","q":"x"}`,
		secret: "AIzaSyD-EXAMPLEexamplekey1234567",
	},
}

// TestDefaultRedactorCoversAllSecretShapes is the SURFACE-004 acceptance wall:
// every realistic secret shape is removed by DefaultRedactor and a redaction
// marker is left in its place. This fails on the pre-fix three-regex redactor
// (8 of the first 9 shapes survived) and passes after.
func TestDefaultRedactorCoversAllSecretShapes(t *testing.T) {
	for _, c := range surfaceProbeShapes {
		t.Run(c.name, func(t *testing.T) {
			out := DefaultRedactor(c.prompt)
			if strings.Contains(out, c.secret) {
				t.Errorf("secret %q SURVIVED redaction\n  in:  %s\n  out: %s", c.secret, c.prompt, out)
			}
			if !strings.Contains(out, "[REDACTED") {
				t.Errorf("no redaction marker in output for %q\n  out: %s", c.name, out)
			}
		})
	}
}

// TestRedactorLeavesNoResidualEntropy: after redaction, no probe prompt still
// trips the residual high-entropy detector — so the hard egress gate would let
// each redacted prompt through (the redactor and the gate are consistent).
func TestRedactorLeavesNoResidualEntropy(t *testing.T) {
	for _, c := range surfaceProbeShapes {
		t.Run(c.name, func(t *testing.T) {
			out := DefaultRedactor(c.prompt)
			if ResidualSecret(out) {
				t.Errorf("residual high-entropy material after redaction for %q\n  out: %s", c.name, out)
			}
		})
	}
}

// TestResidualSecretGateRefusesUnredactableSecret: if a raw secret somehow
// reaches Reason with redaction disabled (a hostile/buggy custom redactor that
// passes material through), the residual-entropy gate refuses the send rather
// than egressing it. This proves the gate is a real backstop, not decoration.
func TestResidualSecretGateRefusesUnredactableSecret(t *testing.T) {
	cm := &captureModel{name: "cloud"}
	// A no-op redactor stands in for a broken/hostile redactor.
	a := New(cm, func(p string) string { return p })
	_, err := a.Reason(context.Background(), "raw key 0123456789abcdef0123456789abcdef stays")
	if !errors.Is(err, ErrResidualSecret) {
		t.Fatalf("Reason should refuse a residual secret, got err=%v", err)
	}
	if cm.seen != "" {
		t.Errorf("model received material despite the residual gate: %q", cm.seen)
	}
}

// TestRedactorDoesNotMangleOrdinaryProse: redaction is over-eager but must not
// destroy a normal incident question with no secret in it (otherwise RCA answers
// become useless). Plain words, identifiers, dotted hostnames, and short hex/ids
// stay; the [REDACTED] markers are the only substitutions.
func TestRedactorDoesNotMangleOrdinaryProse(t *testing.T) {
	cases := []string{
		"what is the blast radius of the payments-tls certificate?",
		"the renewal for svc-api.prod.internal failed at 2026-06-14T10:00:00Z",
		"identity id 7f3a is in state requested; explain the transition",
		"the CA is trstctl Issuing CA and the owner is platform-team",
	}
	for _, c := range cases {
		out := DefaultRedactor(c)
		if out != c {
			t.Errorf("ordinary prose was altered:\n  in:  %s\n  out: %s", c, out)
		}
		if ResidualSecret(out) {
			t.Errorf("ordinary prose tripped the residual detector: %s", c)
		}
	}
}
