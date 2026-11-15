// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"math/rand"
	"strings"
)

// corpusToken is one credential format trstctl needs a scan to catch (P14-L4).
// The samples are built at test time, never written in the source, so the
// repository holds no token-shaped literal.
type corpusToken struct {
	Name   string // the format, as the corpus file names it
	Sample string // one synthetic value of the format
}

// corpusChars draws n characters from alphabet, deterministically.
func corpusChars(r *rand.Rand, alphabet string, n int) string {
	var b strings.Builder
	for range n {
		b.WriteByte(alphabet[r.Intn(len(alphabet))])
	}
	return b.String()
}

const (
	corpusB64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	corpusB64    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	corpusB62    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	corpusLower  = "abcdefghijklmnopqrstuvwxyz0123456789"
	corpusHex    = "0123456789abcdef"
	corpusUpper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

// tokenCorpus is every format in the corpus, each with one sample: the
// credentials trstctl issues, the tokens of the secret stores it reads and
// leases from, the clouds it leases, and the code hosts and channels it
// integrates with.
func tokenCorpus() []corpusToken {
	r := rand.New(rand.NewSource(1414)) // #nosec G404 -- a fixed, reproducible corpus of synthetic samples, not a secret (CWE-338)
	p := func(parts ...string) string { return strings.Join(parts, "") }
	uuid := func() string {
		h := corpusChars(r, corpusHex, 32)
		return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-8" + h[17:20] + "-" + h[20:]
	}
	return []corpusToken{
		// trstctl's own credentials.
		{"trstctl-api-token", p("trs", "t_", corpusChars(r, corpusB64URL, 43))},
		{"trstctl-opaque-access-token", p("trs", "to_", corpusChars(r, corpusB64URL, 120))},
		{"trstctl-vault-wrapping-token", p("trs", "tw_", corpusChars(r, corpusHex, 64))},
		// Secret stores trstctl reads and leases from.
		{"vault-service-token", p("hv", "s.", corpusChars(r, corpusB62, 95))},
		{"vault-legacy-service-token", p("s", ".", corpusChars(r, corpusB62, 24))},
		{"vault-batch-token", p("hv", "b.", corpusChars(r, corpusB62, 150))},
		{"doppler-service-token", p("dp", ".st.", corpusChars(r, corpusLower, 4), ".", corpusChars(r, corpusB62, 40))},
		{"doppler-personal-token", p("dp", ".pt.", corpusChars(r, corpusB62, 43))},
		{"doppler-service-account-token", p("dp", ".sa.", corpusChars(r, corpusB62, 43))},
		{"doppler-cli-token", p("dp", ".ct.", corpusChars(r, corpusB62, 43))},
		{"infisical-service-token", p("st", ".", corpusChars(r, corpusHex, 24), ".", corpusChars(r, corpusHex, 32), ".", corpusChars(r, corpusHex, 32))},
		{"bitwarden-secrets-manager-access-token", p("0", ".", uuid(), ".", corpusChars(r, corpusB62, 30), ":", corpusChars(r, corpusB64, 22), "==")},
		{"1password-service-account-token", p("op", "s_", "eyJ", corpusChars(r, corpusB64, 300))},
		// Clouds trstctl leases from.
		{"aws-access-key-id", p("AK", "IA", corpusChars(r, corpusUpper, 16))},
		{"aws-session-key-id", p("AS", "IA", corpusChars(r, corpusUpper, 16))},
		{"azure-client-secret", p(corpusChars(r, corpusB62, 3), "8Q", "~", corpusChars(r, corpusB62, 34))},
		// Channels and code hosts trstctl integrates with.
		{"github-fine-grained-token", p("github", "_pat_", corpusChars(r, corpusB62, 22), "_", corpusChars(r, corpusB62, 59))},
		{"github-classic-token", p("gh", "p_", corpusChars(r, corpusB62, 36))},
		{"gitlab-personal-token", p("gl", "pat-", corpusChars(r, corpusB62, 20))},
		{"slack-bot-token", p("xo", "xb-", corpusChars(r, "0123456789", 12), "-", corpusChars(r, "0123456789", 13), "-", corpusChars(r, corpusB62, 24))},
		// Doppler's workplace SCIM and audit tokens (drawn last, so the samples
		// above stay the same).
		{"doppler-scim-token", p("dp", ".scim.", corpusChars(r, corpusB62, 43))},
		{"doppler-audit-token", p("dp", ".audit.", corpusChars(r, corpusB62, 43))},
	}
}
