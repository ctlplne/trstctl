// SPDX-License-Identifier: BUSL-1.1

package cryptorisk

import (
	"strings"
	"time"
)

// IR8547Source names where the deadlines come from. NIST IR 8547 was still an
// initial public draft when they were encoded (read 2026-10-27), and the report
// says so wherever it cites them.
const IR8547Source = "NIST IR 8547 initial public draft (November 2024), Tables 2 and 4"

// The years IR 8547's tables state: quantum-vulnerable public-key algorithms at
// 112 bits of security strength are deprecated after 2030, and every
// quantum-vulnerable one is disallowed after 2035.
const (
	ir8547DeprecatedAfter = 2030
	ir8547DisallowedAfter = 2035
)

// Deadline statuses, relative to the report's time.
const (
	// DeadlineReplaceNow: a weak or distrusted key, a key below the 112-bit
	// strength IR 8547's tables start from, or a passed disallow date.
	DeadlineReplaceNow = "replace_now"
	// DeadlineDeprecated: past the deprecation year, before the disallow year.
	DeadlineDeprecated = "deprecated"
	// DeadlineUpcoming: a quantum-vulnerable key whose dates are still ahead.
	DeadlineUpcoming = "upcoming"
	// DeadlineNone: no IR 8547 deadline applies (a post-quantum or symmetric
	// algorithm), or the algorithm is not recognized (Assumed says which).
	DeadlineNone = "none"
)

// Deadline is the transition date that applies to one key.
type Deadline struct {
	Source          string `json:"source"`
	Rule            string `json:"rule"`
	SecurityBits    int    `json:"security_bits,omitempty"`
	DeprecatedAfter int    `json:"deprecated_after,omitempty"`
	DisallowedAfter int    `json:"disallowed_after,omitempty"`
	Status          string `json:"status"`
	// Assumed names what the rule had to assume, such as an unknown key size.
	Assumed string `json:"assumed,omitempty"`
}

// keyFamily maps a recorded algorithm name to the IR 8547 table row family.
func keyFamily(algorithm string) string {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case a == "":
		return "unknown"
	case strings.HasPrefix(a, "ML-") || strings.HasPrefix(a, "SLH-") || strings.HasPrefix(a, "LMS") ||
		strings.HasPrefix(a, "HSS") || strings.HasPrefix(a, "XMSS") || strings.Contains(a, "MLKEM") || strings.Contains(a, "MLDSA"):
		return "post_quantum"
	case strings.HasPrefix(a, "AES") || strings.HasPrefix(a, "CHACHA") || strings.HasPrefix(a, "SHA") || strings.HasPrefix(a, "HMAC"):
		return "symmetric"
	case strings.HasPrefix(a, "RSA"):
		return "rsa"
	case strings.HasPrefix(a, "ED25519") || strings.HasPrefix(a, "ED448") || strings.HasPrefix(a, "EDDSA"):
		return "eddsa"
	case strings.HasPrefix(a, "X25519") || strings.HasPrefix(a, "X448"):
		return "ecc"
	case strings.HasPrefix(a, "ECDSA") || strings.HasPrefix(a, "ECDH") || strings.HasPrefix(a, "EC") || strings.Contains(a, "P-") || strings.HasPrefix(a, "SECP"):
		return "ecc"
	case strings.HasPrefix(a, "DSA"):
		return "dsa"
	case strings.HasPrefix(a, "DH") || strings.HasPrefix(a, "FFDH") || strings.HasPrefix(a, "DIFFIE"):
		return "ff_dh"
	default:
		return "unknown"
	}
}

// securityBits is the security strength of a key of this family and size, or
// 0 when the size is unknown, and -1 below 112 bits.
func securityBits(family string, keyBits int, algorithm string) int {
	a := strings.ToUpper(algorithm)
	switch family {
	case "rsa", "ff_dh":
		switch {
		case keyBits <= 0:
			return 0
		case keyBits < 2048:
			return -1
		case keyBits < 3072:
			return 112
		case keyBits < 7680:
			return 128
		case keyBits < 15360:
			return 192
		default:
			return 256
		}
	case "ecc":
		if strings.HasPrefix(a, "X25519") {
			return 128
		}
		if strings.HasPrefix(a, "X448") {
			return 224
		}
		switch {
		case keyBits <= 0:
			return 0
		case keyBits < 224:
			return -1
		case keyBits < 256:
			return 112
		case keyBits < 384:
			return 128
		case keyBits < 521:
			return 192
		default:
			return 256
		}
	case "eddsa":
		if strings.HasPrefix(a, "ED448") {
			return 224
		}
		return 128
	}
	return 0
}

// DeadlineFor is the IR 8547 deadline for a key, as of now. A weak key (one a
// reader rated weak whatever its size) is replaced now whatever the table says.
func DeadlineFor(algorithm string, keyBits int, weak bool, now time.Time) Deadline {
	family := keyFamily(algorithm)
	d := Deadline{Source: IR8547Source}
	switch family {
	case "post_quantum", "symmetric":
		d.Rule, d.Status = "no IR 8547 transition: not a quantum-vulnerable public-key algorithm", DeadlineNone
		if weak {
			d.Rule, d.Status = "weak key: replace now", DeadlineReplaceNow
		}
		return d
	case "unknown":
		d.Rule, d.Status = "no IR 8547 transition applied", DeadlineNone
		d.Assumed = "the recorded algorithm " + quoted(algorithm) + " is not recognized"
		if weak {
			d.Rule, d.Status = "weak key: replace now", DeadlineReplaceNow
		}
		return d
	case "dsa":
		d.Rule, d.Status = "DSA is not among the quantum-vulnerable algorithms IR 8547 lists as approved: replace now", DeadlineReplaceNow
		return d
	}
	d.SecurityBits = securityBits(family, keyBits, algorithm)
	switch {
	case d.SecurityBits < 0:
		d.SecurityBits = 0
		d.Rule, d.Status = "below the 112-bit strength IR 8547's tables start from: replace now", DeadlineReplaceNow
		return d
	case d.SecurityBits == 0:
		d.Assumed = "key size unknown: the 112-bit rule is applied"
		d.SecurityBits = 112
	}
	if d.SecurityBits == 112 {
		d.Rule, d.DeprecatedAfter, d.DisallowedAfter = "deprecated after 2030, disallowed after 2035", ir8547DeprecatedAfter, ir8547DisallowedAfter
	} else {
		d.Rule, d.DisallowedAfter = "disallowed after 2035", ir8547DisallowedAfter
	}
	year := now.UTC().Year()
	switch {
	case weak:
		d.Rule, d.Status = "weak key: replace now ("+d.Rule+" in any case)", DeadlineReplaceNow
	case year > d.DisallowedAfter:
		d.Status = DeadlineReplaceNow
	case d.DeprecatedAfter != 0 && year > d.DeprecatedAfter:
		d.Status = DeadlineDeprecated
	default:
		d.Status = DeadlineUpcoming
	}
	return d
}

func quoted(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none)"
	}
	return `"` + s + `"`
}
