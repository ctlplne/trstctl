// SPDX-License-Identifier: BUSL-1.1

// Package keyposture rates one certificate for the inventory (eMudhra, Part
// 4): whether its key is weak whatever its algorithm and size
// (internal/crypto/weakkey), and whether it is, or was issued under, a CA or
// key on the distrust list (internal/crypto/trust). The verdict is computed
// where the certificate's bytes are at hand — an agent, a relay, a cloud or CT
// reader, the issuing path — and travels as plain metadata on findings, so no
// reader parses certificates again and nothing outside internal/crypto touches
// crypto/* (AN-3).
package keyposture

import (
	"bytes"
	"encoding/pem"
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/crypto/trust"
	"trstctl.com/trstctl/internal/crypto/weakkey"
)

// Verdict is the rating of one certificate.
type Verdict struct {
	WeakReasons     []string `json:"weak_reasons,omitempty"`
	DistrustEntry   string   `json:"distrust_entry,omitempty"`   // the distrust list entry's name
	DistrustHow     string   `json:"distrust_how,omitempty"`     // itself, chain, issuer_key_id or issuer_name
	DistrustReason  string   `json:"distrust_reason,omitempty"`  // the entry's reason
	DistrustSubject string   `json:"distrust_subject,omitempty"` // the distrusted certificate, or the issuer that names it
}

// DistrustedByName is how a certificate is matched when only its recorded
// issuer name is known (an imported inventory row): weaker than a key match,
// and said so.
const DistrustedByName = "issuer_name"

// Weak reports a weak key.
func (v Verdict) Weak() bool { return len(v.WeakReasons) > 0 }

// Distrusted reports a distrusted certificate or issuer.
func (v Verdict) Distrusted() bool { return v.DistrustEntry != "" }

// Empty reports a sound certificate.
func (v Verdict) Empty() bool { return !v.Weak() && !v.Distrusted() }

// Risk floors: a distrusted certificate or issuer outranks a weak key, which
// outranks anything an expiry date alone can say.
const (
	RiskDistrusted = 95
	RiskWeak       = 85
)

// RiskFloor is the lowest risk score a finding with this verdict may carry.
func (v Verdict) RiskFloor() int {
	switch {
	case v.Distrusted():
		return RiskDistrusted
	case v.Weak():
		return RiskWeak
	default:
		return 0
	}
}

// Metadata keys every producer and reader shares.
const (
	MetaKeyStrength     = "key_strength" // "weak"
	MetaWeakKeyReason   = "key_weak_reason"
	MetaDistrustEntry   = "distrust_entry"
	MetaDistrustHow     = "distrust_how"
	MetaDistrustReason  = "distrust_reason"
	MetaDistrustSubject = "distrust_subject"
)

const reasonSeparator = "; "

// StringMetadata renders the verdict as string metadata (agent inventory).
func (v Verdict) StringMetadata() map[string]string {
	out := map[string]string{}
	if v.Weak() {
		out[MetaKeyStrength] = "weak"
		out[MetaWeakKeyReason] = strings.Join(v.WeakReasons, reasonSeparator)
	}
	if v.Distrusted() {
		out[MetaDistrustEntry] = v.DistrustEntry
		out[MetaDistrustHow] = v.DistrustHow
		out[MetaDistrustReason] = v.DistrustReason
		out[MetaDistrustSubject] = v.DistrustSubject
	}
	return out
}

// AddTo writes the verdict into finding metadata.
func (v Verdict) AddTo(meta map[string]any) {
	for k, val := range v.StringMetadata() {
		meta[k] = val
	}
}

// FromStringMetadata reads a verdict back from string metadata.
func FromStringMetadata(meta map[string]string) Verdict {
	v := Verdict{
		DistrustEntry:   meta[MetaDistrustEntry],
		DistrustHow:     meta[MetaDistrustHow],
		DistrustReason:  meta[MetaDistrustReason],
		DistrustSubject: meta[MetaDistrustSubject],
	}
	if meta[MetaKeyStrength] == "weak" {
		for _, r := range strings.Split(meta[MetaWeakKeyReason], reasonSeparator) {
			if r = strings.TrimSpace(r); r != "" {
				v.WeakReasons = append(v.WeakReasons, r)
			}
		}
		if len(v.WeakReasons) == 0 {
			v.WeakReasons = []string{"rated weak by the reporter"}
		}
	}
	return v
}

// FromMetadata reads a verdict back from finding metadata.
func FromMetadata(meta map[string]any) Verdict {
	strs := map[string]string{}
	for _, k := range []string{MetaKeyStrength, MetaWeakKeyReason, MetaDistrustEntry, MetaDistrustHow, MetaDistrustReason, MetaDistrustSubject} {
		if s, ok := meta[k].(string); ok {
			strs[k] = s
		}
	}
	return FromStringMetadata(strs)
}

// RateCertificate rates a DER certificate and the DER chain recorded with it
// (may be empty) against the process-wide weak-key checker and distrust list.
func RateCertificate(certDER []byte, chainDER [][]byte) (Verdict, error) {
	findings, err := weakkey.Default().RateCertificate(certDER)
	if err != nil {
		return Verdict{}, err
	}
	var v Verdict
	for _, f := range findings {
		v.WeakReasons = append(v.WeakReasons, f.Reason)
	}
	x, ok, err := trust.Active().ExposureOf(certDER, chainDER)
	if err != nil {
		return Verdict{}, err
	}
	if ok {
		v.DistrustEntry, v.DistrustHow, v.DistrustReason, v.DistrustSubject = x.Entry.Name, x.How, x.Entry.Reason, x.Subject
	}
	return v, nil
}

// RateCertificateBytes rates the first certificate of a PEM bundle with the
// rest of the bundle as its chain, or a single DER certificate.
func RateCertificateBytes(raw []byte) (Verdict, error) {
	trimmed := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		return RateCertificate(raw, nil)
	}
	var ders [][]byte
	rest := trimmed
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type == "CERTIFICATE" {
			ders = append(ders, block.Bytes)
		}
	}
	if len(ders) == 0 {
		return Verdict{}, errors.New("keyposture: no certificate in the PEM input")
	}
	return RateCertificate(ders[0], ders[1:])
}

// RateRecorded rates an inventory row whose certificate bytes were never kept:
// its recorded key-algorithm name, and its issuer's common name against the
// distrust list's entry names (marked issuer_name, a weaker match than a key).
func RateRecorded(issuerDN, keyAlgorithm string) Verdict {
	var v Verdict
	for _, f := range weakkey.RateKeyAlgorithmName(keyAlgorithm) {
		v.WeakReasons = append(v.WeakReasons, f.Reason)
	}
	if cn := CommonName(issuerDN); cn != "" {
		if e, ok := trust.Active().MatchName(cn); ok {
			v.DistrustEntry, v.DistrustHow, v.DistrustReason, v.DistrustSubject = e.Name, DistrustedByName, e.Reason, issuerDN
		}
	}
	return v
}

// CommonName returns the CN of an RFC 4514 distinguished name as Go renders
// it ("CN=EM OV TLS CA - G3C,O=eMudhra Inc,C=US"), honouring backslash escapes.
func CommonName(dn string) string {
	var attrs []string
	var cur strings.Builder
	escaped := false
	for _, r := range dn {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == ',' || r == '+':
			attrs = append(attrs, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	attrs = append(attrs, cur.String())
	for _, a := range attrs {
		a = strings.TrimSpace(a)
		if len(a) > 3 && strings.EqualFold(a[:3], "CN=") {
			return strings.TrimSpace(a[3:])
		}
	}
	return ""
}
