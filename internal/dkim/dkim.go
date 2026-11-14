// SPDX-License-Identifier: BUSL-1.1

// Package dkim verifies DKIM signatures (RFC 6376) on a received message:
// rsa-sha256 and ed25519-sha256 (RFC 8463), simple and relaxed
// canonicalization. It exists for ACME's email-reply-00 (RFC 8823 §3.2 item
// 9), which needs to know that the reply's From domain signed it. Keys come
// from DNS TXT records at <selector>._domainkey.<domain>, or from keys an
// operator pins per domain for a network without that DNS. Signature math
// runs in internal/crypto (AN-3). A signature with l= (a partial body) or
// rsa-sha1 is refused rather than half-trusted.
package dkim

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// MaxMessageBytes bounds a message this package verifies.
const MaxMessageBytes = 1 << 20

// maxSignatures bounds the DKIM-Signature fields one message may make us check.
const maxSignatures = 5

var (
	// ErrNoValidSignature: no DKIM signature on the message verifies for the
	// required domain.
	ErrNoValidSignature = errors.New("dkim: no valid signature for the domain")
	// ErrMalformed: the message or a signature does not parse.
	ErrMalformed = errors.New("dkim: malformed message or signature")
)

// KeyLookup returns the TXT record strings at name (selector._domainkey.domain).
type KeyLookup func(ctx context.Context, name string) ([]string, error)

// Verifier checks DKIM signatures with keys from DNS, or pinned keys.
type Verifier struct {
	// Lookup reads DNS TXT records; nil uses only Pinned.
	Lookup KeyLookup
	// Pinned maps "selector._domainkey.domain" to the key record ("v=DKIM1;
	// k=ed25519; p=..."), for networks whose mail domains are not in DNS.
	Pinned map[string]string
	// Now is the clock for x= (expiry); nil is time.Now.
	Now func() time.Time
}

// field is one header field: its name as written and its raw bytes (name,
// colon, value with folding, final CRLF).
type field struct {
	name string
	raw  []byte
}

// VerifyDomain reports nil when one DKIM signature on msg, signed by domain
// (d= equal to it, case-insensitively), verifies. msg uses CRLF line ends.
func (v Verifier) VerifyDomain(ctx context.Context, msg []byte, domain string) error {
	if len(msg) > MaxMessageBytes {
		return fmt.Errorf("%w: message larger than %d bytes", ErrMalformed, MaxMessageBytes)
	}
	fields, body, err := splitMessage(msg)
	if err != nil {
		return err
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	checked := 0
	last := ErrNoValidSignature
	for _, f := range fields {
		if !strings.EqualFold(f.name, "DKIM-Signature") {
			continue
		}
		if checked++; checked > maxSignatures {
			break
		}
		sig, err := parseSignature(f.raw)
		if err != nil {
			last = err
			continue
		}
		if strings.ToLower(sig.domain) != domain {
			continue
		}
		if err := v.verify(ctx, sig, fields, f, body); err != nil {
			last = err
			continue
		}
		return nil
	}
	if errors.Is(last, ErrNoValidSignature) {
		return ErrNoValidSignature
	}
	return fmt.Errorf("%w: %v", ErrNoValidSignature, last)
}

type signature struct {
	algorithm       string // rsa-sha256 | ed25519-sha256
	headerCanon     string // simple | relaxed
	bodyCanon       string
	domain          string
	selector        string
	headers         []string
	bodyHash        []byte
	sig             []byte
	expires         int64 // 0 when absent
	signatureFields []byte
}

// parseSignature reads a DKIM-Signature field (RFC 6376 §3.5).
func parseSignature(raw []byte) (signature, error) {
	_, value, ok := bytes.Cut(raw, []byte(":"))
	if !ok {
		return signature{}, ErrMalformed
	}
	tags, err := parseTagList(string(value))
	if err != nil {
		return signature{}, err
	}
	sig := signature{headerCanon: "simple", bodyCanon: "simple"}
	if tags["v"] != "1" {
		return signature{}, fmt.Errorf("%w: v=%q", ErrMalformed, tags["v"])
	}
	switch tags["a"] {
	case "rsa-sha256", "ed25519-sha256":
		sig.algorithm = tags["a"]
	default:
		return signature{}, fmt.Errorf("%w: algorithm %q is not accepted", ErrMalformed, tags["a"])
	}
	if _, present := tags["l"]; present {
		return signature{}, fmt.Errorf("%w: a signature over part of the body (l=) is not accepted", ErrMalformed)
	}
	if c := tags["c"]; c != "" {
		h, b, _ := strings.Cut(c, "/")
		if b == "" {
			b = "simple"
		}
		if (h != "simple" && h != "relaxed") || (b != "simple" && b != "relaxed") {
			return signature{}, fmt.Errorf("%w: canonicalization %q", ErrMalformed, c)
		}
		sig.headerCanon, sig.bodyCanon = h, b
	}
	if q := tags["q"]; q != "" && q != "dns/txt" {
		return signature{}, fmt.Errorf("%w: query method %q", ErrMalformed, q)
	}
	sig.domain, sig.selector = tags["d"], tags["s"]
	if sig.domain == "" || sig.selector == "" || strings.ContainsAny(sig.domain+sig.selector, " \t/\\") {
		return signature{}, fmt.Errorf("%w: missing d= or s=", ErrMalformed)
	}
	for _, h := range strings.Split(tags["h"], ":") {
		if h = strings.TrimSpace(h); h != "" {
			sig.headers = append(sig.headers, h)
		}
	}
	signsFrom := false
	for _, h := range sig.headers {
		signsFrom = signsFrom || strings.EqualFold(h, "From")
	}
	if !signsFrom {
		return signature{}, fmt.Errorf("%w: h= does not cover From", ErrMalformed)
	}
	if sig.bodyHash, err = decodeBase64(tags["bh"]); err != nil || len(sig.bodyHash) == 0 {
		return signature{}, fmt.Errorf("%w: bh=", ErrMalformed)
	}
	if sig.sig, err = decodeBase64(tags["b"]); err != nil || len(sig.sig) == 0 {
		return signature{}, fmt.Errorf("%w: b=", ErrMalformed)
	}
	if x := tags["x"]; x != "" {
		if _, err := fmt.Sscanf(x, "%d", &sig.expires); err != nil {
			return signature{}, fmt.Errorf("%w: x=", ErrMalformed)
		}
	}
	sig.signatureFields = raw
	return sig, nil
}

// parseTagList reads an RFC 6376 §3.2 tag list. A duplicated tag is an error.
func parseTagList(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("%w: tag %q", ErrMalformed, part)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%w: duplicated tag %q", ErrMalformed, name)
		}
		out[name] = strings.TrimSpace(value)
	}
	return out, nil
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
}

// verify checks one signature: the key, the body hash and the header hash.
func (v Verifier) verify(ctx context.Context, sig signature, all []field, self field, body []byte) error {
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	if sig.expires > 0 && now().Unix() > sig.expires {
		return errors.New("dkim: the signature expired")
	}
	keyType, keyData, err := v.key(ctx, sig)
	if err != nil {
		return err
	}
	bodyHash, err := crypto.Digest(crypto.SHA256, canonicalBody(body, sig.bodyCanon))
	if err != nil {
		return err
	}
	if !crypto.ConstantTimeEqual(bodyHash, sig.bodyHash) {
		return errors.New("dkim: the body hash does not match")
	}
	data := canonicalHeaders(all, sig, self)
	headerHash, err := crypto.Digest(crypto.SHA256, data)
	if err != nil {
		return err
	}
	if (keyType == "ed25519") != (sig.algorithm == "ed25519-sha256") {
		return errors.New("dkim: the key type does not match the signature algorithm")
	}
	return crypto.VerifyDKIM(keyType, keyData, headerHash, sig.sig)
}

// key reads the selector's key record (RFC 6376 §3.6.1).
func (v Verifier) key(ctx context.Context, sig signature) (string, []byte, error) {
	name := sig.selector + "._domainkey." + strings.ToLower(sig.domain)
	var records []string
	if pinned, ok := v.Pinned[name]; ok {
		records = []string{pinned}
	} else if v.Lookup != nil {
		var err error
		if records, err = v.Lookup(ctx, name); err != nil {
			return "", nil, fmt.Errorf("dkim: key lookup %s: %w", name, err)
		}
	}
	for _, record := range records {
		tags, err := parseTagList(record)
		if err != nil {
			continue
		}
		if ver := tags["v"]; ver != "" && ver != "DKIM1" {
			continue
		}
		keyType := tags["k"]
		if keyType == "" {
			keyType = "rsa"
		}
		if keyType != "rsa" && keyType != "ed25519" {
			continue
		}
		key, err := decodeBase64(tags["p"])
		if err != nil || len(key) == 0 {
			return "", nil, fmt.Errorf("dkim: the key at %s is revoked or unreadable", name)
		}
		return keyType, key, nil
	}
	return "", nil, fmt.Errorf("dkim: no usable key at %s", name)
}

// splitMessage splits msg into header fields and body (RFC 5322 §2.1).
func splitMessage(msg []byte) ([]field, []byte, error) {
	end := bytes.Index(msg, []byte("\r\n\r\n"))
	if end < 0 {
		return nil, nil, fmt.Errorf("%w: no header/body boundary", ErrMalformed)
	}
	head, body := msg[:end+2], msg[end+4:]
	var fields []field
	for len(head) > 0 {
		lineEnd := bytes.Index(head, []byte("\r\n"))
		if lineEnd < 0 {
			return nil, nil, ErrMalformed
		}
		line := head[:lineEnd+2]
		head = head[lineEnd+2:]
		if line[0] == ' ' || line[0] == '\t' {
			if len(fields) == 0 {
				return nil, nil, fmt.Errorf("%w: continuation before any field", ErrMalformed)
			}
			fields[len(fields)-1].raw = append(fields[len(fields)-1].raw, line...)
			continue
		}
		name, _, ok := bytes.Cut(line, []byte(":"))
		if !ok || len(bytes.TrimSpace(name)) == 0 || bytes.ContainsAny(name, " \t") {
			return nil, nil, fmt.Errorf("%w: header line without a field name", ErrMalformed)
		}
		fields = append(fields, field{name: string(name), raw: append([]byte(nil), line...)})
	}
	return fields, body, nil
}

// canonicalHeaders builds the signed header data (RFC 6376 §3.7): each h=
// name selects the last not-yet-used field of that name, bottom up; a name
// with no field left signs nothing; then the DKIM-Signature field itself with
// its b= value emptied and no final CRLF.
func canonicalHeaders(all []field, sig signature, self field) []byte {
	used := map[int]bool{}
	var out []byte
	for _, name := range sig.headers {
		for i := len(all) - 1; i >= 0; i-- {
			if used[i] || !strings.EqualFold(all[i].name, name) || bytes.Equal(all[i].raw, self.raw) {
				continue
			}
			used[i] = true
			out = append(out, canonicalHeader(all[i].raw, sig.headerCanon)...)
			break
		}
	}
	signatureField := canonicalHeader(emptyB(self.raw), sig.headerCanon)
	return append(out, bytes.TrimSuffix(signatureField, []byte("\r\n"))...)
}

// emptyB removes the value of the b= tag, keeping everything else as written.
func emptyB(raw []byte) []byte {
	s := string(raw)
	colon := strings.IndexByte(s, ':')
	rest := s[colon+1:]
	out := s[:colon+1]
	for i := 0; i < len(rest); {
		semi := strings.IndexByte(rest[i:], ';')
		end := len(rest)
		if semi >= 0 {
			end = i + semi
		}
		part := rest[i:end]
		trimmed := strings.TrimLeft(part, " \t\r\n")
		if strings.HasPrefix(trimmed, "b") {
			name, _, ok := strings.Cut(trimmed, "=")
			if ok && strings.TrimSpace(name) == "b" {
				part = part[:len(part)-len(trimmed)] + trimmed[:strings.IndexByte(trimmed, '=')+1]
				if strings.HasSuffix(rest[i:end], "\r\n") {
					part += "\r\n"
				}
			}
		}
		out += part
		if semi < 0 {
			break
		}
		out += ";"
		i = end + 1
	}
	return []byte(out)
}

// canonicalHeader canonicalizes one field (RFC 6376 §3.4.1, §3.4.2).
func canonicalHeader(raw []byte, mode string) []byte {
	if mode == "simple" {
		return raw
	}
	name, value, _ := bytes.Cut(raw, []byte(":"))
	v := strings.ReplaceAll(string(value), "\r\n", "")
	v = strings.Join(strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == '\t' }), " ")
	return []byte(strings.ToLower(strings.TrimSpace(string(name))) + ":" + strings.TrimSpace(v) + "\r\n")
}

// canonicalBody canonicalizes the body (RFC 6376 §3.4.3, §3.4.4).
func canonicalBody(body []byte, mode string) []byte {
	lines := strings.Split(string(body), "\r\n")
	if mode == "relaxed" {
		for i, line := range lines {
			lines[i] = strings.TrimRight(collapseWSP(line), " ")
		}
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		if mode == "relaxed" {
			return nil
		}
		return []byte("\r\n")
	}
	return []byte(strings.Join(lines, "\r\n") + "\r\n")
}

// collapseWSP reduces every run of spaces and tabs to one space, keeping a
// leading run as one space (RFC 6376 §3.4.4).
func collapseWSP(line string) string {
	var b strings.Builder
	inRun := false
	for i := 0; i < len(line); i++ {
		if c := line[i]; c == ' ' || c == '\t' {
			if !inRun {
				b.WriteByte(' ')
			}
			inRun = true
			continue
		}
		inRun = false
		b.WriteByte(line[i])
	}
	return b.String()
}

// Sign adds a DKIM-Signature (rsa-sha256, relaxed/relaxed) to msg for domain
// and selector, covering headers (which must include From), signed by an RSA
// key in the crypto boundary. trstctl signs its own ACME challenge mail with
// it when a signing key is configured (P15-L2); a lab or test mail system
// signs with it too.
func Sign(msg []byte, domain, selector string, headers []string, signer crypto.DigestSigner, now time.Time) ([]byte, error) {
	switch signer.Algorithm() {
	case crypto.RSA2048, crypto.RSA3072, crypto.RSA4096:
	default:
		return nil, fmt.Errorf("dkim: signing needs an RSA key, not %s", signer.Algorithm())
	}
	fields, body, err := splitMessage(msg)
	if err != nil {
		return nil, err
	}
	bodyHash, err := crypto.Digest(crypto.SHA256, canonicalBody(body, "relaxed"))
	if err != nil {
		return nil, err
	}
	value := fmt.Sprintf(" v=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; t=%d; h=%s; bh=%s; b=",
		domain, selector, now.Unix(), strings.Join(headers, ":"), base64.StdEncoding.EncodeToString(bodyHash))
	self := field{name: "DKIM-Signature", raw: []byte("DKIM-Signature:" + value + "\r\n")}
	sig := signature{headerCanon: "relaxed", headers: headers}
	headerHash, err := crypto.Digest(crypto.SHA256, canonicalHeaders(fields, sig, self))
	if err != nil {
		return nil, err
	}
	b, err := signer.SignDigest(headerHash, crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15})
	if err != nil {
		return nil, err
	}
	signed := append([]byte("DKIM-Signature:"+value+base64.StdEncoding.EncodeToString(b)+"\r\n"), msg...)
	return signed, nil
}
