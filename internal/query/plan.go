// SPDX-License-Identifier: BUSL-1.1

package query

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// The question planner (A152) turns an operator's question into a typed Spec the
// engine answers exactly, or reports that it cannot. It is a small compositional
// grammar, not a language model: every word of the question must be understood,
// values taken from the question are only ever bound as typed filter values, and
// the plan carries an interpretation sentence so the operator can see exactly
// what was answered. Anything outside the grammar is unplanned, and the caller
// keeps answering it as scoped evidence marked insufficient.
//
// Certificate questions compose any of these, in any order:
//
//	which | what | show [me] [all] | list [all] | find | how many   (count)
//	[revoked | active | superseded | expired | unowned | <algorithm>] certificates
//	expiring within N days|weeks · expired · revoked · active · superseded
//	issued by <name> · using <algorithm> [keys] · for <name>
//	owned by <owner> · without an owner
//
// plus "who owns <serial|fingerprint|name>?", crypto-asset questions
// ("where is RSA used?", "which crypto assets are quantum-vulnerable?",
// "which crypto assets use RSA keys smaller than 2048 bits?") and graph
// inventories ("which workloads exist?"). A value of more than one word goes
// in double quotes.

// PlanKind names the answer shape of a planned question.
type PlanKind string

const (
	PlanCertificates      PlanKind = "certificates"
	PlanCertificateCount  PlanKind = "certificate-count"
	PlanCertificateOwners PlanKind = "certificate-owners"
	PlanCryptoAssets      PlanKind = "crypto-assets"
	PlanCryptoAssetCount  PlanKind = "crypto-asset-count"
	PlanGraphNodes        PlanKind = "graph-nodes"
)

// Plan is one interpreted question: the typed Spec to run and the interpretation
// in words. Spec.Select lists the surfaces the question needs the caller to have
// selected; Spec.Focus lists the surfaces whose rows answer it.
type Plan struct {
	Kind           PlanKind
	Spec           Spec
	Interpretation string
	// Clauses names the clause kinds the question used (never their values), for
	// the audit record.
	Clauses []string
	// ExpiryDays is the expiry window a certificate question asked about, if any.
	ExpiryDays int
}

// MaxPlannedQuestion bounds the text the planner reads.
const MaxPlannedQuestion = 500

// PlanQuestion interprets question as of now. ok is false when any part of the
// question falls outside the grammar.
func PlanQuestion(question string, now time.Time) (Plan, bool) {
	if len(question) > MaxPlannedQuestion {
		return Plan{}, false
	}
	toks, ok := lex(question)
	if !ok || len(toks) == 0 {
		return Plan{}, false
	}
	p := &parser{toks: toks, now: now.UTC()}
	for _, try := range []func() (Plan, bool){p.certificateOwners, p.cryptoAssets, p.graphNodes, p.certificates} {
		p.pos = 0
		if plan, ok := try(); ok {
			return plan, true
		}
	}
	return Plan{}, false
}

// token is one lexed word, number, quoted value or comma.
type token struct {
	word   string // lower-cased word, or "" for a quoted value
	raw    string // the text as written (the value of a quoted token)
	quoted bool
}

// lex splits the question into tokens. Trailing ?, . and ! end the question;
// any other punctuation outside a quoted value is outside the grammar.
func lex(question string) ([]token, bool) {
	q := strings.TrimRightFunc(strings.TrimSpace(question), func(r rune) bool { return r == '?' || r == '.' || r == '!' || unicode.IsSpace(r) })
	var out []token
	runes := []rune(q)
	for i := 0; i < len(runes); {
		r := runes[i]
		switch {
		case unicode.IsSpace(r):
			i++
		case r == ',':
			out = append(out, token{word: ","})
			i++
		case r == '"' || r == '“' || r == '”':
			j := i + 1
			for j < len(runes) && runes[j] != '"' && runes[j] != '”' && runes[j] != '“' {
				j++
			}
			if j >= len(runes) {
				return nil, false
			}
			value := strings.TrimSpace(string(runes[i+1 : j]))
			if value == "" || len([]rune(value)) > 200 {
				return nil, false
			}
			out = append(out, token{raw: value, quoted: true})
			i = j + 1
		case valueRune(r):
			j := i
			for j < len(runes) && valueRune(runes[j]) {
				j++
			}
			raw := string(runes[i:j])
			out = append(out, token{word: strings.ToLower(raw), raw: raw})
			i = j
		default:
			return nil, false
		}
	}
	return out, true
}

func valueRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(".-_:@*/=+'", r)
}

type parser struct {
	toks []token
	pos  int
	now  time.Time
}

func (p *parser) done() bool { return p.pos >= len(p.toks) }

func (p *parser) peek(offset int) string {
	if p.pos+offset >= len(p.toks) || p.toks[p.pos+offset].quoted {
		return ""
	}
	return p.toks[p.pos+offset].word
}

// accept consumes the words in order when they all match.
func (p *parser) accept(words ...string) bool {
	for i, w := range words {
		if p.peek(i) != w {
			return false
		}
	}
	p.pos += len(words)
	return true
}

// acceptAny consumes one word from the set.
func (p *parser) acceptAny(words ...string) (string, bool) {
	w := p.peek(0)
	for _, candidate := range words {
		if w != "" && w == candidate {
			p.pos++
			return w, true
		}
	}
	return "", false
}

// value consumes one value: a quoted token, or a single bare word that is not
// part of the grammar.
func (p *parser) value() (string, bool) {
	if p.done() {
		return "", false
	}
	t := p.toks[p.pos]
	if t.quoted {
		p.pos++
		return t.raw, true
	}
	if t.word == "," || reserved[t.word] {
		return "", false
	}
	p.pos++
	return t.raw, true
}

// number consumes a whole number in [lo, hi].
func (p *parser) number(lo, hi int) (int, bool) {
	w := p.peek(0)
	n, err := strconv.Atoi(w)
	if err != nil || n < lo || n > hi {
		return 0, false
	}
	p.pos++
	return n, true
}

// skipFillers consumes words that join clauses without meaning anything.
func (p *parser) skipFillers() {
	for {
		if _, ok := p.acceptAny(",", "and", "that", "which", "are", "is", "were", "was", "whose", "currently", "still"); !ok {
			return
		}
	}
}

var reserved = map[string]bool{
	"and": true, "that": true, "which": true, "are": true, "is": true, "were": true, "was": true,
	"expire": true, "expires": true, "expiring": true, "expired": true, "within": true,
	"issued": true, "signed": true, "using": true, "use": true, "uses": true, "with": true,
	"for": true, "covering": true, "owned": true, "belonging": true, "without": true,
	"revoked": true, "active": true, "superseded": true, "unowned": true, "owner": true,
	"certificates": true, "certificate": true, "certs": true, "cert": true, "by": true,
}

// algorithms maps question wording to the key algorithm family recorded in the
// inventory and the CBOM.
var algorithms = map[string]string{
	"rsa": "RSA", "ecdsa": "ECDSA", "ec": "ECDSA", "ed25519": "Ed25519", "dsa": "DSA",
	"ml-dsa": "ML-DSA", "mldsa": "ML-DSA", "slh-dsa": "SLH-DSA", "ml-kem": "ML-KEM",
}

func (p *parser) algorithm() (string, bool) {
	alg, ok := algorithms[p.peek(0)]
	if ok {
		p.pos++
	}
	return alg, ok
}

// certificates parses a certificate list or count question.
func (p *parser) certificates() (Plan, bool) {
	count := false
	switch {
	case p.accept("how", "many"):
		count = true
	case p.accept("which"), p.accept("what"), p.accept("find"):
	case p.accept("show"), p.accept("list"):
		p.accept("me")
	}
	p.accept("all")
	p.accept("the")
	f := CertificateFilter{}
	c := &certClauses{}
	// Adjectives before the noun.
	for !p.nounAhead() {
		if !p.certAdjective(&f, c) {
			return Plan{}, false
		}
	}
	if _, ok := p.acceptAny("certificates", "certificate", "certs", "cert"); !ok {
		return Plan{}, false
	}
	for {
		p.skipFillers()
		if p.done() {
			break
		}
		if !p.certClause(&f, c) {
			return Plan{}, false
		}
	}
	return c.plan(f, count, p.now)
}

func (p *parser) nounAhead() bool {
	switch p.peek(0) {
	case "certificates", "certificate", "certs", "cert":
		return true
	}
	return p.done()
}

// certClauses collects what a certificate question said, so contradictions are
// refused and the interpretation can be written once.
type certClauses struct {
	status       string
	expired      bool
	windowDays   int
	issuer, name string
	owner        string
	unowned      bool
	algorithm    string
	kinds        []string
}

func (c *certClauses) setStatus(s string) bool {
	if c.status != "" && c.status != s {
		return false
	}
	c.status = s
	c.kinds = append(c.kinds, "status")
	return true
}

func (p *parser) certAdjective(f *CertificateFilter, c *certClauses) bool {
	switch {
	case p.accept("revoked"):
		return c.setStatus("revoked")
	case p.accept("active"):
		return c.setStatus("active")
	case p.accept("superseded"):
		return c.setStatus("superseded")
	case p.accept("expired"):
		c.expired = true
		c.kinds = append(c.kinds, "expired")
		return true
	case p.accept("unowned"):
		c.unowned = true
		c.kinds = append(c.kinds, "unowned")
		return true
	}
	if alg, ok := p.algorithm(); ok {
		return c.setAlgorithm(alg)
	}
	return false
}

func (c *certClauses) setAlgorithm(alg string) bool {
	if c.algorithm != "" && c.algorithm != alg {
		return false
	}
	c.algorithm = alg
	c.kinds = append(c.kinds, "key_algorithm")
	return true
}

func (p *parser) certClause(f *CertificateFilter, c *certClauses) bool {
	switch {
	case p.accept("expire"), p.accept("expires"), p.accept("expiring"):
		if c.windowDays != 0 {
			return false
		}
		if !p.accept("within") && !p.accept("in", "the", "next") && !p.accept("in", "next") {
			return false
		}
		n, ok := p.number(1, 365)
		if !ok {
			return false
		}
		switch unit, _ := p.acceptAny("day", "days", "week", "weeks"); unit {
		case "day", "days":
		case "week", "weeks":
			n *= 7
		default:
			return false
		}
		if n > 365 {
			return false
		}
		c.windowDays = n
		c.kinds = append(c.kinds, "expiry_window")
		return true
	case p.accept("have", "expired"), p.accept("has", "expired"), p.accept("already", "expired"), p.accept("expired"):
		c.expired = true
		c.kinds = append(c.kinds, "expired")
		return true
	case p.accept("revoked"), p.accept("active"), p.accept("superseded"):
		return c.setStatus(p.toks[p.pos-1].word)
	case p.accept("issued", "by"), p.accept("signed", "by"):
		v, ok := p.value()
		if !ok || c.issuer != "" {
			return false
		}
		c.issuer = v
		c.kinds = append(c.kinds, "issuer")
		return true
	case p.accept("without", "an", "owner"), p.accept("without", "owner"), p.accept("with", "no", "owner"),
		p.accept("have", "no", "owner"), p.accept("has", "no", "owner"), p.accept("no", "owner"), p.accept("unowned"):
		if c.unowned {
			return false
		}
		c.unowned = true
		c.kinds = append(c.kinds, "unowned")
		return true
	case p.accept("using"), p.accept("use"), p.accept("uses"), p.accept("with"):
		alg, ok := p.algorithm()
		if !ok {
			return false
		}
		p.acceptAny("key", "keys")
		return c.setAlgorithm(alg)
	case p.accept("for"), p.accept("covering"), p.accept("matching"):
		v, ok := p.value()
		if !ok || c.name != "" {
			return false
		}
		c.name = v
		c.kinds = append(c.kinds, "name")
		return true
	case p.accept("owned", "by"), p.accept("belonging", "to"):
		v, ok := p.value()
		if !ok || c.owner != "" {
			return false
		}
		c.owner = v
		c.kinds = append(c.kinds, "owner")
		return true
	}
	return false
}

// plan turns the collected clauses into a Spec and its interpretation.
func (c *certClauses) plan(f CertificateFilter, count bool, now time.Time) (Plan, bool) {
	if (c.owner != "" && c.unowned) || (c.expired && c.windowDays != 0) {
		return Plan{}, false
	}
	f.Status = c.status
	if (c.expired || c.windowDays != 0) && f.Status == "" {
		// Expiry questions are about certificates still in service, as on the
		// expiry views: a renewed or revoked certificate has no deadline left.
		f.Status = "active"
	}
	var words []string
	switch f.Status {
	case "":
		words = append(words, "certificates of any status")
	default:
		words = append(words, f.Status+" certificates")
	}
	if c.algorithm != "" {
		f.KeyAlgorithm = c.algorithm
		words = append(words, "with a "+c.algorithm+" key")
	}
	if c.issuer != "" {
		f.IssuerContains = c.issuer
		words = append(words, fmt.Sprintf("issued by an issuer containing %q", c.issuer))
	}
	if c.name != "" {
		f.NameContains = c.name
		words = append(words, fmt.Sprintf("for a subject or SAN containing %q", c.name))
	}
	if c.owner != "" {
		f.OwnerName = c.owner
		words = append(words, fmt.Sprintf("owned by the owner named %q", c.owner))
	}
	if c.unowned {
		f.Unowned = true
		words = append(words, "with no owner")
	}
	if c.expired {
		before := now
		f.ExpiresBefore = &before
		words = append(words, "whose validity ended before "+now.Format(time.RFC3339))
	}
	if c.windowDays != 0 {
		after, before := now, now.Add(time.Duration(c.windowDays)*24*time.Hour)
		f.ExpiresAfter, f.ExpiresBefore = &after, &before
		words = append(words, fmt.Sprintf("expiring within %d days (after %s and before %s)", c.windowDays, after.Format(time.RFC3339), before.Format(time.RFC3339)))
	}
	spec := Spec{Select: []Surface{SurfaceCertificates}, Focus: []Surface{SurfaceCertificates}, Certificates: &f, Count: count}
	if c.owner != "" {
		spec.Select = append(spec.Select, SurfaceOwners)
	}
	kind := PlanCertificates
	if count {
		kind = PlanCertificateCount
	}
	return Plan{Kind: kind, Spec: spec, Interpretation: strings.Join(words, ", "), Clauses: c.kinds, ExpiryDays: c.windowDays}, true
}

// certificateOwners parses "who owns X?" and "what is the owner of X?".
func (p *parser) certificateOwners() (Plan, bool) {
	if !p.accept("who", "owns") && !p.accept("who", "is", "the", "owner", "of") && !p.accept("what", "is", "the", "owner", "of") {
		return Plan{}, false
	}
	p.accept("the")
	p.acceptAny("certificate", "cert")
	v, ok := p.value()
	if !ok || !p.done() {
		return Plan{}, false
	}
	f := CertificateFilter{}
	interpretation := ""
	switch {
	case looksLikeHexID(v) && len(strings.ReplaceAll(v, ":", "")) == 64:
		f.Fingerprint = v
		interpretation = fmt.Sprintf("the owner of the certificate with fingerprint %q", v)
	case looksLikeHexID(v):
		f.Serial = v
		interpretation = fmt.Sprintf("the owner of the certificate with serial %q", v)
	default:
		f.NameContains = v
		interpretation = fmt.Sprintf("the owners of certificates for a subject or SAN containing %q", v)
	}
	return Plan{
		Kind:           PlanCertificateOwners,
		Spec:           Spec{Select: []Surface{SurfaceCertificates, SurfaceOwners}, Focus: []Surface{SurfaceCertificates}, Certificates: &f},
		Interpretation: interpretation,
		Clauses:        []string{"owner_of"},
	}, true
}

func looksLikeHexID(v string) bool {
	digits := 0
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			digits++
		case r == ':':
		default:
			return false
		}
	}
	return digits >= 8
}

// cryptoAssets parses crypto-asset questions over the CBOM.
func (p *parser) cryptoAssets() (Plan, bool) {
	f := CryptoAssetFilter{}
	var kinds, words []string
	count := false
	switch {
	case p.accept("where", "is"), p.accept("where", "are"):
		alg, ok := p.algorithm()
		if !ok {
			return Plan{}, false
		}
		p.acceptAny("key", "keys")
		if !p.accept("used") || !p.done() {
			return Plan{}, false
		}
		f.Algorithm = alg
		return Plan{
			Kind: PlanCryptoAssets, Spec: Spec{Select: []Surface{SurfaceCBOM}, Focus: []Surface{SurfaceCBOM}, CryptoAssets: &f},
			Interpretation: "crypto assets using " + alg, Clauses: []string{"algorithm"},
		}, true
	case p.accept("how", "many"):
		count = true
	case p.accept("which"), p.accept("what"), p.accept("list"), p.accept("show"):
	default:
		return Plan{}, false
	}
	p.accept("all")
	p.accept("the")
	p.acceptAny("crypto", "cryptographic")
	if !p.accept("assets") {
		return Plan{}, false
	}
	for {
		p.skipFillers()
		if p.done() {
			break
		}
		switch {
		case p.accept("quantum-vulnerable"), p.accept("quantum", "vulnerable"), p.accept("vulnerable", "to", "quantum"):
			f.QuantumVulnerable = true
			kinds, words = append(kinds, "quantum_vulnerable"), append(words, "quantum-vulnerable")
		case p.accept("out", "of", "policy"), p.accept("outside", "policy"):
			f.OutOfPolicy = true
			kinds, words = append(kinds, "out_of_policy"), append(words, "out of policy")
		case p.accept("use"), p.accept("uses"), p.accept("using"), p.accept("with"):
			alg, ok := p.algorithm()
			if !ok || f.Algorithm != "" {
				return Plan{}, false
			}
			f.Algorithm = alg
			p.acceptAny("key", "keys")
			kinds, words = append(kinds, "algorithm"), append(words, "using "+alg)
		case p.accept("smaller", "than"), p.accept("weaker", "than"), p.accept("under"), p.accept("below"), p.accept("shorter", "than"):
			n, ok := p.number(1, 65536)
			if !ok || f.KeyBitsBelow != 0 {
				return Plan{}, false
			}
			if _, ok := p.acceptAny("bits", "bit"); !ok {
				return Plan{}, false
			}
			f.KeyBitsBelow = n
			kinds, words = append(kinds, "key_bits"), append(words, fmt.Sprintf("with keys smaller than %d bits", n))
		default:
			return Plan{}, false
		}
	}
	if len(kinds) == 0 {
		words = append(words, "of any kind")
	}
	kind := PlanCryptoAssets
	if count {
		kind = PlanCryptoAssetCount
	}
	return Plan{
		Kind: kind, Spec: Spec{Select: []Surface{SurfaceCBOM}, Focus: []Surface{SurfaceCBOM}, CryptoAssets: &f, Count: count},
		Interpretation: "crypto assets " + strings.Join(words, ", "), Clauses: kinds,
	}, true
}

// graphKinds maps plural question wording to credential-graph node kinds.
var graphKinds = map[string]string{
	"workloads": "workload", "credentials": "credential", "resources": "resource",
	"issuers": "issuer", "attestations": "attestation",
}

// graphNodes parses "which workloads exist?" and "list all issuers".
func (p *parser) graphNodes() (Plan, bool) {
	list := p.accept("list") || p.accept("show")
	if !list && !p.accept("which") && !p.accept("what") {
		return Plan{}, false
	}
	p.accept("all")
	p.accept("the")
	kind, ok := graphKinds[p.peek(0)]
	if !ok {
		if p.accept("trust", "stores") {
			kind, ok = "trust-store", true
		}
	} else {
		p.pos++
	}
	if !ok {
		return Plan{}, false
	}
	if !list && !p.accept("exist") && !p.accept("are", "there") {
		return Plan{}, false
	}
	if !p.done() {
		return Plan{}, false
	}
	return Plan{
		Kind: PlanGraphNodes,
		Spec: Spec{Select: []Surface{SurfaceGraph}, Focus: []Surface{SurfaceGraph},
			Where: []Predicate{{Field: FieldGraphNodeKind, Op: OpEq, Value: kind}}},
		Interpretation: "credential-graph nodes of kind " + kind,
		Clauses:        []string{"graph_kind"},
	}, true
}
