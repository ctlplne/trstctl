// SPDX-License-Identifier: BUSL-1.1

// Package trust holds trstctl's shipped certificate distrust list and the
// operations the image builds, the outbound TLS clients and the posture checks
// share over it (eMudhra incident, October 2026): parse the list, match a
// certificate by SPKI or certificate hash, filter a PEM trust bundle so an image
// ships exactly the roots a current browser trusts, and probe an endpoint with
// the system roots. Hashing and X.509 handling stay inside the internal/crypto
// boundary (AN-3); callers outside it only see entries and results.
package trust

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed distrust.json
var shippedJSON []byte

// Entry kinds.
const (
	KindRoot         = "root"
	KindIntermediate = "intermediate"
)

// Entry origins.
const (
	OriginShipped  = "shipped"
	OriginOperator = "operator"
)

// Entry is one distrusted certificate or key. SPKISHA256 matches every
// certificate issued for the same public key (a cross-sign included);
// CertSHA256, when set, also matches that exact certificate.
type Entry struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	SPKISHA256 string   `json:"spki_sha256"`
	CertSHA256 string   `json:"cert_sha256,omitempty"`
	Reason     string   `json:"reason"`
	Sources    []string `json:"sources"`
	Since      string   `json:"since"`
	Origin     string   `json:"origin,omitempty"`
}

type file struct {
	Schema  int     `json:"schema"`
	Updated string  `json:"updated"`
	Notes   string  `json:"notes"`
	Entries []Entry `json:"entries"`
}

// List is an immutable, validated distrust list.
type List struct {
	updated string
	entries []Entry
	bySPKI  map[string]int
	byCert  map[string]int
}

var (
	shippedOnce sync.Once
	shippedList *List
	shippedErr  error
)

// Shipped returns the list compiled into the binary. The embedded file is
// validated once; a malformed shipped list is a build defect, so this panics
// rather than letting a client run with no list.
func Shipped() *List {
	shippedOnce.Do(func() {
		shippedList, shippedErr = parse(shippedJSON, OriginShipped)
	})
	if shippedErr != nil {
		panic("trust: shipped distrust list is invalid: " + shippedErr.Error())
	}
	return shippedList
}

// Parse validates an operator-supplied list in the shipped file's shape.
func Parse(data []byte) (*List, error) { return parse(data, OriginOperator) }

func parse(data []byte, origin string) (*List, error) {
	var f file
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("trust: decode distrust list: %w", err)
	}
	if f.Schema != 1 {
		return nil, fmt.Errorf("trust: distrust list schema %d is not supported", f.Schema)
	}
	for i := range f.Entries {
		f.Entries[i].Origin = origin
	}
	return build(f.Updated, f.Entries)
}

func build(updated string, entries []Entry) (*List, error) {
	l := &List{updated: updated, bySPKI: map[string]int{}, byCert: map[string]int{}}
	for _, e := range entries {
		e.SPKISHA256 = strings.ToLower(strings.TrimSpace(e.SPKISHA256))
		e.CertSHA256 = strings.ToLower(strings.TrimSpace(e.CertSHA256))
		e.Name = strings.TrimSpace(e.Name)
		switch {
		case e.Name == "":
			return nil, errors.New("trust: distrust entry without a name")
		case e.Kind != KindRoot && e.Kind != KindIntermediate:
			return nil, fmt.Errorf("trust: distrust entry %q: kind %q is not root or intermediate", e.Name, e.Kind)
		case !isSHA256Hex(e.SPKISHA256):
			return nil, fmt.Errorf("trust: distrust entry %q: spki_sha256 must be 64 hex characters", e.Name)
		case e.CertSHA256 != "" && !isSHA256Hex(e.CertSHA256):
			return nil, fmt.Errorf("trust: distrust entry %q: cert_sha256 must be 64 hex characters", e.Name)
		case strings.TrimSpace(e.Reason) == "":
			return nil, fmt.Errorf("trust: distrust entry %q: a reason is required", e.Name)
		case len(e.Sources) == 0:
			return nil, fmt.Errorf("trust: distrust entry %q: at least one source is required", e.Name)
		case e.Origin == "":
			return nil, fmt.Errorf("trust: distrust entry %q: origin is required", e.Name)
		}
		if _, dup := l.bySPKI[e.SPKISHA256]; dup {
			return nil, fmt.Errorf("trust: distrust entry %q repeats spki_sha256 %s", e.Name, e.SPKISHA256)
		}
		l.bySPKI[e.SPKISHA256] = len(l.entries)
		if e.CertSHA256 != "" {
			if _, dup := l.byCert[e.CertSHA256]; dup {
				return nil, fmt.Errorf("trust: distrust entry %q repeats cert_sha256 %s", e.Name, e.CertSHA256)
			}
			l.byCert[e.CertSHA256] = len(l.entries)
		}
		l.entries = append(l.entries, e)
	}
	return l, nil
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Merge returns a list holding every entry of l plus extra. Shipped entries
// can never be removed this way: a configured list only ever adds.
func (l *List) Merge(extra *List) (*List, error) {
	if l == nil {
		return nil, errors.New("trust: merge into a nil list")
	}
	entries := append([]Entry(nil), l.entries...)
	if extra != nil {
		for _, e := range extra.entries {
			if _, known := l.bySPKI[e.SPKISHA256]; known {
				continue // the shipped entry already covers this key
			}
			entries = append(entries, e)
		}
	}
	updated := l.updated
	if extra != nil && extra.updated > updated {
		updated = extra.updated
	}
	return build(updated, entries)
}

// Updated is the list's own date stamp.
func (l *List) Updated() string { return l.updated }

// Len is the number of entries.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.entries)
}

// Entries returns a copy of the entries in file order.
func (l *List) Entries() []Entry {
	if l == nil {
		return nil
	}
	return append([]Entry(nil), l.entries...)
}

// SPKISHA256 is the lowercase hex SHA-256 of the certificate's
// SubjectPublicKeyInfo: the same value for every certificate of one key.
func SPKISHA256(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// CertSHA256 is the lowercase hex SHA-256 of the DER certificate.
func CertSHA256(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// Match reports the entry covering c, by key first and then by exact
// certificate.
func (l *List) Match(c *x509.Certificate) (Entry, bool) {
	if l == nil || c == nil {
		return Entry{}, false
	}
	return l.MatchHashes(SPKISHA256(c), CertSHA256(c))
}

// MatchHashes is Match over precomputed lowercase hex hashes.
func (l *List) MatchHashes(spkiSHA256, certSHA256 string) (Entry, bool) {
	if l == nil {
		return Entry{}, false
	}
	if i, ok := l.bySPKI[strings.ToLower(spkiSHA256)]; ok {
		return l.entries[i], true
	}
	if certSHA256 != "" {
		if i, ok := l.byCert[strings.ToLower(certSHA256)]; ok {
			return l.entries[i], true
		}
	}
	return Entry{}, false
}

// MatchChain reports the first distrusted certificate in chain.
func (l *List) MatchChain(chain []*x509.Certificate) (*x509.Certificate, Entry, bool) {
	for _, c := range chain {
		if e, ok := l.Match(c); ok {
			return c, e, true
		}
	}
	return nil, Entry{}, false
}

// Dropped is one certificate FilterBundle removed.
type Dropped struct {
	Subject    string `json:"subject"`
	SPKISHA256 string `json:"spki_sha256"`
	CertSHA256 string `json:"cert_sha256"`
	Entry      string `json:"entry"`
}

// FilterResult is the outcome of FilterBundle: the bundle to ship and what
// was removed, so an image build can prove what it dropped.
type FilterResult struct {
	Bundle  []byte    `json:"-"`
	Kept    int       `json:"kept"`
	Dropped []Dropped `json:"dropped"`
	// KeptSubjects lists the kept roots in output order; the audit compares
	// them with Mozilla's list.
	KeptSubjects []string `json:"kept_subjects"`
}

// FilterBundle parses every CERTIFICATE block in bundle, drops the ones the
// list covers and re-encodes the rest in input order with a normalised PEM
// framing, so the same inputs always give the same bytes. A block that is not
// a parseable certificate fails the whole filter: a trust bundle with junk in
// it is not something to ship.
func FilterBundle(bundle []byte, list *List) (FilterResult, error) {
	var out bytes.Buffer
	res := FilterResult{Dropped: []Dropped{}, KeptSubjects: []string{}}
	rest := bundle
	seen := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return FilterResult{}, fmt.Errorf("trust: bundle holds a %q block; only certificates belong in a trust bundle", block.Type)
		}
		seen++
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return FilterResult{}, fmt.Errorf("trust: bundle certificate %d does not parse: %w", seen, err)
		}
		if e, ok := list.Match(cert); ok {
			res.Dropped = append(res.Dropped, Dropped{Subject: cert.Subject.String(), SPKISHA256: SPKISHA256(cert), CertSHA256: CertSHA256(cert), Entry: e.Name})
			continue
		}
		if err := pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}); err != nil {
			return FilterResult{}, err
		}
		res.Kept++
		res.KeptSubjects = append(res.KeptSubjects, cert.Subject.String())
	}
	if seen == 0 {
		return FilterResult{}, errors.New("trust: bundle holds no certificates")
	}
	res.Bundle = out.Bytes()
	return res, nil
}

// BundleFromAPK extracts etc/ssl/certs/ca-certificates.crt from an Alpine
// ca-certificates-bundle .apk (three concatenated gzip streams: signature,
// control, data) without shelling out, so an image build stage needs only
// this tool.
func BundleFromAPK(apk []byte) ([]byte, error) {
	const want = "etc/ssl/certs/ca-certificates.crt"
	r := bytes.NewReader(apk)
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("trust: apk is not gzip: %w", err)
	}
	for {
		gz.Multistream(false)
		tr := tar.NewReader(gz)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("trust: read apk member: %w", err)
			}
			if strings.TrimPrefix(hdr.Name, "./") == want {
				data, err := io.ReadAll(io.LimitReader(tr, 8<<20))
				if err != nil {
					return nil, fmt.Errorf("trust: read %s: %w", want, err)
				}
				return data, nil
			}
		}
		// Drain the rest of this gzip member (bounded: a bundle package is a few
		// hundred KiB), then start the next one.
		if _, err := io.CopyN(io.Discard, gz, 64<<20); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if err := gz.Reset(r); err != nil {
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("trust: apk holds no %s", want)
			}
			return nil, fmt.Errorf("trust: next apk stream: %w", err)
		}
	}
}

// ProbeResult is one endpoint handshake with the system roots.
type ProbeResult struct {
	Target     string   `json:"target"`
	OK         bool     `json:"ok"`
	Error      string   `json:"error,omitempty"`
	Chain      []string `json:"chain,omitempty"`
	Root       string   `json:"root,omitempty"`
	Distrusted string   `json:"distrusted,omitempty"`
}

// Probe performs a TLS handshake with hostport (host or host:port; 443 by
// default) using the process's system roots and reports the verified chain,
// its root, and whether any certificate on it is in list. roots overrides the
// system roots for tests.
func Probe(ctx context.Context, hostport string, list *List, roots *x509.CertPool, timeout time.Duration) ProbeResult {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, "443"
	}
	res := ProbeResult{Target: net.JoinHostPort(host, port)}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: roots},
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", res.Target)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer func() { _ = conn.Close() }()
	state := conn.(*tls.Conn).ConnectionState()
	var chain []*x509.Certificate
	if len(state.VerifiedChains) > 0 {
		chain = state.VerifiedChains[0]
	} else {
		chain = state.PeerCertificates
	}
	for _, c := range chain {
		res.Chain = append(res.Chain, c.Subject.String())
	}
	if len(chain) > 0 {
		res.Root = chain[len(chain)-1].Subject.String()
	}
	if _, e, ok := list.MatchChain(chain); ok {
		res.Distrusted = e.Name
		res.Error = "verified chain contains distrusted " + e.Kind + " " + e.Name
		return res
	}
	res.OK = true
	return res
}

// Subjects returns the sorted subjects of every certificate in a PEM bundle.
func Subjects(bundle []byte) ([]string, error) {
	var out []string
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c.Subject.String())
	}
	sort.Strings(out)
	return out, nil
}
