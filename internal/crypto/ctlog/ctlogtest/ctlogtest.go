// Package ctlogtest is a faithful in-process Certificate Transparency log (RFC
// 6962): it issues real certificates and frames them into get-sth / get-entries
// responses with correct MerkleTreeLeaf encoding, so packages outside the crypto
// boundary can exercise CT parsing and the monitor end to end without importing
// crypto. It plays the role the connector doubles play for deployment targets.
package ctlogtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"time"
)

// Log entry types (RFC 6962 §3.4).
const (
	entryX509    = 0
	entryPrecert = 1
)

// LogEntry is one framed CT log entry: the MerkleTreeLeaf (leaf_input) and the
// chain/precert payload (extra_data).
type LogEntry struct {
	LeafInput []byte
	ExtraData []byte
}

// IssueCert builds a real end-entity certificate for the given common name and
// DNS SANs and returns its DER encoding together with the DER of its
// TBSCertificate (used to frame precert entries).
func IssueCert(cn string, dnsNames ...string) (der, tbs []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: "ctlogtest Issuing CA"},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return der, parsed.RawTBSCertificate, nil
}

// X509Entry frames a leaf certificate as an RFC 6962 x509_entry: the certificate
// lives in the MerkleTreeLeaf and extra_data carries an (empty) chain.
func X509Entry(certDER []byte) LogEntry {
	var leaf []byte
	leaf = append(leaf, 0, 0) // version v1, leaf_type timestamped_entry
	leaf = append(leaf, u64(timestampMillis())...)
	leaf = append(leaf, u16(entryX509)...)
	leaf = append(leaf, asn1Cert(certDER)...) // ASN.1Cert signed_entry
	leaf = append(leaf, u16(0)...)            // empty CtExtensions
	return LogEntry{LeafInput: leaf, ExtraData: u24Len(nil)}
}

// PrecertEntry frames a (pre)certificate as an RFC 6962 precert_entry: the
// MerkleTreeLeaf carries the issuer key hash and TBSCertificate, while the full
// precertificate lives in extra_data (where a real monitor reads it).
func PrecertEntry(certDER, tbsDER []byte) LogEntry {
	var leaf []byte
	leaf = append(leaf, 0, 0)
	leaf = append(leaf, u64(timestampMillis())...)
	leaf = append(leaf, u16(entryPrecert)...)
	leaf = append(leaf, make([]byte, 32)...) // issuer_key_hash[32]
	leaf = append(leaf, asn1Cert(tbsDER)...) // TBSCertificate
	leaf = append(leaf, u16(0)...)           // empty CtExtensions

	// extra_data: PrecertChainEntry = pre_certificate, then the (empty) chain.
	extra := asn1Cert(certDER)
	extra = append(extra, u24Len(nil)...)
	return LogEntry{LeafInput: leaf, ExtraData: extra}
}

// GetSTHBody returns the JSON body of a get-sth response for a tree of the given
// size — useful for testing the parser without a server.
func GetSTHBody(treeSize int) []byte {
	b, _ := json.Marshal(map[string]any{
		"tree_size":           treeSize,
		"timestamp":           timestampMillis(),
		"sha256_root_hash":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"tree_head_signature": base64.StdEncoding.EncodeToString([]byte("sig")),
	})
	return b
}

// GetEntriesBody returns the JSON body of a get-entries response carrying the
// given framed entries, in order.
func GetEntriesBody(entries ...LogEntry) []byte {
	type je struct {
		LeafInput string `json:"leaf_input"`
		ExtraData string `json:"extra_data"`
	}
	out := struct {
		Entries []je `json:"entries"`
	}{}
	for _, e := range entries {
		out.Entries = append(out.Entries, je{
			LeafInput: base64.StdEncoding.EncodeToString(e.LeafInput),
			ExtraData: base64.StdEncoding.EncodeToString(e.ExtraData),
		})
	}
	b, _ := json.Marshal(out)
	return b
}

// Server is a faithful CT log serving get-sth and get-entries over HTTP.
type Server struct {
	httptest *httptest.Server
	entries  []LogEntry
}

// NewServer starts a CT log whose tree contains the given entries in order.
func NewServer(entries ...LogEntry) *Server {
	s := &Server{entries: entries}
	mux := http.NewServeMux()
	mux.HandleFunc("/ct/v1/get-sth", s.getSTH)
	mux.HandleFunc("/ct/v1/get-entries", s.getEntries)
	s.httptest = httptest.NewServer(mux)
	return s
}

// URL is the log's base URL (no trailing slash).
func (s *Server) URL() string { return s.httptest.URL }

// Close shuts the log down.
func (s *Server) Close() { s.httptest.Close() }

func (s *Server) getSTH(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"tree_size":           len(s.entries),
		"timestamp":           timestampMillis(),
		"sha256_root_hash":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"tree_head_signature": base64.StdEncoding.EncodeToString([]byte("sig")),
	})
}

func (s *Server) getEntries(w http.ResponseWriter, r *http.Request) {
	start, err1 := strconv.Atoi(r.URL.Query().Get("start"))
	end, err2 := strconv.Atoi(r.URL.Query().Get("end")) // inclusive per RFC 6962
	if err1 != nil || err2 != nil || start < 0 || end < start {
		http.Error(w, "bad range", http.StatusBadRequest)
		return
	}
	if end >= len(s.entries) {
		end = len(s.entries) - 1
	}
	type je struct {
		LeafInput string `json:"leaf_input"`
		ExtraData string `json:"extra_data"`
	}
	out := struct {
		Entries []je `json:"entries"`
	}{}
	for i := start; i <= end; i++ {
		out.Entries = append(out.Entries, je{
			LeafInput: base64.StdEncoding.EncodeToString(s.entries[i].LeafInput),
			ExtraData: base64.StdEncoding.EncodeToString(s.entries[i].ExtraData),
		})
	}
	writeJSON(w, out)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// --- minimal TLS-style encoders (RFC 6962 §3.4) ---

func u16(v int) []byte { return []byte{byte(v >> 8), byte(v)} }

func u64(v uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

// asn1Cert prefixes a DER blob with a 24-bit length (ASN.1Cert<1..2^24-1>).
func asn1Cert(der []byte) []byte { return append(u24Len(der), der...) }

// u24Len returns the 24-bit big-endian length of b.
func u24Len(b []byte) []byte {
	n := len(b)
	return []byte{byte(n >> 16), byte(n >> 8), byte(n)}
}

func timestampMillis() uint64 { return uint64(time.Now().UnixMilli()) }
