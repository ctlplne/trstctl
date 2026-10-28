// SPDX-License-Identifier: BUSL-1.1

package ctlogtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net/http"
	"strconv"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/ctlog"
)

// SigningOption shapes a signing log.
type SigningOption func(*signingLog)

// WithDelayedMerge keeps accepted submissions out of the tree until Merge, so
// a test can see an SCT before its inclusion.
func WithDelayedMerge() SigningOption { return func(l *signingLog) { l.delayMerge = true } }

// WithCorruptSCTs returns SCTs whose signatures do not verify.
func WithCorruptSCTs() SigningOption { return func(l *signingLog) { l.corrupt = true } }

// WithForkedTreeHeads signs tree heads over a root that is not the root of
// the entries the log accepted, so no audit path leads to it.
func WithForkedTreeHeads() SigningOption { return func(l *signingLog) { l.forked = true } }

// signingLog is the RFC 6962 state of a signing Server: its key, its Merkle
// tree of accepted entries and the entries waiting to be merged.
type signingLog struct {
	mu         sync.Mutex
	key        *ecdsa.PrivateKey
	leaves     [][]byte // MerkleTreeLeaf bytes, in tree order
	pending    [][]byte
	delayMerge bool
	corrupt    bool
	forked     bool
	// headAge dates tree heads later than now, as a log's heads would be
	// once time passes.
	headAge time.Duration
}

// NewSigningServer starts a CT log with its own ECDSA P-256 key: add-chain and
// add-pre-chain answer with SCTs it signs over the real RFC 6962 entry, get-sth
// with a signed tree head over a real Merkle tree of what it accepted, and
// get-proof-by-hash with a real audit path.
func NewSigningServer(options ...SigningOption) *Server {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	s := NewServer()
	s.signing = &signingLog{key: key}
	for _, option := range options {
		option(s.signing)
	}
	return s
}

// PublicKeyDER is the signing log's key as DER SubjectPublicKeyInfo.
func (s *Server) PublicKeyDER() []byte {
	der, err := x509.MarshalPKIXPublicKey(&s.signing.key.PublicKey)
	if err != nil {
		panic(err)
	}
	return der
}

// AgeTreeHeads dates the tree heads the log signs from now on d later, so a
// test can stand past the log's maximum merge delay.
func (s *Server) AgeTreeHeads(d time.Duration) {
	l := s.signing
	l.mu.Lock()
	defer l.mu.Unlock()
	l.headAge = d
}

// Merge adds the accepted submissions waiting under WithDelayedMerge to the
// tree.
func (s *Server) Merge() {
	l := s.signing
	l.mu.Lock()
	defer l.mu.Unlock()
	l.leaves = append(l.leaves, l.pending...)
	l.pending = nil
}

// sign answers one accepted chain with a signed SCT and queues or merges its
// leaf.
func (l *signingLog) sign(chain [][]byte, precert bool) (map[string]any, error) {
	entryType := entryX509
	var entry []byte
	if precert {
		tbs, err := ctlog.PrecertificateTBS(chain[0])
		if err != nil {
			return nil, err
		}
		issuer, err := x509.ParseCertificate(chain[1])
		if err != nil {
			return nil, err
		}
		keyHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
		entryType = entryPrecert
		entry = append(entry, keyHash[:]...)
		entry = append(entry, asn1Cert(tbs)...)
	} else {
		entry = asn1Cert(chain[0])
	}
	timestamp := timestampMillis()
	var signed []byte
	signed = append(signed, 0, 0) // version v1, certificate_timestamp
	signed = append(signed, u64(timestamp)...)
	signed = append(signed, u16(entryType)...)
	signed = append(signed, entry...)
	signed = append(signed, u16(0)...)
	signature, err := l.digitallySigned(signed)
	if err != nil {
		return nil, err
	}
	if l.corrupt {
		signature[len(signature)-1] ^= 0xff
	}
	leaf := append([]byte{0, 0}, u64(timestamp)...)
	leaf = append(leaf, u16(entryType)...)
	leaf = append(leaf, entry...)
	leaf = append(leaf, u16(0)...)
	l.mu.Lock()
	if l.delayMerge {
		l.pending = append(l.pending, leaf)
	} else {
		l.leaves = append(l.leaves, leaf)
	}
	l.mu.Unlock()
	spki, err := x509.MarshalPKIXPublicKey(&l.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"sct_version": 0,
		"id":          base64.StdEncoding.EncodeToString(ctlog.LogID(spki)),
		"timestamp":   timestamp,
		"extensions":  "",
		"signature":   base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// digitallySigned signs message as an RFC 5246 DigitallySigned struct
// (SHA-256 with ECDSA).
func (l *signingLog) digitallySigned(message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, l.key, digest[:])
	if err != nil {
		return nil, err
	}
	out := []byte{4, 3}
	out = append(out, u16(len(signature))...)
	return append(out, signature...), nil
}

func (l *signingLog) signedTreeHead() (map[string]any, error) {
	l.mu.Lock()
	hashes := make([][]byte, 0, len(l.leaves))
	for _, leaf := range l.leaves {
		hashes = append(hashes, ctlog.MerkleLeafHash(leaf))
	}
	forked, age := l.forked, l.headAge
	l.mu.Unlock()
	root := merkleRoot(hashes)
	if forked {
		fork := sha256.Sum256(append([]byte("fork"), root...))
		root = fork[:]
	}
	timestamp := timestampMillis()
	if age > 0 {
		timestamp += uint64(age / time.Millisecond) // #nosec G115 -- a positive test clock offset (CWE-190)
	}
	signed := []byte{0, 1} // version v1, tree_hash
	signed = append(signed, u64(timestamp)...)
	signed = append(signed, u64(uint64(len(hashes)))...)
	signed = append(signed, root...)
	signature, err := l.digitallySigned(signed)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"tree_size":           len(hashes),
		"timestamp":           timestamp,
		"sha256_root_hash":    base64.StdEncoding.EncodeToString(root),
		"tree_head_signature": base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func (l *signingLog) proofByHash(w http.ResponseWriter, r *http.Request) {
	hash, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("hash"))
	if err != nil {
		http.Error(w, "bad hash", http.StatusBadRequest)
		return
	}
	l.mu.Lock()
	hashes := make([][]byte, 0, len(l.leaves))
	for _, leaf := range l.leaves {
		hashes = append(hashes, ctlog.MerkleLeafHash(leaf))
	}
	l.mu.Unlock()
	if size, err := strconv.Atoi(r.URL.Query().Get("tree_size")); err == nil && size >= 0 && size <= len(hashes) {
		hashes = hashes[:size]
	}
	index := -1
	for i, h := range hashes {
		if string(h) == string(hash) {
			index = i
			break
		}
	}
	if index < 0 {
		http.Error(w, "no entry with that hash", http.StatusNotFound)
		return
	}
	path := auditPath(index, hashes)
	encoded := make([]string, 0, len(path))
	for _, node := range path {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(node))
	}
	writeJSON(w, map[string]any{"leaf_index": index, "audit_path": encoded})
}

// merkleRoot is RFC 6962 §2.1 MTH over leaf hashes.
func merkleRoot(hashes [][]byte) []byte {
	switch len(hashes) {
	case 0:
		empty := sha256.Sum256(nil)
		return empty[:]
	case 1:
		return hashes[0]
	}
	k := largestPowerOfTwoBelow(len(hashes))
	return node(merkleRoot(hashes[:k]), merkleRoot(hashes[k:]))
}

// auditPath is RFC 6962 §2.1.1 PATH(m, D[n]).
func auditPath(m int, hashes [][]byte) [][]byte {
	if len(hashes) <= 1 {
		return nil
	}
	k := largestPowerOfTwoBelow(len(hashes))
	if m < k {
		return append(auditPath(m, hashes[:k]), merkleRoot(hashes[k:]))
	}
	return append(auditPath(m-k, hashes[k:]), merkleRoot(hashes[:k]))
}

func largestPowerOfTwoBelow(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func node(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// IssuePrecert builds a CA and a precertificate it signs (RFC 6962 §3.1: the
// critical poison extension), returning both DERs — what a CA submits with
// add-pre-chain.
func IssuePrecert(cn string, dnsNames ...string) (precertDER, issuerDER []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ctlogtest Precert CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	issuerDER, err = x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return nil, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: dnsNames,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}, Critical: true, Value: asn1.NullBytes}},
	}
	precertDER, err = x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, caKey)
	return precertDER, issuerDER, err
}
