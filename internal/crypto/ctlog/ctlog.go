// Package ctlog parses Certificate Transparency log responses (RFC 6962) — the
// signed tree head and get-entries batches — into crypto-free Entry values.
//
// It lives inside the crypto boundary (AN-3): decoding the MerkleTreeLeaf
// framing and parsing the embedded X.509 certificate happen here, and the CT
// monitor outside the boundary consumes only the resulting Entry. The leaf
// framing decoders are bounds-checked so a malformed or hostile log cannot panic
// the monitor.
package ctlog

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"certctl.io/certctl/internal/crypto/certinfo"
)

// RFC 6962 §3.4 enumerations.
const (
	leafVersionV1       = 0
	leafTypeTimestamped = 0
	logEntryTypeX509    = 0
	logEntryTypePrecert = 1
)

// STH is the part of a signed tree head the monitor needs: the number of entries
// in the log.
type STH struct {
	TreeSize int64
}

// Entry is one certificate observed in a CT log, reduced to crypto-free
// inventory metadata.
type Entry struct {
	Index             int64
	Subject           string
	Issuer            string
	SerialHex         string
	FingerprintSHA256 string
	DNSNames          []string
	NotBefore         time.Time
	NotAfter          time.Time
	Precert           bool
}

// ParseSTH parses a get-sth response body.
func ParseSTH(body []byte) (STH, error) {
	var raw struct {
		TreeSize int64 `json:"tree_size"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return STH{}, fmt.Errorf("ctlog: parse sth: %w", err)
	}
	if raw.TreeSize < 0 {
		return STH{}, fmt.Errorf("ctlog: negative tree_size %d", raw.TreeSize)
	}
	return STH{TreeSize: raw.TreeSize}, nil
}

// ParseEntries parses a get-entries response body. start is the log index of the
// first entry, so each returned Entry carries its absolute index.
func ParseEntries(start int64, body []byte) ([]Entry, error) {
	var raw struct {
		Entries []struct {
			LeafInput string `json:"leaf_input"`
			ExtraData string `json:"extra_data"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("ctlog: parse entries: %w", err)
	}

	out := make([]Entry, 0, len(raw.Entries))
	for i, je := range raw.Entries {
		index := start + int64(i)
		leaf, err := base64.StdEncoding.DecodeString(je.LeafInput)
		if err != nil {
			return nil, fmt.Errorf("ctlog: entry %d: decode leaf_input: %w", index, err)
		}
		extra, err := base64.StdEncoding.DecodeString(je.ExtraData)
		if err != nil {
			return nil, fmt.Errorf("ctlog: entry %d: decode extra_data: %w", index, err)
		}
		der, precert, err := leafCertDER(leaf, extra)
		if err != nil {
			return nil, fmt.Errorf("ctlog: entry %d: %w", index, err)
		}
		info, err := certinfo.Inspect(der)
		if err != nil {
			return nil, fmt.Errorf("ctlog: entry %d: inspect certificate: %w", index, err)
		}
		out = append(out, Entry{
			Index:             index,
			Subject:           info.Subject,
			Issuer:            info.Issuer,
			SerialHex:         info.SerialNumber,
			FingerprintSHA256: info.SHA256Fingerprint,
			DNSNames:          info.DNSNames,
			NotBefore:         info.NotBefore,
			NotAfter:          info.NotAfter,
			Precert:           precert,
		})
	}
	return out, nil
}

// leafCertDER decodes a MerkleTreeLeaf and returns the DER of the certificate it
// references. For an x509_entry the certificate is in the leaf itself; for a
// precert_entry the full precertificate is in extra_data (the leaf carries only
// the issuer key hash and TBSCertificate).
func leafCertDER(leaf, extra []byte) (der []byte, precert bool, err error) {
	r := &reader{b: leaf}
	version, err := r.u8()
	if err != nil {
		return nil, false, err
	}
	leafType, err := r.u8()
	if err != nil {
		return nil, false, err
	}
	if version != leafVersionV1 {
		return nil, false, fmt.Errorf("unsupported MerkleTreeLeaf version %d", version)
	}
	if leafType != leafTypeTimestamped {
		return nil, false, fmt.Errorf("unsupported leaf type %d", leafType)
	}
	if _, err := r.u64(); err != nil { // timestamp
		return nil, false, err
	}
	entryType, err := r.u16()
	if err != nil {
		return nil, false, err
	}
	switch entryType {
	case logEntryTypeX509:
		cert, err := r.varBytes24()
		if err != nil {
			return nil, false, fmt.Errorf("x509 entry: %w", err)
		}
		return cert, false, nil
	case logEntryTypePrecert:
		// The leaf holds issuer_key_hash + TBSCertificate, which are not a full
		// certificate; the parseable precertificate is the first ASN.1Cert in
		// extra_data (PrecertChainEntry.pre_certificate).
		cert, err := (&reader{b: extra}).varBytes24()
		if err != nil {
			return nil, false, fmt.Errorf("precert entry extra_data: %w", err)
		}
		return cert, true, nil
	default:
		return nil, false, fmt.Errorf("unknown log entry type %d", entryType)
	}
}

// reader is a bounds-checked big-endian reader over a TLS-style byte buffer.
type reader struct {
	b []byte
	i int
}

var errShort = errors.New("short read")

func (r *reader) need(n int) error {
	if n < 0 || r.i+n > len(r.b) {
		return errShort
	}
	return nil
}

func (r *reader) u8() (int, error) {
	if err := r.need(1); err != nil {
		return 0, err
	}
	v := int(r.b[r.i])
	r.i++
	return v, nil
}

func (r *reader) u16() (int, error) {
	if err := r.need(2); err != nil {
		return 0, err
	}
	v := int(binary.BigEndian.Uint16(r.b[r.i:]))
	r.i += 2
	return v, nil
}

func (r *reader) u24() (int, error) {
	if err := r.need(3); err != nil {
		return 0, err
	}
	v := int(r.b[r.i])<<16 | int(r.b[r.i+1])<<8 | int(r.b[r.i+2])
	r.i += 3
	return v, nil
}

func (r *reader) u64() (uint64, error) {
	if err := r.need(8); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint64(r.b[r.i:])
	r.i += 8
	return v, nil
}

// varBytes24 reads a 24-bit length prefix followed by that many bytes.
func (r *reader) varBytes24() ([]byte, error) {
	n, err := r.u24()
	if err != nil {
		return nil, err
	}
	if err := r.need(n); err != nil {
		return nil, err
	}
	b := r.b[r.i : r.i+n]
	r.i += n
	return b, nil
}
