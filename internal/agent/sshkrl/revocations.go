// SPDX-License-Identifier: BUSL-1.1

package sshkrl

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sort"
)

// A host must never replace its installed list with one that stops revoking
// something (A110). Versions order lists of one lineage; they say nothing about
// a list from a restored or replacement control plane, whose counter is its
// own. So before any replacement the host compares what the two lists revoke,
// whatever their versions.

// ErrDropsRevocations marks a candidate KRL that would stop revoking something
// the installed list revokes. The installed list stays in force.
var ErrDropsRevocations = errors.New("sshkrl: candidate KRL drops installed revocations")

// ErrNotNewer marks a candidate KRL whose version does not advance the
// installed one.
var ErrNotNewer = errors.New("sshkrl: candidate KRL does not advance the installed version")

// DropError counts what a candidate would stop revoking.
type DropError struct {
	Serials      uint64 // certificate serials (saturating)
	KeyIDs       int    // certificate key IDs
	Keys         int    // explicitly revoked public keys
	Fingerprints int    // revoked key fingerprints
}

func (e *DropError) Error() string {
	return fmt.Sprintf("sshkrl: the served KRL would stop revoking %d certificate serials, %d key IDs, %d keys and %d key fingerprints this host revokes; the installed list stays in force",
		e.Serials, e.KeyIDs, e.Keys, e.Fingerprints)
}

func (e *DropError) Is(target error) bool { return target == ErrDropsRevocations }

// OpenSSH KRL sections (PROTOCOL.krl).
const (
	sectionCertificates   = 1
	sectionExplicitKey    = 2
	sectionFingerprintSHA = 3
	sectionSignature      = 4
	sectionFingerprint256 = 5

	certSerialList   = 0x20
	certSerialRange  = 0x21
	certSerialBitmap = 0x22
	certKeyID        = 0x23

	// maxBitmapBytes is OpenSSH's bignum bound (SSHBUF_MAX_BIGNUM).
	maxBitmapBytes = 16384 / 8
	// maxRevocationEntries bounds the parsed form of one list.
	maxRevocationEntries = 1 << 20
)

// Revocations is what one OpenSSH KRL revokes. It is compared, never
// re-encoded: the installed bytes stay the bytes sshd reads.
type Revocations struct {
	Version uint64
	certs   map[string]*certRevocations // by CA key blob; "" is any CA
	keys    map[string]struct{}         // explicit public key blobs
	sha1    map[string]struct{}
	sha256  map[string]struct{}
	entries int
}

type certRevocations struct {
	serials []serialRange // sorted, merged, disjoint
	keyIDs  map[string]struct{}
}

type serialRange struct{ lo, hi uint64 }

// ParseRevocations reads every revocation in an OpenSSH binary KRL. It refuses
// what OpenSSH refuses (a bad header, an unknown section, trailing bytes,
// serial zero, a wrapped bitmap) and a signed KRL, which current OpenSSH no
// longer verifies.
func ParseRevocations(data []byte) (Revocations, error) {
	version, err := Version(data)
	if err != nil {
		return Revocations{}, err
	}
	r := Revocations{Version: version, certs: map[string]*certRevocations{},
		keys: map[string]struct{}{}, sha1: map[string]struct{}{}, sha256: map[string]struct{}{}}
	in := wire(data[20:])
	if _, err := in.uint64(); err != nil { // generated_date
		return Revocations{}, err
	}
	if _, err := in.uint64(); err != nil { // flags
		return Revocations{}, err
	}
	if _, err := in.string(); err != nil { // reserved
		return Revocations{}, err
	}
	if _, err := in.string(); err != nil { // comment
		return Revocations{}, err
	}
	pending := map[string][]serialRange{}
	for len(in) > 0 {
		kind, err := in.byte()
		if err != nil {
			return Revocations{}, err
		}
		body, err := in.string()
		if err != nil {
			return Revocations{}, err
		}
		switch kind {
		case sectionCertificates:
			if err := r.parseCertificates(body, pending); err != nil {
				return Revocations{}, err
			}
		case sectionExplicitKey:
			if err := r.parseBlobs(body, r.keys, 0); err != nil {
				return Revocations{}, err
			}
		case sectionFingerprintSHA:
			if err := r.parseBlobs(body, r.sha1, 20); err != nil {
				return Revocations{}, err
			}
		case sectionFingerprint256:
			if err := r.parseBlobs(body, r.sha256, 32); err != nil {
				return Revocations{}, err
			}
		case sectionSignature:
			return Revocations{}, errors.New("sshkrl: signed KRLs are not supported")
		default:
			return Revocations{}, fmt.Errorf("sshkrl: unsupported KRL section %d", kind)
		}
	}
	for ca, ranges := range pending {
		r.certScope(ca).serials = mergeSerialRanges(ranges)
	}
	return r, nil
}

func (r *Revocations) certScope(ca string) *certRevocations {
	scope := r.certs[ca]
	if scope == nil {
		scope = &certRevocations{keyIDs: map[string]struct{}{}}
		r.certs[ca] = scope
	}
	return scope
}

func (r *Revocations) count(n int) error {
	r.entries += n
	if r.entries > maxRevocationEntries {
		return fmt.Errorf("sshkrl: KRL holds more than %d revocation entries", maxRevocationEntries)
	}
	return nil
}

func (r *Revocations) parseCertificates(body []byte, pending map[string][]serialRange) error {
	in := wire(body)
	caKey, err := in.string()
	if err != nil {
		return err
	}
	if _, err := in.string(); err != nil { // reserved
		return err
	}
	ca := string(caKey)
	scope := r.certScope(ca)
	for len(in) > 0 {
		kind, err := in.byte()
		if err != nil {
			return err
		}
		sub, err := in.string()
		if err != nil {
			return err
		}
		switch kind {
		case certSerialList:
			if len(sub)%8 != 0 {
				return errors.New("sshkrl: malformed KRL serial list")
			}
			for ; len(sub) > 0; sub = sub[8:] {
				serial := binary.BigEndian.Uint64(sub[:8])
				if serial == 0 {
					return errors.New("sshkrl: KRL revokes serial zero")
				}
				if err := r.count(1); err != nil {
					return err
				}
				pending[ca] = append(pending[ca], serialRange{serial, serial})
			}
		case certSerialRange:
			if len(sub) != 16 {
				return errors.New("sshkrl: malformed KRL serial range")
			}
			lo, hi := binary.BigEndian.Uint64(sub[:8]), binary.BigEndian.Uint64(sub[8:])
			if lo == 0 || lo > hi {
				return errors.New("sshkrl: invalid KRL serial range")
			}
			if err := r.count(1); err != nil {
				return err
			}
			pending[ca] = append(pending[ca], serialRange{lo, hi})
		case certSerialBitmap:
			ranges, err := bitmapRanges(sub)
			if err != nil {
				return err
			}
			if err := r.count(len(ranges)); err != nil {
				return err
			}
			pending[ca] = append(pending[ca], ranges...)
		case certKeyID:
			ids := wire(sub)
			for len(ids) > 0 {
				id, err := ids.string()
				if err != nil {
					return err
				}
				if bytes.IndexByte(id, 0) >= 0 {
					return errors.New("sshkrl: KRL key ID holds a NUL byte")
				}
				if err := r.count(1); err != nil {
					return err
				}
				scope.keyIDs[string(id)] = struct{}{}
			}
		default:
			return fmt.Errorf("sshkrl: unsupported KRL certificate section %d", kind)
		}
	}
	return nil
}

// bitmapRanges reads a serial bitmap: a base serial and an SSH mpint whose
// least significant bit is that base.
func bitmapRanges(sub []byte) ([]serialRange, error) {
	in := wire(sub)
	base, err := in.uint64()
	if err != nil {
		return nil, err
	}
	mpint, err := in.string()
	if err != nil {
		return nil, err
	}
	if len(in) != 0 {
		return nil, errors.New("sshkrl: malformed KRL serial bitmap")
	}
	if len(mpint) > 0 && mpint[0]&0x80 != 0 {
		return nil, errors.New("sshkrl: negative KRL serial bitmap")
	}
	for len(mpint) > 0 && mpint[0] == 0 {
		mpint = mpint[1:]
	}
	if len(mpint) > maxBitmapBytes {
		return nil, errors.New("sshkrl: KRL serial bitmap is too large")
	}
	var out []serialRange
	open := false
	nbits := uint64(len(mpint)) * 8
	for bit := uint64(0); bit < nbits; bit++ {
		set := mpint[len(mpint)-1-int(bit/8)]&(1<<(bit%8)) != 0
		if !set {
			open = false
			continue
		}
		if bit > 0 && base+bit < base {
			return nil, errors.New("sshkrl: KRL serial bitmap wraps")
		}
		serial := base + bit
		if serial == 0 {
			return nil, errors.New("sshkrl: KRL revokes serial zero")
		}
		if open {
			out[len(out)-1].hi = serial
		} else {
			out = append(out, serialRange{serial, serial})
			open = true
		}
	}
	return out, nil
}

func (r *Revocations) parseBlobs(body []byte, into map[string]struct{}, size int) error {
	in := wire(body)
	for len(in) > 0 {
		blob, err := in.string()
		if err != nil {
			return err
		}
		if len(blob) == 0 || (size != 0 && len(blob) != size) {
			return errors.New("sshkrl: malformed KRL key or fingerprint entry")
		}
		if err := r.count(1); err != nil {
			return err
		}
		into[string(blob)] = struct{}{}
	}
	return nil
}

// SerialRange is an inclusive range of certificate serials.
type SerialRange struct{ Lo, Hi uint64 }

// Carried is what a list revokes, in the form a list for any CA carries it:
// what a replacement control plane adopts from its predecessor (A110).
type Carried struct {
	Serials   []SerialRange // merged across CA scopes
	KeyIDs    []string      // sorted
	Keys      [][]byte      // explicitly revoked public key blobs, sorted
	SHA1      [][]byte      // revoked key SHA-1 hashes, sorted
	SHA256    [][]byte      // revoked key SHA-256 hashes, sorted
	Broadened int           // CA-scoped serial ranges and key IDs now carried for any CA
}

// Carried returns r's revocations for a list that revokes them for any CA. A
// revocation scoped to one CA becomes one for every CA, which still revokes
// what the list did, so a host comparing the two keeps nothing less.
func (r Revocations) Carried() Carried {
	var out Carried
	var all []serialRange
	ids := map[string]struct{}{}
	for ca, scope := range r.certs {
		all = append(all, scope.serials...)
		for id := range scope.keyIDs {
			ids[id] = struct{}{}
		}
		if ca != "" {
			out.Broadened += len(scope.serials) + len(scope.keyIDs)
		}
	}
	for _, s := range mergeSerialRanges(all) {
		out.Serials = append(out.Serials, SerialRange{Lo: s.lo, Hi: s.hi})
	}
	for id := range ids {
		out.KeyIDs = append(out.KeyIDs, id)
	}
	sort.Strings(out.KeyIDs)
	out.Keys, out.SHA1, out.SHA256 = sortedBlobs(r.keys), sortedBlobs(r.sha1), sortedBlobs(r.sha256)
	return out
}

func sortedBlobs(set map[string]struct{}) [][]byte {
	out := make([][]byte, 0, len(set))
	for blob := range set {
		out = append(out, []byte(blob))
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

func mergeSerialRanges(ranges []serialRange) []serialRange {
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].lo < ranges[j].lo })
	out := ranges[:0]
	for _, next := range ranges {
		if n := len(out); n > 0 && (next.lo <= out[n-1].hi || (out[n-1].hi != math.MaxUint64 && next.lo == out[n-1].hi+1)) {
			if next.hi > out[n-1].hi {
				out[n-1].hi = next.hi
			}
			continue
		}
		out = append(out, next)
	}
	return out
}

// Dropped reports what installed revokes that r does not. A certificate
// revocation under a specific CA is kept by the same revocation under that CA
// or under any CA; the other kinds must be present as they are.
func (r Revocations) Dropped(installed Revocations) DropError {
	var drop DropError
	for ca, scope := range installed.certs {
		keep := r.certs[ca]
		var any *certRevocations
		if ca != "" {
			any = r.certs[""]
		}
		var covering []serialRange
		if keep != nil {
			covering = append(covering, keep.serials...)
		}
		if any != nil {
			covering = append(covering, any.serials...)
		}
		drop.Serials = saturatingAdd(drop.Serials, uncoveredSerials(scope.serials, mergeSerialRanges(covering)))
		for id := range scope.keyIDs {
			if !hasKey(keep, id) && !hasKey(any, id) {
				drop.KeyIDs++
			}
		}
	}
	drop.Keys = missing(installed.keys, r.keys)
	drop.Fingerprints = missing(installed.sha1, r.sha1) + missing(installed.sha256, r.sha256)
	return drop
}

// Empty reports whether nothing is dropped.
func (e *DropError) Empty() bool { return *e == DropError{} }

// RevokesNothing reports whether the list revokes no certificate serial, key
// ID, key, or key hash for any CA: the empty list `ssh-keygen -k` writes when
// a host is prepared, or a control plane's list before its first revocation.
func (r Revocations) RevokesNothing() bool {
	for _, scope := range r.certs {
		if len(scope.serials) > 0 || len(scope.keyIDs) > 0 {
			return false
		}
	}
	return len(r.keys) == 0 && len(r.sha1) == 0 && len(r.sha256) == 0
}

func hasKey(scope *certRevocations, id string) bool {
	if scope == nil {
		return false
	}
	_, ok := scope.keyIDs[id]
	return ok
}

func missing(want, have map[string]struct{}) int {
	n := 0
	for k := range want {
		if _, ok := have[k]; !ok {
			n++
		}
	}
	return n
}

// uncoveredSerials counts the serials in want (sorted, disjoint) outside
// covering (sorted, merged).
func uncoveredSerials(want, covering []serialRange) uint64 {
	var total uint64
	j := 0
	for _, w := range want {
		lo := w.lo
		for lo <= w.hi {
			for j < len(covering) && covering[j].hi < lo {
				j++
			}
			if j == len(covering) || covering[j].lo > w.hi {
				total = saturatingAdd(total, w.hi-lo+1)
				break
			}
			if covering[j].lo > lo {
				total = saturatingAdd(total, covering[j].lo-lo)
			}
			if covering[j].hi >= w.hi {
				break
			}
			lo = covering[j].hi + 1
		}
	}
	return total
}

func saturatingAdd(a, b uint64) uint64 {
	sum, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return math.MaxUint64
	}
	return sum
}

// wire reads SSH wire encoding (RFC 4251).
type wire []byte

func (w *wire) byte() (byte, error) {
	if len(*w) < 1 {
		return 0, errors.New("sshkrl: truncated KRL")
	}
	b := (*w)[0]
	*w = (*w)[1:]
	return b, nil
}

func (w *wire) uint64() (uint64, error) {
	if len(*w) < 8 {
		return 0, errors.New("sshkrl: truncated KRL")
	}
	v := binary.BigEndian.Uint64(*w)
	*w = (*w)[8:]
	return v, nil
}

func (w *wire) string() ([]byte, error) {
	if len(*w) < 4 {
		return nil, errors.New("sshkrl: truncated KRL")
	}
	n := binary.BigEndian.Uint32(*w)
	if int64(n) > int64(len(*w))-4 {
		return nil, errors.New("sshkrl: truncated KRL")
	}
	s := (*w)[4 : 4+int(n)]
	*w = (*w)[4+int(n):]
	return s, nil
}
