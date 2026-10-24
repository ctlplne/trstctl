// SPDX-License-Identifier: BUSL-1.1

package sshkrl

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	sshprotocol "trstctl.com/trstctl/internal/protocols/ssh"
)

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- committed test fixture
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustParse(t testing.TB, data []byte) Revocations {
	t.Helper()
	r, err := ParseRevocations(data)
	if err != nil {
		t.Fatalf("ParseRevocations: %v", err)
	}
	return r
}

func trstctlList(version uint64, serials []uint64, keyIDs ...string) []byte {
	k := sshprotocol.NewKRL()
	for _, serial := range serials {
		k.RevokeSerial(serial)
	}
	for _, id := range keyIDs {
		k.RevokeKeyID(id)
	}
	return k.DistributeKRL(version)
}

// The lists stock ssh-keygen writes parse to what they revoke: a CA-scoped
// bitmap and key ID, wildcard serials and key IDs, an explicit key, and a
// SHA-256 key hash.
func TestParseRevocationsReadsSSHKeygenLists(t *testing.T) {
	scoped := mustParse(t, readFixture(t, "ssh-keygen-ca-scoped.krl"))
	if scoped.Version != 7 || len(scoped.certs) != 1 {
		t.Fatalf("CA-scoped list = version %d scopes %d", scoped.Version, len(scoped.certs))
	}
	for ca, scope := range scoped.certs {
		if ca == "" || len(scope.serials) != 2 || scope.serials[0] != (serialRange{5, 5}) || scope.serials[1] != (serialRange{10, 20}) || !hasKey(scope, "alice@corp") {
			t.Fatalf("CA-scoped list scope = %+v", scope)
		}
	}
	wild := mustParse(t, readFixture(t, "ssh-keygen-wildcard.krl"))
	if any := wild.certs[""]; wild.Version != 3 || any == nil || len(any.serials) != 1 || any.serials[0] != (serialRange{42, 42}) || !hasKey(any, "pam:abc") {
		t.Fatalf("wildcard list = %+v", wild)
	}
	if keys := mustParse(t, readFixture(t, "ssh-keygen-explicit-key.krl")); len(keys.keys) != 1 {
		t.Fatalf("explicit-key list = %+v", keys)
	}
	if hashes := mustParse(t, readFixture(t, "ssh-keygen-sha256.krl")); len(hashes.sha256) != 1 {
		t.Fatalf("SHA-256 list = %+v", hashes)
	}
}

// Differential: a list stock ssh-keygen writes from a spec parses to exactly
// that spec, including the bitmap and range encodings it chooses.
func TestParseRevocationsMatchesSSHKeygenSpec(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	dir := t.TempDir()
	spec := filepath.Join(dir, "spec")
	if err := os.WriteFile(spec, []byte("serial: 7\nserial: 9\nserial: 100-164\nserial: 4000-4001\nserial: 18446744073709551615\nid: deploy-bot\nid: pam:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "list.krl")
	if msg, err := exec.CommandContext(t.Context(), keygen, "-k", "-f", out, "-s", "none", "-z", "12", spec).CombinedOutput(); err != nil { // #nosec G204 -- fixed ssh-keygen argv over test-owned temp paths
		t.Fatalf("ssh-keygen -k: %v %s", err, msg)
	}
	list := mustParse(t, readFile(t, out))
	any := list.certs[""]
	want := []serialRange{{7, 7}, {9, 9}, {100, 164}, {4000, 4001}, {18446744073709551615, 18446744073709551615}}
	if list.Version != 12 || any == nil || len(any.serials) != len(want) || len(any.keyIDs) != 2 || !hasKey(any, "deploy-bot") || !hasKey(any, "pam:1") {
		t.Fatalf("parsed = version %d %+v", list.Version, any)
	}
	for i := range want {
		if any.serials[i] != want[i] {
			t.Fatalf("serials = %+v, want %+v", any.serials, want)
		}
	}
}

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test-created path under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDroppedComparesWhatEachListRevokes(t *testing.T) {
	scoped := mustParse(t, readFixture(t, "ssh-keygen-ca-scoped.krl"))
	// A wildcard revocation keeps a CA-scoped one.
	if drop := mustParse(t, trstctlList(8, []uint64{5, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}, "alice@corp")).Dropped(scoped); !drop.Empty() {
		t.Fatalf("wildcard superset dropped %+v", drop)
	}
	// Losing one serial of a range and the key ID is counted.
	if drop := mustParse(t, trstctlList(8, []uint64{5, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20})).Dropped(scoped); drop.Serials != 1 || drop.KeyIDs != 1 {
		t.Fatalf("partial cover dropped %+v", drop)
	}
	// A CA-scoped revocation does not keep a wildcard one.
	wild := mustParse(t, trstctlList(3, []uint64{5}, "alice@corp"))
	if drop := scoped.Dropped(wild); drop.Serials != 1 || drop.KeyIDs != 1 {
		t.Fatalf("scoped list kept wildcard revocations: %+v", drop)
	}
	// Plain keys and key hashes must be carried as they are.
	keys, hashes := mustParse(t, readFixture(t, "ssh-keygen-explicit-key.krl")), mustParse(t, readFixture(t, "ssh-keygen-sha256.krl"))
	empty := mustParse(t, trstctlList(99, nil))
	if drop := empty.Dropped(keys); drop.Keys != 1 {
		t.Fatalf("explicit key not counted: %+v", drop)
	}
	if drop := empty.Dropped(hashes); drop.Fingerprints != 1 {
		t.Fatalf("key hash not counted: %+v", drop)
	}
	for _, list := range []Revocations{scoped, wild, keys, hashes, empty} {
		if drop := list.Dropped(list); !drop.Empty() {
			t.Fatalf("a list drops its own revocations: %+v", drop)
		}
	}
}

func TestUncoveredSerialsAtTheEdges(t *testing.T) {
	max := ^uint64(0)
	for _, tc := range []struct {
		want, covering []serialRange
		uncovered      uint64
	}{
		{[]serialRange{{1, max}}, nil, max},
		{[]serialRange{{1, max}}, []serialRange{{1, max}}, 0},
		{[]serialRange{{1, max}}, []serialRange{{2, max}}, 1},
		{[]serialRange{{10, 20}}, []serialRange{{1, 12}, {15, 15}, {19, 30}}, 5},
		{[]serialRange{{5, 5}, {max, max}}, []serialRange{{5, 5}}, 1},
	} {
		if got := uncoveredSerials(tc.want, mergeSerialRanges(tc.covering)); got != tc.uncovered {
			t.Fatalf("uncovered(%v, %v) = %d, want %d", tc.want, tc.covering, got, tc.uncovered)
		}
	}
}

func appendString(b []byte, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) // #nosec G115 -- test fixture strings are a few bytes, far under the uint32 bound
	return append(b, s...)
}

// krlWith builds a list from raw sections after a valid header.
func krlWith(sections ...[]byte) []byte {
	out := []byte(krlMagic)
	out = binary.BigEndian.AppendUint32(out, 1)
	out = binary.BigEndian.AppendUint64(out, 1)
	out = binary.BigEndian.AppendUint64(out, 0)
	out = binary.BigEndian.AppendUint64(out, 0)
	out = appendString(out, nil)
	out = appendString(out, nil)
	for _, s := range sections {
		out = append(out, s...)
	}
	return out
}

func section(kind byte, body []byte) []byte { return appendString([]byte{kind}, body) }

func certSection(sub ...[]byte) []byte {
	body := appendString(appendString(nil, nil), nil)
	for _, s := range sub {
		body = append(body, s...)
	}
	return section(sectionCertificates, body)
}

func TestParseRevocationsRefusesMalformedLists(t *testing.T) {
	u64 := func(v ...uint64) []byte {
		var b []byte
		for _, x := range v {
			b = binary.BigEndian.AppendUint64(b, x)
		}
		return b
	}
	for name, data := range map[string][]byte{
		"truncated header":       krlWith()[:30],
		"unknown section":        krlWith(section(9, nil)),
		"signed list":            krlWith(section(sectionSignature, nil)),
		"serial zero":            krlWith(certSection(section(certSerialList, u64(0)))),
		"ragged serial list":     krlWith(certSection(section(certSerialList, []byte{1, 2, 3}))),
		"inverted range":         krlWith(certSection(section(certSerialRange, u64(9, 3)))),
		"range from zero":        krlWith(certSection(section(certSerialRange, u64(0, 3)))),
		"negative bitmap":        krlWith(certSection(section(certSerialBitmap, append(u64(5), appendString(nil, []byte{0x80})...)))),
		"bitmap at serial zero":  krlWith(certSection(section(certSerialBitmap, append(u64(0), appendString(nil, []byte{0x01})...)))),
		"wrapping bitmap":        krlWith(certSection(section(certSerialBitmap, append(u64(^uint64(0)), appendString(nil, []byte{0x03})...)))),
		"unknown cert section":   krlWith(certSection(section(0x30, nil))),
		"short key hash":         krlWith(section(sectionFingerprint256, appendString(nil, []byte{1, 2, 3}))),
		"empty explicit key":     krlWith(section(sectionExplicitKey, appendString(nil, nil))),
		"overlong section":       append(krlWith(), sectionExplicitKey, 0, 0, 1, 0),
		"truncated key ID entry": krlWith(certSection(section(certKeyID, []byte{0, 0, 0, 9, 'x'}))),
	} {
		if _, err := ParseRevocations(data); err == nil {
			t.Errorf("%s: malformed list accepted", name)
		}
	}
	if r, err := ParseRevocations(krlWith(certSection(section(certSerialBitmap, append(u64(1), appendString(nil, []byte{0x05})...))))); err != nil ||
		len(r.certs[""].serials) != 2 || r.certs[""].serials[0] != (serialRange{1, 1}) || r.certs[""].serials[1] != (serialRange{3, 3}) {
		t.Fatalf("bitmap 0b101 from serial 1 = %+v, %v", r, err)
	}
}

func FuzzParseRevocations(f *testing.F) {
	for _, name := range []string{"ssh-keygen-ca-scoped.krl", "ssh-keygen-wildcard.krl", "ssh-keygen-explicit-key.krl", "ssh-keygen-sha256.krl"} {
		f.Add(readFixture(f, name))
	}
	f.Add(trstctlList(4, []uint64{1, 2, 3, 900}, "pam:x"))
	f.Add(krlWith(certSection(section(certSerialBitmap, append(binary.BigEndian.AppendUint64(nil, 1), appendString(nil, []byte{0x7f, 0xff})...)))))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseRevocations(data)
		if err != nil {
			return
		}
		if drop := r.Dropped(r); !drop.Empty() {
			t.Fatalf("a parsed list drops its own revocations: %+v", drop)
		}
		if !bytes.HasPrefix(data, []byte(krlMagic)) || strings.Contains((&DropError{}).Error(), "%!") {
			t.Fatal("parsed list without the KRL magic")
		}
	})
}
