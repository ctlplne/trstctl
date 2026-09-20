// SPDX-License-Identifier: BUSL-1.1

package sshkeys_test

import (
	"bytes"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"testing/quick"

	"golang.org/x/crypto/ssh"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
)

const sshPropertySeed int64 = 81007

type sshRoundTripPropertyInput struct {
	KeyIndex   uint8
	Comment    string
	Hosts      []string
	OptionMask uint8
}

func (sshRoundTripPropertyInput) Generate(r *rand.Rand, size int) reflect.Value {
	hostCount := 1 + r.Intn(1+minSSHProperty(size, 4))
	hosts := make([]string, hostCount)
	for i := range hosts {
		hosts[i] = "host-" + sshPropertyToken(r, 1+r.Intn(12)) + ".example.test"
	}
	comment := ""
	if r.Intn(3) != 0 {
		comment = "owner-" + sshPropertyToken(r, 1+minSSHProperty(size, 32))
	}
	return reflect.ValueOf(sshRoundTripPropertyInput{
		KeyIndex:   uint8(r.Intn(3)), // #nosec G115 -- generator bounds the value to 0..2 (CWE-190)
		Comment:    comment,
		Hosts:      hosts,
		OptionMask: uint8(r.Intn(4)), // #nosec G115 -- generator bounds the value to 0..3 (CWE-190)
	})
}

// TestPropertySSHAuthorizedKnownHostsAndPublicKeyRoundTrips generates the three
// OpenSSH public-key record shapes. Parsing must preserve the same cryptographic
// identity while returning the record-specific comment, options, and host list.
func TestPropertySSHAuthorizedKnownHostsAndPublicKeyRoundTrips(t *testing.T) {
	prop := func(g sshRoundTripPropertyInput) bool {
		base, wantType, wantFingerprint := sshPropertyKey(g.KeyIndex)
		publicLine := base
		if g.Comment != "" {
			publicLine += " " + g.Comment
		}
		publicLine += "\n"

		publicInfo, err := sshkeys.ParsePublicKey([]byte(publicLine))
		if err != nil {
			t.Logf("parse generated SSH public key: %v; line=%q", err, publicLine)
			return false
		}
		if publicInfo.Type != wantType || publicInfo.FingerprintSHA256 != wantFingerprint || publicInfo.Comment != g.Comment {
			t.Logf("generated SSH public-key fields changed: got=%+v want_type=%q want_fp=%q want_comment=%q", publicInfo, wantType, wantFingerprint, g.Comment)
			return false
		}

		options := sshPropertyOptions(g.OptionMask)
		authorizedLine := publicLine
		if len(options) > 0 {
			authorizedLine = strings.Join(options, ",") + " " + publicLine
		}
		authorized := sshkeys.ParseAuthorizedKeys([]byte(authorizedLine))
		if len(authorized) != 1 || authorized[0].Type != wantType || authorized[0].FingerprintSHA256 != wantFingerprint || authorized[0].Comment != g.Comment || !reflect.DeepEqual(authorized[0].Options, options) {
			t.Logf("generated authorized_keys record changed: got=%+v options=%v line=%q", authorized, options, authorizedLine)
			return false
		}

		knownHostsLine := strings.Join(g.Hosts, ",") + " " + publicLine
		knownHosts := sshkeys.ParseKnownHosts([]byte(knownHostsLine))
		if len(knownHosts) != 1 || knownHosts[0].Type != wantType || knownHosts[0].FingerprintSHA256 != wantFingerprint || knownHosts[0].Comment != g.Comment || !reflect.DeepEqual(knownHosts[0].Hosts, g.Hosts) {
			t.Logf("generated known_hosts record changed: got=%+v hosts=%v line=%q", knownHosts, g.Hosts, knownHostsLine)
			return false
		}

		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(base))
		if err != nil {
			t.Logf("reference parser rejected fixture key: %v", err)
			return false
		}
		canonical := ssh.MarshalAuthorizedKey(parsed)
		canonicalInfo, err := sshkeys.ParsePublicKey(canonical)
		if err != nil || canonicalInfo.Type != wantType || canonicalInfo.FingerprintSHA256 != wantFingerprint || canonicalInfo.Comment != "" {
			t.Logf("canonical SSH key identity changed: got=%+v err=%v", canonicalInfo, err)
			return false
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{
		MaxCount: 1000,
		Rand:     rand.New(rand.NewSource(sshPropertySeed)), // #nosec G404 -- deterministic property-test stream, not security randomness (CWE-338)
	}); err != nil {
		t.Fatalf("SSH record round-trip property violated: %v", err)
	}
}

type sshParserPropertyInput struct {
	Data []byte
}

func (sshParserPropertyInput) Generate(r *rand.Rand, size int) reflect.Value {
	n := r.Intn(1 + minSSHProperty(size*8, 4096))
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(r.Intn(256)) // #nosec G115 -- generator bounds the value to one byte (CWE-190)
	}
	if r.Intn(4) == 0 {
		base, _, _ := sshPropertyKey(uint8(r.Intn(3))) // #nosec G115 -- generator bounds the value to 0..2 (CWE-190)
		data = append([]byte(base+" generated\n"), data...)
	}
	return reflect.ValueOf(sshParserPropertyInput{Data: data})
}

// TestPropertySSHParsersRejectOrReturnWholeRecords feeds deterministic hostile
// byte streams to every SSH public-key parser. Repeated parses must agree; any
// accepted record must have a complete key type and fingerprint, never partial
// attacker-controlled metadata.
func TestPropertySSHParsersRejectOrReturnWholeRecords(t *testing.T) {
	prop := func(g sshParserPropertyInput) bool {
		firstAuthorized := sshkeys.ParseAuthorizedKeys(g.Data)
		secondAuthorized := sshkeys.ParseAuthorizedKeys(g.Data)
		if !reflect.DeepEqual(firstAuthorized, secondAuthorized) || !sshAuthorizedRecordsWhole(firstAuthorized) {
			t.Logf("authorized_keys parser returned nondeterministic or partial records: first=%+v second=%+v", firstAuthorized, secondAuthorized)
			return false
		}
		firstHosts := sshkeys.ParseKnownHosts(g.Data)
		secondHosts := sshkeys.ParseKnownHosts(g.Data)
		if !reflect.DeepEqual(firstHosts, secondHosts) || !sshKnownHostRecordsWhole(firstHosts) {
			t.Logf("known_hosts parser returned nondeterministic or partial records: first=%+v second=%+v", firstHosts, secondHosts)
			return false
		}
		maxRecords := bytes.Count(g.Data, []byte{'\n'}) + 1
		if len(firstAuthorized) > maxRecords || len(firstHosts) > maxRecords {
			t.Logf("SSH parser produced more records than input lines: authorized=%d known_hosts=%d max=%d", len(firstAuthorized), len(firstHosts), maxRecords)
			return false
		}

		firstPublic, firstErr := sshkeys.ParsePublicKey(g.Data)
		secondPublic, secondErr := sshkeys.ParsePublicKey(g.Data)
		if (firstErr == nil) != (secondErr == nil) || !reflect.DeepEqual(firstPublic, secondPublic) {
			t.Logf("public-key parser result changed between identical inputs: first=%+v/%v second=%+v/%v", firstPublic, firstErr, secondPublic, secondErr)
			return false
		}
		if firstErr == nil && (firstPublic.Type == "" || firstPublic.FingerprintSHA256 == "") {
			t.Logf("public-key parser accepted partial record: %+v", firstPublic)
			return false
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{
		MaxCount: 1000,
		Rand:     rand.New(rand.NewSource(sshPropertySeed + 1)), // #nosec G404 -- deterministic property-test stream, not security randomness (CWE-338)
	}); err != nil {
		t.Fatalf("SSH fail-closed parser property violated: %v", err)
	}
}

func sshPropertyKey(index uint8) (base, keyType, fingerprint string) {
	switch index % 3 {
	case 0:
		return strings.Join(strings.Fields(edPub)[:2], " "), "ssh-ed25519", edFP
	case 1:
		return strings.Join(strings.Fields(rsaPub)[:2], " "), "ssh-rsa", rsaFP
	default:
		return strings.Join(strings.Fields(ecPub)[:2], " "), "ecdsa-sha2-nistp256", ecFP
	}
}

func sshPropertyOptions(mask uint8) []string {
	var options []string
	if mask&1 != 0 {
		options = append(options, "no-pty")
	}
	if mask&2 != 0 {
		options = append(options, "restrict")
	}
	return options
}

func sshAuthorizedRecordsWhole(records []sshkeys.AuthorizedKey) bool {
	for _, record := range records {
		if record.Type == "" || record.FingerprintSHA256 == "" {
			return false
		}
	}
	return true
}

func sshKnownHostRecordsWhole(records []sshkeys.KnownHostKey) bool {
	for _, record := range records {
		if record.Type == "" || record.FingerprintSHA256 == "" || len(record.Hosts) == 0 {
			return false
		}
	}
	return true
}

func sshPropertyToken(r *rand.Rand, n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789_-"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

func minSSHProperty(a, b int) int {
	if a < b {
		return a
	}
	return b
}
