// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bytes"
	"context"
	"testing"
	"trstctl.com/trstctl/internal/accessrules"
)

func TestMySQLRuleQueryExcludesQueryAttributeValues(t *testing.T) {
	raw := []byte("DELETE FROM notes")
	got, ok := mysqlRuleQuery(raw, false)
	if !ok || !bytes.Equal(got, raw) {
		t.Fatal("ordinary SQL changed")
	}
	got, ok = mysqlRuleQuery(append([]byte{0, 1}, raw...), true)
	if !ok || !bytes.Equal(got, raw) {
		t.Fatal("empty query attribute envelope changed SQL")
	}
	for _, bad := range [][]byte{{}, {0}, {0, 2}, {1, 1, 0, 1, 0xfd, 0, 3, 'k', 'e', 'y', 5, 'v', 'a', 'l', 'u', 'e'}, {0xfc, 0, 0}} {
		if _, ok := mysqlRuleQuery(bad, true); ok {
			t.Fatal("attribute values or malformed envelope reached classifier")
		}
	}
}

func FuzzMySQLRuleQueryEnvelope(f *testing.F) {
	f.Add([]byte{0, 1, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'}, true)
	f.Add([]byte("DELETE FROM notes"), false)
	f.Fuzz(func(t *testing.T, raw []byte, attributes bool) {
		var header [4]byte
		copy(header[:], raw)
		size, valid := mysqlGuardedFrameSize(header)
		if valid && (size < 1 || size > accessrules.MaxStatementBytes+1) {
			t.Fatal("unbounded header accepted")
		}
		before := bytes.Clone(raw)
		got, ok := mysqlRuleQuery(raw, attributes)
		if !bytes.Equal(before, raw) {
			t.Fatal("framing changed bytes")
		}
		if ok && (len(got) > len(raw) || !bytes.HasSuffix(raw, got)) {
			t.Fatal("framing invented SQL bytes")
		}
	})
}

func TestMySQLCredentialSwitchNeverEntersCommandPolicy(t *testing.T) {
	var target bytes.Buffer
	frame := mysqlCommandFrame{payload: []byte{mysqlComChangeUser, 'u', 0, 1, 'p'}}
	err := forwardMySQLCommand(context.Background(), &target, &mysqlRelay{}, &commandConnection{}, frame)
	if err == nil || target.Len() != 0 {
		t.Fatal("credential-switch bytes entered command evaluation or target forwarding")
	}
	for _, tc := range []struct {
		header [4]byte
		valid  bool
	}{{[4]byte{}, false}, {[4]byte{1, 0, 0, 0}, true}, {[4]byte{1, 0, 16, 0}, true}, {[4]byte{2, 0, 16, 0}, false}, {[4]byte{255, 255, 255, 0}, false}} {
		_, valid := mysqlGuardedFrameSize(tc.header)
		if valid != tc.valid {
			t.Fatal("guarded frame bound changed")
		}
	}
}
