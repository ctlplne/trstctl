// SPDX-License-Identifier: BUSL-1.1

package switchkit

import (
	"strings"
	"testing"
)

func TestMapRejectsExpiryOutsidePostgresTimestampWindow(t *testing.T) {
	for _, input := range []string{
		"0000-01-01",
		"0001-01-01T00:00:00+14:00", // UTC crosses into year 0000.
		"9999-12-31T23:59:59-14:00", // UTC crosses beyond JSON's year 9999.
	} {
		rows, err := Parse([]byte("fingerprint_sha256,not_after\n"+fingerprintOf(1)+","+input+"\n"), nil)
		if err != nil {
			t.Fatal(err)
		}
		report := Map(rows, nil, now)
		item := report.Items[0]
		if item.Outcome != OutcomeUnparseable || !item.NotAfter.IsZero() || !strings.Contains(item.Reason, "not_after") {
			t.Fatalf("not_after %q mapped as %+v", input, item)
		}
	}
}
