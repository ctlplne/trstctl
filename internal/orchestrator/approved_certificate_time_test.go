// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"testing"
	"time"
)

func TestApprovedCertificateEventTimeIsPostgresExact(t *testing.T) {
	input := time.Unix(1_780_000_000, 123_456_789).In(time.FixedZone("fixture", -5*60*60))
	got := approvedCertificateEventTime(input)
	want := time.Unix(1_780_000_000, 123_456_000).UTC()
	if !got.Equal(want) || got.Location() != time.UTC {
		t.Fatalf("approved certificate event time = %s (%s), want %s (UTC)", got, got.Location(), want)
	}
}
