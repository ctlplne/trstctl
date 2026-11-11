// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"
	"time"
)

// N4-L2: a trail is read from the day its oldest decoy was created through
// today, oldest first, at most awsHoneyTrailMaxDays back; and a trail's last
// day read in full only moves forward.
func TestAWSHoneyTrailDayRangeN4L2(t *testing.T) {
	now := time.Date(2026, 11, 11, 9, 30, 0, 0, time.UTC)
	today := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		since time.Time
		days  int
		first time.Time
	}{
		"five days ago":   {now.Add(-5*24*time.Hour - time.Hour), 6, today.AddDate(0, 0, -5)},
		"today":           {now.Add(-time.Hour), 1, today},
		"in the future":   {now.Add(48 * time.Hour), 1, today},
		"beyond the cap":  {now.AddDate(-1, 0, 0), awsHoneyTrailMaxDays + 1, today.AddDate(0, 0, -awsHoneyTrailMaxDays)},
		"a local offset":  {time.Date(2026, 11, 10, 23, 30, 0, 0, time.FixedZone("west", -5*3600)), 1, today},
		"start of a day":  {today.AddDate(0, 0, -2), 3, today.AddDate(0, 0, -2)},
		"end of a day":    {today.AddDate(0, 0, -1).Add(-time.Nanosecond), 3, today.AddDate(0, 0, -2)},
		"exactly the cap": {today.AddDate(0, 0, -awsHoneyTrailMaxDays), awsHoneyTrailMaxDays + 1, today.AddDate(0, 0, -awsHoneyTrailMaxDays)},
	} {
		days := awsHoneyTrailDayRange(tc.since, now)
		if len(days) != tc.days || !days[0].Equal(tc.first) || !days[len(days)-1].Equal(today) {
			t.Errorf("%s: %d days from %v to %v, want %d from %v to %v", name, len(days), days[0], days[len(days)-1], tc.days, tc.first, today)
		}
		for i := 1; i < len(days); i++ {
			if !days[i].Equal(days[i-1].AddDate(0, 0, 1)) {
				t.Fatalf("%s: days are not consecutive and oldest first: %v", name, days)
			}
		}
	}
	var read awsHoneyTrailDays
	read.record("k", today.AddDate(0, 0, -3))
	read.record("k", today.AddDate(0, 0, -5))
	if through, ok := read.readThrough("k"); !ok || !through.Equal(today.AddDate(0, 0, -3)) {
		t.Fatalf("read through = %v %v, want three days ago", through, ok)
	}
}
