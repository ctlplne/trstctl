// SPDX-License-Identifier: BUSL-1.1

package lifecycle

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Maintenance windows: when a renewal is allowed to touch production (epic D6).
//
// A certificate renewal is not a passive event. It deploys to a listener and
// reloads a service, and there are hours in every organization's week when
// nobody wants that to happen unattended — a trading window, a month-end close,
// a change freeze. Before this, the scheduler renewed whenever the certificate
// was due and an operator's only control was to turn renewal off entirely,
// which trades an outage risk for an expiry risk.
//
// The design rule that matters most: a window DEFERS work, it never drops it.
// A renewal that cannot run now is still due, and the deferral carries a reason
// an operator can read. Silently skipping would turn a change-freeze into an
// expiry, which is the more expensive of the two failures by a wide margin — and
// it would look exactly like the scheduler working correctly.

var (
	errWindowEmpty    = errors.New("lifecycle: maintenance window spec is empty")
	errWindowNoTime   = errors.New("lifecycle: maintenance window names days but no time range")
	errWindowBadDay   = errors.New("lifecycle: maintenance window names an unrecognized weekday")
	errWindowBadRange = errors.New("lifecycle: maintenance window time range must be HH:MM-HH:MM")
	errWindowBadClock = errors.New("lifecycle: maintenance window time is not a valid HH:MM")
)

// Window is one recurring period during which renewals may run.
//
// Expressed in local weekday/hour terms rather than as absolute instants,
// because that is how organizations actually describe change windows ("weekends
// and weeknights after 8pm"), and an absolute schedule would need regenerating
// forever.
type Window struct {
	// Days are the weekdays this window covers. Empty means every day.
	Days []time.Weekday
	// StartMinute and EndMinute are minutes past local midnight. A window whose
	// end is before its start wraps midnight — 22:00–06:00 is one window, not a
	// configuration error, and treating it as one would exclude exactly the
	// hours most operators want.
	StartMinute int
	EndMinute   int
	// Location is the timezone the window is expressed in. Nil means UTC.
	//
	// Named rather than a fixed offset, so a window follows daylight saving the
	// way the humans who wrote it expect. A fixed offset would drift an hour
	// twice a year and the drift would land in the small hours, where nobody
	// would notice until something renewed during a freeze.
	Location *time.Location
}

// Allows reports whether t falls inside this window.
//
// Day and time are decided TOGETHER, not independently, and that is the whole
// subtlety of a wrapping window. "Fri 22:00-06:00" means Friday evening and the
// small hours of Saturday — it does not mean Saturday evening. Checking "is
// today a covered day" and "is now a covered minute" as separate questions
// admits exactly that: Saturday passes the day test as Friday's spillover, and
// 23:00 passes the minute test as the evening half, so a Friday-only window
// silently runs on Saturday night too.
//
// So a wrapping window is two half-open pieces: the evening belongs to the day
// the window OPENED on, and the morning belongs to the day before it.
func (w Window) Allows(t time.Time) bool {
	loc := w.Location
	if loc == nil {
		loc = time.UTC
	}
	local := t.In(loc)
	day := local.Weekday()
	minute := local.Hour()*60 + local.Minute()

	if !w.wraps() {
		if !w.namesDay(day) {
			return false
		}
		return minute >= w.StartMinute && minute < w.EndMinute
	}
	// Evening half: the window opened today.
	if minute >= w.StartMinute && w.namesDay(day) {
		return true
	}
	// Morning half: the window opened yesterday and is still running.
	return minute < w.EndMinute && w.namesDay((day+6)%7)
}

func (w Window) wraps() bool { return w.EndMinute <= w.StartMinute }

// namesDay reports whether the window's day list includes this weekday. An
// empty list means every day.
func (w Window) namesDay(day time.Weekday) bool {
	if len(w.Days) == 0 {
		return true
	}
	for _, d := range w.Days {
		if d == day {
			return true
		}
	}
	return false
}

// WindowSet is every window that applies to a piece of work.
//
// Empty means UNRESTRICTED, not "never". An operator who has configured no
// windows has not asked for a freeze, and defaulting to closed would stop every
// renewal in every deployment that has not opted in — turning a new feature
// into a fleet-wide outage.
type WindowSet []Window

// Allows reports whether any window admits t. An empty set always allows.
func (s WindowSet) Allows(t time.Time) bool {
	if len(s) == 0 {
		return true
	}
	for _, w := range s {
		if w.Allows(t) {
			return true
		}
	}
	return false
}

// NextOpen returns when the set next admits work, searching forward from t.
//
// Bounded to a week: every window in this model is weekly, so a set that has
// not opened within seven days never will, and reporting that plainly beats
// looping. The zero time means "never opens" and the caller renders it as a
// misconfiguration rather than as a long wait.
func (s WindowSet) NextOpen(t time.Time) time.Time {
	if len(s) == 0 {
		return t
	}
	// Minute granularity: windows are expressed in minutes, so a finer search
	// would cost more and find the same answer.
	probe := t.Truncate(time.Minute)
	for i := 0; i < 7*24*60; i++ {
		if s.Allows(probe) {
			return probe
		}
		probe = probe.Add(time.Minute)
	}
	return time.Time{}
}

// DeferralReason explains, in one operator-readable line, why work is held.
//
// It names the next opening rather than only the closure, because "not now" is
// not actionable and "not until Saturday 22:00" is. A window that never opens
// says so, which is a configuration error worth surfacing as one.
func (s WindowSet) DeferralReason(t time.Time) string {
	if s.Allows(t) {
		return ""
	}
	next := s.NextOpen(t)
	if next.IsZero() {
		return "maintenance window never opens; renewal is held indefinitely and the window " +
			"configuration needs correcting"
	}
	loc := time.UTC
	if len(s) > 0 && s[0].Location != nil {
		loc = s[0].Location
	}
	return "outside the maintenance window; next opens " + next.In(loc).Format("Mon 15:04 MST")
}

// ParseWindow reads a window from the compact form operators write in config:
//
//	"Mon,Tue,Wed,Thu,Fri 22:00-06:00 Europe/London"
//	"Sat,Sun 00:00-23:59"
//	"22:00-06:00"            (every day, UTC)
//
// Deliberately small. A cron expression would be more general and less
// readable, and the thing being expressed — "when may this touch production" —
// is something a change-advisory board should be able to read without learning
// a syntax.
func ParseWindow(spec string) (Window, error) {
	fields := strings.Fields(strings.TrimSpace(spec))
	if len(fields) == 0 {
		return Window{}, errWindowEmpty
	}
	var w Window
	timeField := fields[0]
	if strings.Contains(fields[0], ",") || !strings.Contains(fields[0], ":") {
		days, err := parseWeekdays(fields[0])
		if err != nil {
			return Window{}, err
		}
		w.Days = days
		if len(fields) < 2 {
			return Window{}, errWindowNoTime
		}
		timeField = fields[1]
		fields = fields[1:]
	}
	start, end, err := parseTimeRange(timeField)
	if err != nil {
		return Window{}, err
	}
	w.StartMinute, w.EndMinute = start, end
	if len(fields) > 1 {
		loc, lerr := time.LoadLocation(fields[1])
		if lerr != nil {
			return Window{}, lerr
		}
		w.Location = loc
	}
	return w, nil
}

func parseWeekdays(field string) ([]time.Weekday, error) {
	names := map[string]time.Weekday{
		"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday,
		"wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday,
		"sat": time.Saturday,
	}
	var out []time.Weekday
	seen := map[time.Weekday]bool{}
	for _, part := range strings.Split(field, ",") {
		key := strings.ToLower(strings.TrimSpace(part))
		if len(key) > 3 {
			key = key[:3]
		}
		day, ok := names[key]
		if !ok {
			return nil, errWindowBadDay
		}
		if !seen[day] {
			seen[day] = true
			out = append(out, day)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func parseTimeRange(field string) (start, end int, err error) {
	lo, hi, ok := strings.Cut(field, "-")
	if !ok {
		return 0, 0, errWindowBadRange
	}
	start, err = parseClock(lo)
	if err != nil {
		return 0, 0, err
	}
	end, err = parseClock(hi)
	if err != nil {
		return 0, 0, err
	}
	return start, end, nil
}

func parseClock(v string) (int, error) {
	h, m, ok := strings.Cut(strings.TrimSpace(v), ":")
	if !ok {
		return 0, errWindowBadClock
	}
	hour, err := strconv.Atoi(h)
	if err != nil || hour < 0 || hour > 23 {
		return 0, errWindowBadClock
	}
	minute, err := strconv.Atoi(m)
	if err != nil || minute < 0 || minute > 59 {
		return 0, errWindowBadClock
	}
	return hour*60 + minute, nil
}
