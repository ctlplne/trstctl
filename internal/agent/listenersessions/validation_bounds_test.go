// SPDX-License-Identifier: BUSL-1.1

package listenersessions

import (
	"math"
	"strconv"
	"testing"
)

func TestObservationRejectsCountsUnprojectableByPostgres(t *testing.T) {
	if strconv.IntSize == 32 {
		t.Skip("Go int cannot exceed PostgreSQL integer on a 32-bit platform")
	}
	base := Observation{Port: 443, Established: 1, HeldByOlder: 1, SinceUnix: 10, CheckedAtUnix: 10}
	tooLarge := int(int64(math.MaxInt32) + 1)
	for name, change := range map[string]func(*Observation){
		"established":   func(o *Observation) { o.Established = tooLarge },
		"held_by_older": func(o *Observation) { o.Established, o.HeldByOlder = tooLarge, tooLarge },
		"unattributed":  func(o *Observation) { o.Established, o.HeldByOlder, o.Unattributed = tooLarge, 0, tooLarge },
		"overflow":      func(o *Observation) { o.Established, o.HeldByOlder, o.Unattributed = math.MaxInt, math.MaxInt, 1 },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			change(&value)
			if value.Valid() {
				t.Fatalf("accepted unprojectable session count: %+v", value)
			}
		})
	}
}

func TestObservationRejectsUnprojectableTime(t *testing.T) {
	base := Observation{Port: 443, SinceUnix: 10, CheckedAtUnix: 10}
	for name, change := range map[string]func(*Observation){
		"before year one": func(o *Observation) { o.SinceUnix = -62135596801 },
		"after year 9999": func(o *Observation) { o.CheckedAtUnix = 253402300800 },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			change(&value)
			if value.Valid() {
				t.Fatalf("accepted unprojectable session time: %+v", value)
			}
		})
	}
}
