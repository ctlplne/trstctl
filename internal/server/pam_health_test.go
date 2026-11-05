// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// A258: each account's slot is fixed by its name, lands within one interval
// of any moment, and the slots of many accounts spread over the interval.
func TestPAMHealthSlotsSpreadAndStayFixedA258(t *testing.T) {
	const interval = time.Hour
	start := time.Date(2026, 11, 4, 22, 0, 0, 0, time.UTC)
	buckets := map[int]bool{}
	for i := 0; i < 200; i++ {
		a := pamHealthAccount{tenantID: "t", targetType: "mysql", targetID: "db-" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + time.Duration(i).String()}
		first := pamHealthSlot(a, start, interval)
		if !first.After(start) || first.Sub(start) > interval {
			t.Fatalf("slot %s is not within one interval after %s", first, start)
		}
		if again := pamHealthSlot(a, start.Add(17*time.Minute), interval); (again.Sub(first) % interval) != 0 {
			t.Fatalf("an account's slots are not on one grid: %s then %s", first, again)
		}
		if next := pamHealthSlot(a, first, interval); next.Sub(first) != interval {
			t.Fatalf("the slot after %s is %s, want one interval later", first, next)
		}
		buckets[int(first.Sub(start)/(interval/10))] = true
	}
	if len(buckets) < 9 {
		t.Fatalf("200 accounts' slots fell in %d of 10 tenths of the interval", len(buckets))
	}
}

// A258: the credential digest covers every reference a provider
// configuration names, so a change to any of them is a new credential.
func TestProviderCredentialRefsCoverEveryRefA258(t *testing.T) {
	cfg := config.DynamicSecretProviderConfig{}
	v := reflect.ValueOf(&cfg).Elem()
	var want []string
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		if f.Type.Kind() == reflect.String && strings.HasSuffix(f.Name, "Ref") {
			v.Field(i).SetString("file:/" + f.Name)
			want = append(want, f.Name)
		}
	}
	if len(want) < 8 {
		t.Fatalf("found %d credential reference fields; the configuration changed shape", len(want))
	}
	refs := strings.Join(providerCredentialRefs(cfg), "\n")
	for _, name := range append(want, "AdminDSNRef", "PasswordRef", "BearerTokenRef") {
		if !strings.Contains(refs, name+"=file:/"+name) {
			t.Fatalf("the digest misses %s:\n%s", name, refs)
		}
	}
}
