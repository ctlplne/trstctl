// SPDX-License-Identifier: MPL-2.0

package dependencyobs

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestObservationParsersAgree(t *testing.T) {
	t.Parallel()
	fields := map[string]string{
		"workload": " checkout-service ",
		"target":   " lb-edge ",
		"protocol": " https ",
		"host":     " relay-a ",
	}
	fromMap, err := ParseMap(fields, "lb-edge")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	fromJSON, err := ParseJSON(raw, "lb-edge")
	if err != nil {
		t.Fatal(err)
	}
	if fromMap != fromJSON || fromMap.Workload != "checkout-service" || fromMap.Target != "lb-edge" {
		t.Fatalf("map=%+v json=%+v", fromMap, fromJSON)
	}
}

func TestObservationParsersFailClosed(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]json.RawMessage{
		"unknown field":    json.RawMessage(`{"workload":"checkout","target":"lb","credential":"secret"}`),
		"missing workload": json.RawMessage(`{"target":"lb"}`),
		"mismatch":         json.RawMessage(`{"workload":"checkout","target":"other"}`),
		"trailing value":   json.RawMessage(`{"workload":"checkout","target":"lb"} {}`),
		"oversized":        json.RawMessage(`{"workload":"` + strings.Repeat("x", maxFieldBytes+1) + `","target":"lb"}`),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseJSON(raw, "lb"); err == nil {
				t.Fatal("invalid dependency observation was accepted")
			}
		})
	}
	if _, err := ParseMap(map[string]string{"workload": "checkout", "target": "lb", "credential": "secret"}, "lb"); err == nil {
		t.Fatal("unknown pre-JSON metadata field was accepted")
	}
}

func FuzzParseJSON(f *testing.F) {
	f.Add([]byte(`{"workload":"checkout","target":"lb","protocol":"https"}`), "lb")
	f.Add([]byte(`{"workload":"checkout","target":"other"}`), "lb")
	f.Add([]byte(`{`), "lb")
	f.Fuzz(func(t *testing.T, raw []byte, ref string) {
		observation, err := ParseJSON(raw, ref)
		if err != nil {
			return
		}
		if observation.Workload == "" || observation.Target == "" || observation.Target != strings.TrimSpace(ref) {
			t.Fatalf("accepted invalid observation=%+v ref=%q", observation, ref)
		}
	})
}
