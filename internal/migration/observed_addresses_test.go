// SPDX-License-Identifier: BUSL-1.1

package migration

import (
	"encoding/json"
	"strings"
	"testing"
)

// X3-L2: a deployment target names where an observer sees its traffic behind
// NAT or a load balancer; anything but a short list of host:port is refused.
func TestObservedAddressesX3L2(t *testing.T) {
	t.Parallel()
	got, err := ObservedAddresses(json.RawMessage(`{"verify_address":"vip.example.test:443","observed_addresses":[" 10.0.3.17:8443 ","[fd00::7]:8443"]}`))
	if err != nil || strings.Join(got, ",") != "10.0.3.17:8443,[fd00::7]:8443" {
		t.Fatalf("observed addresses = %v %v", got, err)
	}
	for _, none := range []string{`{}`, `{"observed_addresses":null}`, `{"observed_addresses":[]}`, ``} {
		if got, err := ObservedAddresses(json.RawMessage(none)); err != nil || got != nil {
			t.Fatalf("%q = %v %v; want none", none, got, err)
		}
	}
	tooMany := make([]string, MaxObservedAddresses+1)
	for i := range tooMany {
		tooMany[i] = "10.0.0.1:" + string(rune('1'+i%9)) + "443"
	}
	many, err := json.Marshal(map[string]any{"observed_addresses": tooMany})
	if err != nil {
		t.Fatal(err)
	}
	for name, config := range map[string]string{
		"not a list":   `{"observed_addresses":"10.0.3.17:8443"}`,
		"no port":      `{"observed_addresses":["10.0.3.17"]}`,
		"port 0":       `{"observed_addresses":["10.0.3.17:0"]}`,
		"port 70000":   `{"observed_addresses":["10.0.3.17:70000"]}`,
		"no host":      `{"observed_addresses":[":8443"]}`,
		"listed twice": `{"observed_addresses":["10.0.3.17:8443","10.0.3.17:8443"]}`,
		"too many":     string(many),
	} {
		if got, err := ObservedAddresses(json.RawMessage(config)); err == nil {
			t.Fatalf("%s: %v accepted", name, got)
		}
	}
}
