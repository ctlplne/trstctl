// SPDX-License-Identifier: BUSL-1.1

package custody_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/custody"
)

// A122: an appliance target opts into keys generated on the appliance with
// key_generation=appliance. Only a family whose connector can ask its
// appliance for a key may declare it, and the value must be exactly that
// string: anything else is refused rather than read as consent or ignored.
func TestKeyGenerationOnTheApplianceIsDeclaredExactly(t *testing.T) {
	t.Parallel()
	marked := []byte(`{"endpoint":"https://ns.example.test","key_generation":"appliance"}`)
	if !custody.TargetGeneratesKeyOnAppliance("netscaler", marked) {
		t.Fatal("a NetScaler target marked key_generation=appliance does not generate on the appliance")
	}
	if err := custody.ValidateKeyGeneration("netscaler", marked); err != nil {
		t.Fatalf("a NetScaler target marked key_generation=appliance was refused: %v", err)
	}
	for _, unmarked := range [][]byte{nil, []byte(`{}`), []byte(`{"key_generation":""}`), []byte(`not json`)} {
		if custody.TargetGeneratesKeyOnAppliance("netscaler", unmarked) {
			t.Fatalf("config %q generates on the appliance without saying so", unmarked)
		}
		if err := custody.ValidateKeyGeneration("netscaler", unmarked); err != nil {
			t.Fatalf("config %q without a declaration was refused: %v", unmarked, err)
		}
	}
	for name, tc := range map[string]struct {
		family string
		cfg    string
		want   string
	}{
		"a family that cannot":        {"kemp", `{"key_generation":"appliance"}`, "kemp"},
		"a host family":               {"nginx", `{"key_generation":"appliance"}`, "nginx"},
		"another value":               {"netscaler", `{"key_generation":"device"}`, `"appliance"`},
		"a boolean is not consent":    {"netscaler", `{"key_generation":true}`, "string"},
		"control plane is not a mode": {"netscaler", `{"key_generation":"control_plane"}`, `"appliance"`},
	} {
		if custody.TargetGeneratesKeyOnAppliance(tc.family, []byte(tc.cfg)) {
			t.Errorf("%s: generates on the appliance", name)
		}
		err := custody.ValidateKeyGeneration(tc.family, []byte(tc.cfg))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: ValidateKeyGeneration = %v, want a refusal naming %s", name, err, tc.want)
		}
	}
}
