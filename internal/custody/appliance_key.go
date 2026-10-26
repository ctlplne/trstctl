// SPDX-License-Identifier: BUSL-1.1

package custody

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/connector"
)

// KeyGenerationConfigKey is the deployment-target config key that chooses
// where an appliance target's subject key is generated (A122).
const KeyGenerationConfigKey = "key_generation"

// KeyGenerationAppliance asks the appliance itself to generate the subject key
// through its management API: a relay requests the key and a CSR, the control
// plane signs the CSR, and the key never leaves the appliance. Without it an
// appliance target keeps control-plane keys sealed to the deploy job.
const KeyGenerationAppliance = "appliance"

// TargetGeneratesKeyOnAppliance reports whether a target's subject key is
// generated on the appliance: the target declares key_generation=appliance
// and its family can ask its appliance for a key. Absent, unparseable or any
// other value means no, the same direction TargetExecutorIsAgent fails in.
func TargetGeneratesKeyOnAppliance(family string, cfg []byte) bool {
	value, err := targetKeyGeneration(cfg)
	return err == nil && value == KeyGenerationAppliance && connector.ApplianceKeyFamily(family)
}

// ValidateKeyGeneration refuses a key_generation declaration the target cannot
// honor, before the target is saved: a non-string value, a value other than
// "appliance", or a family whose connector cannot ask its appliance for a key.
// A target that declares nothing is not affected.
func ValidateKeyGeneration(family string, cfg []byte) error {
	value, err := targetKeyGeneration(cfg)
	if err != nil {
		return err
	}
	switch {
	case value == "":
		return nil
	case value != KeyGenerationAppliance:
		return fmt.Errorf("connector: %s %q is not a key generation mode; the only value is %q, which has the appliance generate the key",
			KeyGenerationConfigKey, value, KeyGenerationAppliance)
	case !connector.ApplianceKeyFamily(family):
		return fmt.Errorf("connector: a %s target cannot generate its key on the appliance; %s=%q is available for %s. "+
			"Remove it to keep control-plane keys sealed to the deploy",
			family, KeyGenerationConfigKey, KeyGenerationAppliance, strings.Join(connector.ApplianceKeyFamilies(), ", "))
	}
	return nil
}

// targetKeyGeneration reads the declared value. Absent, null and empty are no
// declaration; an unparseable config declares nothing (other validators refuse
// it); a value that is not a string is an error.
func targetKeyGeneration(cfg []byte) (string, error) {
	if len(cfg) == 0 {
		return "", nil
	}
	var fields map[string]any
	if err := json.Unmarshal(cfg, &fields); err != nil {
		return "", nil
	}
	raw, present := fields[KeyGenerationConfigKey]
	if !present || raw == nil {
		return "", nil
	}
	value, ok := raw.(string)
	if !ok {
		return "", errors.New("connector: key_generation must be a string")
	}
	return strings.TrimSpace(value), nil
}
