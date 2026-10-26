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
// and the declaration is one the target can honor. Absent, unparseable, any
// other value or a refused declaration means no, the same direction
// TargetExecutorIsAgent fails in.
func TargetGeneratesKeyOnAppliance(family string, cfg []byte) bool {
	value, err := targetKeyGeneration(cfg)
	return err == nil && value == KeyGenerationAppliance && ValidateKeyGeneration(family, cfg) == nil
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
	case family == "f5" && configString(cfg, "peer_endpoint") != "":
		// Each BIG-IP of a pair keeps its own crypto objects, so each would
		// generate its own key, and one certificate cannot carry two keys.
		return fmt.Errorf("connector: an F5 HA pair cannot generate its key on the appliance: each peer would hold a different "+
			"key for one certificate. Remove %s to keep control-plane keys sealed to the deploy, which reaches both peers",
			KeyGenerationConfigKey)
	case family == "cisco" && (configString(cfg, "node_hostname") == "" || !configHasList(cfg, "certificate_roles")):
		// ISE generates the request on a node and binds it to roles; a target
		// without them has nowhere to generate or bind.
		return fmt.Errorf("connector: a Cisco ISE target generates its key on the node only with node_hostname and "+
			"certificate_roles set: ISE makes the request on that node and binds the signed certificate to those roles. "+
			"Set both, or remove %s to keep control-plane keys sealed to the deploy", KeyGenerationConfigKey)
	case family == "paloalto" && (configString(cfg, "ssl_tls_profile") == "" || configString(cfg, "commit_admin") == ""):
		// The firewall's certificate object is installed by pointing the
		// SSL/TLS service profile at it in a partial commit; the in-place
		// import has nothing to point.
		return fmt.Errorf("connector: a Palo Alto target generates its key on the firewall only with ssl_tls_profile and "+
			"commit_admin set, because the certificate the firewall makes is installed by binding that SSL/TLS service "+
			"profile in that administrator's partial commit. Set both, or remove %s to keep control-plane keys sealed to the deploy",
			KeyGenerationConfigKey)
	}
	return nil
}

// configString reads a string field of a target config, or "" when it is
// absent, empty or not a string.
func configString(cfg []byte, key string) string {
	var fields map[string]any
	if json.Unmarshal(cfg, &fields) != nil {
		return ""
	}
	value, _ := fields[key].(string)
	return strings.TrimSpace(value)
}

// configHasList reports whether a target config field is a non-empty list.
func configHasList(cfg []byte, key string) bool {
	var fields map[string]any
	if json.Unmarshal(cfg, &fields) != nil {
		return false
	}
	list, _ := fields[key].([]any)
	return len(list) > 0
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
