// SPDX-License-Identifier: BUSL-1.1

package pluginhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// HostAPIVersion is the connector ABI this host implements. A module's
// manifest names the range it supports; a host outside it refuses the module.
const HostAPIVersion = 1

// MaxMemoryPages bounds any module's linear memory (64 KiB pages: 256 MiB),
// whatever its manifest asks for.
const MaxMemoryPages = 4096

// Manifest is what a connector module's publisher declares beside the module
// (A242): its name and version, the host ABI range it supports, the
// permissions it asks for, its actions and how it behaves on retry and
// revocation, the inputs a setup form asks the operator for, and its resource
// limits. It is signed with the key that signed the module, and names the
// module's SHA-256, so a manifest speaks for exactly one build.
//
// A manifest only ever NARROWS what a module may do. The operator's grant on
// the relay is the ceiling: a manifest that asks for a capability or a
// resource outside it is refused, never granted. And a version that asks for
// more than the version an operator approved waits for a new approval
// (PermissionDiff).
type Manifest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// ModuleSHA256 is the lowercase hex SHA-256 of the module it describes.
	ModuleSHA256 string `json:"module_sha256"`
	// HostAPI is the inclusive ABI range the module supports.
	HostAPI struct {
		Min int `json:"min"`
		Max int `json:"max"`
	} `json:"host_api"`
	Permissions Permissions `json:"permissions"`
	// Actions are the entry points the module implements: deploy, test,
	// rollback, readback, revoke.
	Actions []string `json:"actions"`
	// Idempotency says how a retried deploy converges: replace-by-name (the
	// same object is overwritten, so a retry is safe), create-new (each
	// attempt makes a new object) or read-before-write (the module reads the
	// target first). The last two need a readback action: before retrying,
	// the host asks it whether the earlier attempt already landed.
	Idempotency string `json:"idempotency"`
	// Revocation says what revoke does at the target: delete, unbind or none.
	Revocation string          `json:"revocation"`
	Inputs     []ManifestInput `json:"inputs,omitempty"`
	Limits     struct {
		MemoryPages uint32 `json:"memory_pages,omitempty"`
		TimeoutMS   int    `json:"timeout_ms,omitempty"`
	} `json:"limits"`
}

// Permissions are the capabilities a module asks for, each with the
// resources it needs (paths for fs.*, host:port authorities for net.*), and
// how the host may add the target's credential to its requests: "basic",
// "bearer" or "header:<Name>". A module that names no credential mode gets
// none.
type Permissions struct {
	Capabilities []string            `json:"capabilities"`
	Resources    map[string][]string `json:"resources,omitempty"`
	Credentials  []string            `json:"credentials,omitempty"`
}

// ManifestInput is one field of the module's setup form.
type ManifestInput struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required,omitempty"`
	Secret      bool   `json:"secret,omitempty"`
	Description string `json:"description,omitempty"`
}

var (
	manifestName    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	manifestVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
	manifestDigest  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	manifestField   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	manifestActions = map[string]bool{"deploy": true, "test": true, "rollback": true, "readback": true, "revoke": true}
	idempotencies   = map[string]bool{"replace-by-name": true, "create-new": true, "read-before-write": true}
	revocations     = map[string]bool{"delete": true, "unbind": true, "none": true}
	inputTypes      = map[string]bool{"string": true, "integer": true, "boolean": true}
	knownCaps       = map[Capability]bool{CapFSRead: true, CapFSWrite: true, CapNetDial: true, CapInputRead: true, CapHTTP: true}
)

// ParseManifest reads a manifest strictly: unknown fields, a malformed name
// or version, an unknown action, capability, behaviour or input type, and
// limits beyond the host's are all refused.
func ParseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("pluginhost: manifest: %w", err)
	}
	if dec.More() {
		return Manifest{}, errors.New("pluginhost: manifest: trailing data")
	}
	switch {
	case !manifestName.MatchString(m.Name):
		return Manifest{}, errors.New("pluginhost: manifest name is lower-case letters, digits, _ and -")
	case !manifestVersion.MatchString(m.Version):
		return Manifest{}, errors.New("pluginhost: manifest version is MAJOR.MINOR.PATCH")
	case !manifestDigest.MatchString(m.ModuleSHA256):
		return Manifest{}, errors.New("pluginhost: manifest module_sha256 is the module's lowercase hex SHA-256")
	case m.HostAPI.Min < 1 || m.HostAPI.Max < m.HostAPI.Min:
		return Manifest{}, errors.New("pluginhost: manifest host_api is a range min..max of ABI versions, min at least 1")
	case !idempotencies[m.Idempotency]:
		return Manifest{}, errors.New("pluginhost: manifest idempotency is replace-by-name, create-new or read-before-write")
	case !revocations[m.Revocation]:
		return Manifest{}, errors.New("pluginhost: manifest revocation is delete, unbind or none")
	case m.Limits.MemoryPages > MaxMemoryPages:
		return Manifest{}, fmt.Errorf("pluginhost: manifest memory_pages is at most %d", MaxMemoryPages)
	case m.Limits.TimeoutMS < 0 || m.Limits.TimeoutMS > int(maxPluginCallDuration.Milliseconds()):
		return Manifest{}, fmt.Errorf("pluginhost: manifest timeout_ms is at most %d", maxPluginCallDuration.Milliseconds())
	}
	if len(m.Actions) == 0 || !slices.Contains(m.Actions, "deploy") {
		return Manifest{}, errors.New("pluginhost: manifest actions must include deploy")
	}
	for _, action := range m.Actions {
		if !manifestActions[action] {
			return Manifest{}, fmt.Errorf("pluginhost: manifest action %q is not deploy, test, rollback, readback or revoke", action)
		}
	}
	if m.Idempotency != "replace-by-name" && !slices.Contains(m.Actions, "readback") {
		return Manifest{}, fmt.Errorf("pluginhost: a %s module needs a readback action, so a retry can ask whether the earlier attempt landed", m.Idempotency)
	}
	for _, c := range m.Permissions.Capabilities {
		if !knownCaps[Capability(c)] {
			return Manifest{}, fmt.Errorf("pluginhost: manifest capability %q is unknown", c)
		}
	}
	for c, resources := range m.Permissions.Resources {
		if !slices.Contains(m.Permissions.Capabilities, c) {
			return Manifest{}, fmt.Errorf("pluginhost: manifest resources name %q, which it does not ask for", c)
		}
		for _, r := range resources {
			if strings.TrimSpace(r) == "" {
				return Manifest{}, fmt.Errorf("pluginhost: manifest resource for %q is empty", c)
			}
		}
	}
	for _, mode := range m.Permissions.Credentials {
		if _, ok := CanonicalCredentialMode(mode); !ok {
			return Manifest{}, fmt.Errorf("pluginhost: manifest credential %q is not basic, bearer or header:<Name>", mode)
		}
	}
	for _, in := range m.Inputs {
		if !manifestField.MatchString(in.Name) || !inputTypes[in.Type] {
			return Manifest{}, fmt.Errorf("pluginhost: manifest input %q needs a field name and a type of string, integer or boolean", in.Name)
		}
	}
	return m, nil
}

// SupportsHost reports whether the module runs on this host's ABI.
func (m Manifest) SupportsHost() bool {
	return m.HostAPI.Min <= HostAPIVersion && HostAPIVersion <= m.HostAPI.Max
}

// Has reports whether the module implements action.
func (m Manifest) Has(action string) bool { return slices.Contains(m.Actions, action) }

// ResourceLimits are the limits the manifest asks for; LoadVerifiedModule
// fills in the defaults.
func (m Manifest) ResourceLimits() Limits {
	return Limits{MemoryPages: m.Limits.MemoryPages, Timeout: time.Duration(m.Limits.TimeoutMS) * time.Millisecond}
}

// EffectiveGrant is the grant a module runs under: exactly what its manifest
// asks for, which must lie inside the operator's grant. A capability the
// operator did not grant, a resource outside the operator's constraint for
// it, or a credential mode the operator's grant does not allow refuses the
// module rather than being dropped; a capability the manifest names without
// resources takes the operator's constraints.
func EffectiveGrant(operator Grant, m Manifest) (Grant, error) {
	effective := NewGrant()
	for _, name := range m.Permissions.Capabilities {
		c := Capability(name)
		if !operator.Has(c) {
			return Grant{}, fmt.Errorf("pluginhost: %s asks for %s, which this host's grant does not give", m.Name, c)
		}
		effective.caps[c] = true
		resources := m.Permissions.Resources[name]
		if len(resources) == 0 {
			for _, p := range operator.PathPrefixes(c) {
				effective = effective.WithPathPrefix(c, p)
			}
			continue
		}
		for _, r := range resources {
			if !operator.Allows(c, r) {
				return Grant{}, fmt.Errorf("pluginhost: %s asks for %s on %q, outside this host's grant", m.Name, c, r)
			}
			effective = effective.WithPathPrefix(c, r)
		}
	}
	for _, mode := range m.Permissions.Credentials {
		c, _ := CanonicalCredentialMode(mode)
		if !operator.AllowsCredential(credentialRequest(c)) {
			return Grant{}, fmt.Errorf("pluginhost: %s asks for %s credentials, which this host's grant does not give", m.Name, c)
		}
	}
	return effective.WithCredentials(m.Permissions.Credentials...), nil
}

// credentialRequest turns a canonical credential mode back into the auth and
// header an HTTPRequest names.
func credentialRequest(mode string) (auth, header string) {
	if name, ok := strings.CutPrefix(mode, "header:"); ok {
		return "header", name
	}
	return mode, ""
}

// PermissionsDigest is the SHA-256 of a manifest's permissions in canonical
// form (sorted), what an approval records.
func (m Manifest) PermissionsDigest() string {
	return crypto.SHA256Hex(canonicalPermissions(m.Permissions))
}

func canonicalPermissions(p Permissions) []byte {
	caps := append([]string(nil), p.Capabilities...)
	sort.Strings(caps)
	resources := map[string][]string{}
	for c, rs := range p.Resources {
		sorted := append([]string(nil), rs...)
		sort.Strings(sorted)
		resources[c] = sorted
	}
	creds := make([]string, 0, len(p.Credentials))
	for _, mode := range p.Credentials {
		if c, ok := CanonicalCredentialMode(mode); ok {
			creds = append(creds, c)
		}
	}
	sort.Strings(creds)
	raw, _ := json.Marshal(struct {
		Capabilities []string            `json:"capabilities"`
		Resources    map[string][]string `json:"resources"`
		Credentials  []string            `json:"credentials"`
	}{caps, resources, creds})
	return raw
}

// PermissionDiff lists what requested asks for beyond approved: each added
// capability, resource and credential field, as "capability net.http",
// "resource net.http=api.example:443" or "credential basic". Empty means
// requested is within approved (an upgrade that narrows needs no review).
func PermissionDiff(approved, requested Permissions) []string {
	var added []string
	for _, c := range requested.Capabilities {
		if !slices.Contains(approved.Capabilities, c) {
			added = append(added, "capability "+c)
		}
	}
	for c, rs := range requested.Resources {
		approvedResources, constrained := approved.Resources[c]
		if !constrained && slices.Contains(approved.Capabilities, c) {
			continue // the approval left this capability unconstrained
		}
		for _, r := range rs {
			if !slices.Contains(approvedResources, r) {
				added = append(added, "resource "+c+"="+r)
			}
		}
	}
	for c := range approved.Resources {
		if _, still := requested.Resources[c]; !still && slices.Contains(requested.Capabilities, c) {
			added = append(added, "resource "+c+" unconstrained")
		}
	}
	approvedModes := map[string]bool{}
	for _, mode := range approved.Credentials {
		if c, ok := CanonicalCredentialMode(mode); ok {
			approvedModes[c] = true
		}
	}
	for _, mode := range requested.Credentials {
		if c, ok := CanonicalCredentialMode(mode); ok && !approvedModes[c] {
			added = append(added, "credential "+c)
		}
	}
	sort.Strings(added)
	return added
}

// CompareVersions orders two MAJOR.MINOR.PATCH versions (-1, 0, 1).
func CompareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3 && i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}
