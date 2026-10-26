// SPDX-License-Identifier: BUSL-1.1

package connector

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Appliance-generated keys (A122).
//
// An appliance whose management API can generate a key and return a CSR does
// not need the control plane to make its key at all. A relay asks the
// appliance to generate the key into a named object, the control plane signs
// the CSR the appliance returns, and the relay installs the certificate
// against the key the appliance already holds. No key crosses the relay or the
// control plane, so nothing has to be sealed to a deploy job.

// ApplianceKeyRequest names the certificate an appliance is asked to generate a
// key for.
type ApplianceKeyRequest struct {
	// ObjectName is the appliance object the key is generated into, from
	// ApplianceKeyObjectName. It is fixed per job, so a reclaimed job finds
	// the key and CSR its earlier attempt made instead of making another.
	ObjectName  string
	CommonName  string
	DNSNames    []string
	IPAddresses []string
}

// ApplianceKey is a key the appliance holds and the CSR that requests a
// certificate for it. It carries no key bytes: the appliance keeps those.
type ApplianceKey struct {
	ObjectName string
	CSRPEM     []byte
}

// ApplianceKeyGenerator is implemented by an appliance connector whose
// management API generates the subject key on the appliance.
//
// GenerateApplianceKey is idempotent per ObjectName: when the appliance
// already holds that object's key and CSR it returns the same CSR. It never
// reads the key back. InstallWithApplianceKey installs the signed certificate
// (dep.CertPEM, chain included; dep.KeyPEM is empty) against that key and
// binds it exactly where Deploy binds, so readback and rollback see the same
// installed object a sealed-key deploy produces.
type ApplianceKeyGenerator interface {
	GenerateApplianceKey(ctx context.Context, sb Sandbox, req ApplianceKeyRequest) (ApplianceKey, error)
	InstallWithApplianceKey(ctx context.Context, sb Sandbox, dep Deployment, key ApplianceKey) error
}

// ApplianceKeyObjectName is the appliance object a job's key is generated
// into: the target's object base and the job ID. The key exists before its
// certificate, so it cannot carry the certificate fingerprint the way deployed
// certificate objects do; the job ID is known to the relay when it claims the
// job and to the control plane from the certificate the job's CSR produced,
// which is how a rollback finds a predecessor's key again.
func ApplianceKeyObjectName(base string, jobID int64) string {
	base = strings.TrimSpace(base)
	if base == "" || jobID <= 0 {
		return ""
	}
	return base + "-j" + strconv.FormatInt(jobID, 10)
}

// applianceKeyFamilies is the census of appliance connectors that generate the
// subject key on the appliance. Like the rollback and readback censuses it is
// checked against the code in both directions: a family listed here must
// implement ApplianceKeyGenerator, and one that implements it must be listed.
var applianceKeyFamilies = []string{
	"netscaler",
}

// ApplianceKeyFamily reports whether a family can generate its subject key on
// the appliance.
func ApplianceKeyFamily(name string) bool {
	for _, n := range applianceKeyFamilies {
		if n == name {
			return true
		}
	}
	return false
}

// ApplianceKeyFamilies reports the census, sorted.
func ApplianceKeyFamilies() []string {
	out := append([]string(nil), applianceKeyFamilies...)
	sort.Strings(out)
	return out
}

// ErrApplianceKeyUnsupported is returned when a connector cannot generate its
// subject key on the appliance.
var ErrApplianceKeyUnsupported = errors.New("connector: this connector cannot generate the subject key on the appliance")

// RunApplianceKey asks the appliance for a key and CSR inside the connector's
// capability sandbox.
func RunApplianceKey(ctx context.Context, c Connector, ops Ops, req ApplianceKeyRequest) (ApplianceKey, Stats, error) {
	gen, ok := c.(ApplianceKeyGenerator)
	if !ok {
		return ApplianceKey{}, Stats{}, ErrApplianceKeyUnsupported
	}
	sb := &sandbox{ctx: ctx, grant: c.Capabilities(), ops: ops}
	key, err := gen.GenerateApplianceKey(ctx, sb, req)
	return key, Stats{Denied: sb.denied}, err
}

// RunApplianceInstall installs a certificate against an appliance-held key
// inside the connector's capability sandbox.
func RunApplianceInstall(ctx context.Context, c Connector, ops Ops, dep Deployment, key ApplianceKey) (Stats, error) {
	gen, ok := c.(ApplianceKeyGenerator)
	if !ok {
		return Stats{}, ErrApplianceKeyUnsupported
	}
	sb := &sandbox{ctx: ctx, grant: c.Capabilities(), ops: ops}
	err := gen.InstallWithApplianceKey(ctx, sb, dep, key)
	return Stats{Denied: sb.denied}, err
}
