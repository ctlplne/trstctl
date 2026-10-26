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
// into: trstctl-<first eight characters of the destination ID>-j<job ID>. The
// key exists before its certificate, so it cannot carry the certificate
// fingerprint the way deployed certificate objects do. Both halves are known to
// the relay when it claims the job and to the control plane when a rollback
// names the destination and the predecessor certificate, whose issuance key
// records the job; neither depends on a routing name that can change. The
// destination ID keeps two installations driving one appliance apart.
func ApplianceKeyObjectName(targetID string, jobID int64) string {
	var short strings.Builder
	for _, r := range strings.ToLower(targetID) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') {
			short.WriteRune(r)
			if short.Len() == 8 {
				break
			}
		}
	}
	if short.Len() < 8 || jobID <= 0 {
		return ""
	}
	return "trstctl-" + short.String() + "-j" + strconv.FormatInt(jobID, 10)
}

// IsApplianceKeyObjectName reports whether name has the form
// ApplianceKeyObjectName produces, so a connector can tell an object a job's
// key was generated into from a fingerprint-named deploy object, and refuse
// any other name before it reaches an appliance query.
func IsApplianceKeyObjectName(name string) bool {
	rest, ok := strings.CutPrefix(name, "trstctl-")
	if !ok {
		return false
	}
	short, job, ok := strings.Cut(rest, "-j")
	if !ok || len(short) != 8 {
		return false
	}
	for _, r := range short {
		if (r < '0' || r > '9') && (r < 'a' || r > 'z') {
			return false
		}
	}
	id, err := strconv.ParseInt(job, 10, 64)
	return err == nil && id > 0 && strconv.FormatInt(id, 10) == job
}

// applianceKeyFamilies is the census of appliance connectors that generate the
// subject key on the appliance. Like the rollback and readback censuses it is
// checked against the code in both directions: a family listed here must
// implement ApplianceKeyGenerator, and one that implements it must be listed.
var applianceKeyFamilies = []string{
	"a10",
	"f5",
	"netscaler",
	"paloalto",
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

// ErrApplianceKeyAlreadyInstalled is returned when the object a job's key was
// generated into already holds the job's certificate and the appliance kept no
// CSR beside it (PAN-OS replaces a pending request with the certificate
// imported for it). The control plane signs one CSR per job, so a reclaimed job
// cannot ask for another; it stops instead of generating a second key.
var ErrApplianceKeyAlreadyInstalled = errors.New("connector: the appliance already installed a certificate for this job's key")

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
