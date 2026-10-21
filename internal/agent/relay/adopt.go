// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"encoding/json"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Adopting an installed predecessor (A45).
//
// A host that served a certificate before trstctl's first deploy, or whose
// agent was re-enrolled and lost its ledger, had nothing to roll back to until
// a second deploy landed. The agent now reads the pair the host already serves
// before its first deploy to a target and, once that deploy and its own record
// are durable, keeps it as the retained predecessor. The read happens inside
// the host profile's allowed roots like every other host read; nothing leaves
// the host.

type adoptablePredecessor struct {
	ok          bool
	fingerprint string
	certPEM     []byte
	keyPEM      []byte
}

func (a *adoptablePredecessor) wipe() {
	if a == nil {
		return
	}
	secret.Wipe(a.keyPEM)
	a.keyPEM, a.certPEM, a.ok = nil, nil, false
}

// readAdoptablePredecessor returns the installed pair when this is the agent's
// first deploy to the target, the family has an exact file layout and the
// installed leaf differs from the one about to be deployed. Every other case
// returns an empty value; adoption is best effort and never blocks a deploy.
func readAdoptablePredecessor(profile connector.LocalOpsConfig, ledger *HostRollbackStore, hostJob bool, intent DeployIntent) *adoptablePredecessor {
	out := &adoptablePredecessor{}
	if !hostJob || ledger == nil || strings.TrimSpace(intent.TargetID) == "" || len(intent.TargetConfig) == 0 ||
		!SupportsPQCCertificatePredecessor(intent.Connector) {
		return out
	}
	if has, err := ledger.HasState(intent.Connector, intent.TargetID); err != nil || has {
		return out
	}
	var target HostTargetConfig
	if err := json.Unmarshal(intent.TargetConfig, &target); err != nil {
		return out
	}
	certPEM, keyPEM, err := readInstalledHostPredecessor(profile, intent.Connector, target)
	if err != nil {
		return out
	}
	info, err := certinfo.Inspect(certPEM)
	if err != nil || sameHostRollbackFingerprint(info.SHA256Fingerprint, intent.Fingerprint) {
		secret.Wipe(keyPEM)
		return out
	}
	out.ok, out.fingerprint, out.certPEM, out.keyPEM = true, strings.ToLower(info.SHA256Fingerprint), certPEM, keyPEM
	return out
}
