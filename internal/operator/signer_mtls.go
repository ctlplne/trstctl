// SPDX-License-Identifier: BUSL-1.1

package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// The isolated signer's mutually pinned channel needs one Secret per end, each
// holding tls.crt, tls.key, peer-ca.pem and peer-pin. When the spec names
// neither Secret, the operator mints a cross-pinned pair into <cr>-signer-mtls
// and <cr>-cp-signer-mtls, owned by the control plane, and mints a new pair
// before the old one expires. Secrets the spec names, or that someone else
// created at the default names, are used as provided and only checked. Either
// way a fingerprint of both pins rides on both pod templates, so a new pair
// rolls the control plane and the signer together.

const (
	signerMTLSTTL                   = 365 * 24 * time.Hour
	signerMTLSRenewBefore           = 30 * 24 * time.Hour
	signerMTLSServerNameAnnotation  = "trstctl.com/signer-mtls-server-name"
	signerMTLSFingerprintAnnotation = "trstctl.com/signer-mtls"
)

var signerMTLSKeys = []string{"tls.crt", "tls.key", "peer-ca.pem", "peer-pin"}

// signerMTLSEnd is one end's Secret as the operator read it. The private key
// is checked for presence only and never kept.
type signerMTLSEnd struct {
	name       string
	exists     bool
	owned      bool
	serverName string
	cert       []byte
	peerPin    string
	missing    []string
}

func (r *Reconciler) readSignerMTLSEnd(ctx context.Context, namespace, name, cr string) (signerMTLSEnd, error) {
	end := signerMTLSEnd{name: name}
	st, body, err := r.client.do(ctx, http.MethodGet, secretItemPath(namespace, name), "", nil)
	defer secret.Wipe(body)
	if err != nil {
		return end, err
	}
	if st == http.StatusNotFound {
		return end, nil
	}
	if st/100 != 2 {
		return end, fmt.Errorf("operator: get Secret %s/%s: status %d", namespace, name, st)
	}
	var live struct {
		Metadata struct {
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Data map[string][]byte `json:"data"`
	}
	if err := json.Unmarshal(body, &live); err != nil {
		return end, fmt.Errorf("operator: decode Secret %s/%s: %w", namespace, name, err)
	}
	secret.Wipe(live.Data["tls.key"])
	end.exists = true
	end.owned = live.Metadata.Labels[managedByLabel] == managedByOperator && live.Metadata.Labels[ownerLabel] == cr
	end.serverName = live.Metadata.Annotations[signerMTLSServerNameAnnotation]
	end.cert = live.Data["tls.crt"]
	end.peerPin = strings.TrimSpace(string(live.Data["peer-pin"]))
	for _, key := range signerMTLSKeys {
		if len(live.Data[key]) == 0 {
			end.missing = append(end.missing, key)
		}
	}
	return end, nil
}

// ensureSignerMTLS makes both ends' Secrets usable and returns the fingerprint
// of their pins and what it did. Provided material that is missing or
// incomplete blocks the control plane with the reason rather than render pods
// that cannot authenticate each other.
func (r *Reconciler) ensureSignerMTLS(ctx context.Context, namespace string, cr controlPlaneObject) (string, Action, error) {
	serverName := r.signerMTLSServerName(namespace, cr)
	signerEnd, err := r.readSignerMTLSEnd(ctx, namespace, signerMTLSSecret(cr), cr.Metadata.Name)
	if err != nil {
		return "", ActionNone, err
	}
	cpEnd, err := r.readSignerMTLSEnd(ctx, namespace, controlPlaneMTLSSecret(cr), cr.Metadata.Name)
	if err != nil {
		return "", ActionNone, err
	}
	named := strings.TrimSpace(cr.Spec.Signer.MTLS.SignerSecret) != "" || strings.TrimSpace(cr.Spec.Signer.MTLS.ControlPlaneSecret) != ""
	generated := !named && (!signerEnd.exists || signerEnd.owned) && (!cpEnd.exists || cpEnd.owned)
	if !generated {
		for _, end := range []signerMTLSEnd{signerEnd, cpEnd} {
			if !end.exists {
				return "", ActionNone, fmt.Errorf("operator: signer mTLS Secret %s/%s does not exist; create it with %s, or name neither Secret in spec.signer.mtls and remove any you created at the default names, and the operator generates the pair",
					namespace, end.name, strings.Join(signerMTLSKeys, ", "))
			}
			if len(end.missing) > 0 {
				return "", ActionNone, fmt.Errorf("operator: signer mTLS Secret %s/%s is missing %s", namespace, end.name, strings.Join(end.missing, ", "))
			}
		}
		return signerMTLSFingerprint(signerEnd.peerPin, cpEnd.peerPin), ActionNone, nil
	}
	action := ActionNone
	switch {
	case !signerEnd.exists && !cpEnd.exists:
		action = ActionCreate
	case signerMTLSPairNeedsMinting(signerEnd, cpEnd, serverName, time.Now()):
		action = ActionUpdate
	}
	if action == ActionNone {
		return signerMTLSFingerprint(signerEnd.peerPin, cpEnd.peerPin), ActionNone, nil
	}
	pair, err := mtls.GenerateSignerPeerPEM(serverName, signerMTLSTTL)
	if err != nil {
		return "", action, err
	}
	defer pair.Wipe()
	for _, write := range []struct {
		end              signerMTLSEnd
		cert, key, pin   []byte
		component, label string
	}{
		{signerEnd, pair.SignerCert, pair.SignerKey, []byte(pair.ControlPlanePinHex), "signer", "signer"},
		{cpEnd, pair.ControlPlaneCert, pair.ControlPlaneKey, []byte(pair.SignerPinHex), "control-plane", "control plane"},
	} {
		if err := r.writeSignerMTLSEnd(ctx, namespace, cr, write.end, serverName, write.component, map[string][]byte{
			"tls.crt": write.cert, "tls.key": write.key, "peer-ca.pem": pair.CA, "peer-pin": write.pin,
		}); err != nil {
			return "", action, fmt.Errorf("operator: write the %s end of the signer mTLS pair: %w", write.label, err)
		}
	}
	return signerMTLSFingerprint(pair.ControlPlanePinHex, pair.SignerPinHex), action, nil
}

// signerMTLSPairNeedsMinting reports whether operator-owned material must be
// replaced: an end is missing or incomplete, it was minted for another server
// name, the two ends no longer pin each other, or a leaf expires within the
// renewal window.
func signerMTLSPairNeedsMinting(signerEnd, cpEnd signerMTLSEnd, serverName string, now time.Time) bool {
	if !signerEnd.exists || !cpEnd.exists || len(signerEnd.missing) > 0 || len(cpEnd.missing) > 0 {
		return true
	}
	if signerEnd.serverName != serverName {
		return true
	}
	signerPin, err := mtls.PinPEM(signerEnd.cert)
	if err != nil || cpEnd.peerPin != signerPin {
		return true
	}
	cpPin, err := mtls.PinPEM(cpEnd.cert)
	if err != nil || signerEnd.peerPin != cpPin {
		return true
	}
	for _, cert := range [][]byte{signerEnd.cert, cpEnd.cert} {
		notAfter, err := mtls.CertNotAfterUnix(cert)
		if err != nil || now.Add(signerMTLSRenewBefore).Unix() >= notAfter {
			return true
		}
	}
	return false
}

// writeSignerMTLSEnd creates or replaces one end's Secret. The request body
// carries the key and is wiped once sent.
func (r *Reconciler) writeSignerMTLSEnd(ctx context.Context, namespace string, cr controlPlaneObject, end signerMTLSEnd, serverName, component string, data map[string][]byte) error {
	meta := ownedMetadata(namespace, end.name, cr, component)
	meta["annotations"] = map[string]any{signerMTLSServerNameAnnotation: serverName}
	method, path := http.MethodPost, secretCollectionPath(namespace)
	contentType := ""
	var body []byte
	var err error
	if end.exists {
		method, path, contentType = http.MethodPatch, secretItemPath(namespace, end.name), "application/merge-patch+json"
		body, err = json.Marshal(map[string]any{"metadata": meta, "data": data})
	} else {
		body, err = json.Marshal(map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": meta, "data": data})
	}
	defer secret.Wipe(body)
	if err != nil {
		return err
	}
	st, response, err := r.client.do(ctx, method, path, contentType, body)
	secret.Wipe(response)
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("%s Secret %s/%s: status %d", strings.ToLower(method), namespace, end.name, st)
	}
	return nil
}

// signerMTLSFingerprint changes whenever either end's key does.
func signerMTLSFingerprint(signerPeerPin, controlPlanePeerPin string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(signerPeerPin + "/" + controlPlanePeerPin))
	return fmt.Sprintf("%016x", h.Sum64())
}
