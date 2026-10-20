// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// ReceiverReconciliation is what an independent readback of the receiver
// proves about one delivery command after its outcome was lost: the receiver
// holds exactly this command's value, provably holds something else, or the
// target cannot say (no readable state, or the readback itself failed).
type ReceiverReconciliation string

const (
	ReceiverStateUnknown ReceiverReconciliation = "unknown"
	ReceiverStateMatches ReceiverReconciliation = "matches"
	ReceiverStateDiffers ReceiverReconciliation = "differs"
)

// ReceiverReconciler is implemented by pushers whose receiver exposes the
// current value or this command's operation marker. The readback never writes
// and never returns receiver bytes to the caller: only the comparison result.
type ReceiverReconciler interface {
	ReconcileOperation(ctx context.Context, key string, value []byte) (ReceiverReconciliation, error)
}

// CapabilityReceiverReconcile marks catalog providers whose target can read its
// own state back, so a lost delivery result resolves without a second write.
const CapabilityReceiverReconcile = "receiver-reconcile"

// ReceiverReconcileReporter lets an adapter that builds its concrete pusher per
// call answer the capability question statically, from its configured type.
type ReceiverReconcileReporter interface {
	ReconcilesReceiver() bool
}

// CanReconcile reports whether this target can read the receiver back.
func (t *Target) CanReconcile() bool {
	if t == nil || t.pusher == nil {
		return false
	}
	if reporter, ok := t.pusher.(ReceiverReconcileReporter); ok {
		return reporter.ReconcilesReceiver()
	}
	_, ok := t.pusher.(ReceiverReconciler)
	return ok
}

// ReconcileOperation reads the receiver under the same stable operation ID the
// delivery used and reports whether the exact command value is present. A
// target without readback answers unknown rather than guessing.
func (t *Target) ReconcileOperation(ctx context.Context, operationID, key string, value []byte) (ReceiverReconciliation, error) {
	if t == nil || t.pusher == nil {
		return ReceiverStateUnknown, errors.New("secretsync: target is not configured")
	}
	if operationID == "" {
		return ReceiverStateUnknown, errors.New("secretsync: receiver reconciliation needs the durable operation id")
	}
	reconciler, ok := t.pusher.(ReceiverReconciler)
	if !ok || !t.CanReconcile() {
		return ReceiverStateUnknown, nil
	}
	state, err := reconciler.ReconcileOperation(WithOperationID(ctx, operationID), key, value)
	if err != nil {
		return ReceiverStateUnknown, err
	}
	return state, nil
}

// ReconcileOperation reads the KV v2 path and compares the configured field.
// A missing path or a different value proves this command's value is absent.
func (p *VaultKVV2Pusher) ReconcileOperation(ctx context.Context, key string, value []byte) (ReceiverReconciliation, error) {
	path, err := normalizedVaultPath(key, false)
	if err != nil {
		return ReceiverStateUnknown, err
	}
	state, err := p.read(ctx, path)
	if err != nil {
		return ReceiverStateUnknown, err
	}
	defer state.wipe()
	matches, err := p.valueMatches(state, value)
	if err != nil {
		return ReceiverStateUnknown, err
	}
	if matches {
		return ReceiverStateMatches, nil
	}
	return ReceiverStateDiffers, nil
}

// ReconcileOperation looks for this command's operation marker on the
// workspace variable; sensitive variable values are never readable.
func (p *TerraformCloudOpenTofuPusher) ReconcileOperation(ctx context.Context, key string, _ []byte) (ReceiverReconciliation, error) {
	existing, err := p.findVariable(ctx, key)
	if err != nil {
		return ReceiverStateUnknown, err
	}
	if existing != nil && p.isCompletedReplay(ctx, existing, p.operationDescription(ctx)) {
		return ReceiverStateMatches, nil
	}
	return ReceiverStateDiffers, nil
}

// ReconcileOperation compares the latest secret version with this command's value.
func (p *GCPSecretManagerPusher) ReconcileOperation(ctx context.Context, key string, value []byte) (ReceiverReconciliation, error) {
	matches, err := p.latestMatches(ctx, key, value)
	if err != nil {
		return ReceiverStateUnknown, err
	}
	if matches {
		return ReceiverStateMatches, nil
	}
	return ReceiverStateDiffers, nil
}

// ReconcileOperation compares the current Key Vault secret with this command's value.
func (p *AzureKeyVaultPusher) ReconcileOperation(ctx context.Context, key string, value []byte) (ReceiverReconciliation, error) {
	matches, err := p.latestMatches(ctx, key, value)
	if err != nil {
		return ReceiverStateUnknown, err
	}
	if matches {
		return ReceiverStateMatches, nil
	}
	return ReceiverStateDiffers, nil
}

// ReconcileOperation reads the Secret and compares its value field in constant time.
func (p *KubernetesPusher) ReconcileOperation(ctx context.Context, key string, value []byte) (ReceiverReconciliation, error) {
	resource := "/api/v1/namespaces/" + pathEscape(p.namespace) + "/secrets/" + pathEscape(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+resource, nil)
	if err != nil {
		return ReceiverStateUnknown, err
	}
	if token := secretBufferBytes(p.token); len(token) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	}
	var existing struct {
		Data map[string]secret.JSONBytes `json:"data"`
	}
	err = readJSON2xx(p.doer, req, &existing)
	if statusCode(err) == http.StatusNotFound {
		return ReceiverStateDiffers, nil
	}
	if err != nil {
		return ReceiverStateUnknown, err
	}
	defer func() {
		for name, item := range existing.Data {
			secret.Wipe(item)
			delete(existing.Data, name)
		}
	}()
	encoded, ok := existing.Data["value"]
	if !ok {
		return ReceiverStateDiffers, nil
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, decodeErr := base64.StdEncoding.Decode(decoded, encoded)
	if decodeErr != nil {
		secret.Wipe(decoded)
		return ReceiverStateUnknown, decodeErr
	}
	decoded = decoded[:n]
	defer secret.Wipe(decoded)
	if crypto.ConstantTimeEqual(decoded, value) {
		return ReceiverStateMatches, nil
	}
	return ReceiverStateDiffers, nil
}
