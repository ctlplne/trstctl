// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/ee/agentid/taskenv"
)

// taskenvelope.go is the AGID-05 extension of the in-signer gate: when a delegation
// record references a task envelope (its TaskDigest is set), the gate verifies the
// referenced envelope's SIGNATURE and EXPIRY as a PRECONDITION of the key operation
// (claim 2 / INV-A4), reusing the AGID-04b refusal path on failure (zero key ops), and
// requires the referenced envelope's canonical digest to equal the record's TaskDigest.
// The verified digest is then bound into the credential ALONGSIDE the chain-head digest
// and the agent-stack representation (INV-A3 additive; see bind.go).
//
// The envelope travels opaquely in PreconditionsBody.Envelope (wire.go), exactly as the
// chain, subject repr, and attestation do. The gate treats it as untrusted input and
// re-verifies it cryptographically inside the boundary. This file adds NO new core
// signing option: it extends the existing AGID-04a WithIssuanceGate seam the gate is
// already attached through. The envelope model, canonical digest, and pure
// signature/expiry verification live in ee/agentid/taskenv (which imports only
// internal/crypto, so the isolated signer stays datastore-free, AN-4).

// CheckTaskEnvelope is the failed-check identifier a refusal cites when the referenced
// task envelope fails verification (missing/expired/bad-signature/digest-mismatch/
// unresolved requester). It names WHICH pre-keygen check failed without leaking the
// envelope contents, matching the diagnostic style of the other Check* identifiers.
const CheckTaskEnvelope = "task_envelope"

// Task-envelope gate errors (surfaced as refusal detail, never leaking secrets).
var (
	// ErrDecodeTaskEnvelope is returned when the opaque envelope body cannot be decoded.
	ErrDecodeTaskEnvelope = fmt.Errorf("delegation: cannot decode task envelope body")
	// ErrTaskEnvelopeMissing is returned when a record references a task envelope (its
	// TaskDigest is set) but no envelope was carried over the seam. Fail-closed: a
	// dangling reference cannot be silently ignored.
	ErrTaskEnvelopeMissing = fmt.Errorf("delegation: record references a task envelope but none was supplied")
	// ErrTaskEnvelopeDigestMismatch is returned when the supplied envelope's canonical
	// digest does not equal the record's referenced TaskDigest (a substituted envelope).
	ErrTaskEnvelopeDigestMismatch = fmt.Errorf("delegation: supplied task envelope digest does not match the record's reference")
	// ErrNoTaskEnvelopeTrust is returned when a record references a task envelope but the
	// gate holds no task-envelope trust lookup to resolve the requester key. Fail-closed:
	// a referenced envelope must be verifiable; a gate that cannot verify one refuses.
	ErrNoTaskEnvelopeTrust = fmt.Errorf("delegation: no task-envelope trust lookup configured to verify a referenced envelope")
)

// EncodeTaskEnvelope serializes a task envelope for carriage in
// PreconditionsBody.Envelope (the opaque seam bytes). JSON, matching the rest of the
// seam carriage.
func EncodeTaskEnvelope(env taskenv.Envelope) ([]byte, error) { return json.Marshal(env) }

// decodeTaskEnvelope deserializes a task envelope from the opaque body fail-closed.
func decodeTaskEnvelope(b []byte) (taskenv.Envelope, error) {
	var env taskenv.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return taskenv.Envelope{}, fmt.Errorf("%w: %v", ErrDecodeTaskEnvelope, err)
	}
	return env, nil
}

// verifyTaskEnvelope is the AGID-05 in-signer precondition (claim 2 / INV-A4). It runs
// INSIDE verify(), AFTER the chain has verified (so the head record's TaskDigest is a
// verified, signed value) and BEFORE the binding is assembled / any key op is reached.
// Semantics, fail-closed:
//
//   - headTaskDigest empty (no record references an envelope): nothing to verify; the
//     returned digest is empty and the gate binds no task digest (no regression: the
//     AGID-04b path is exactly preserved).
//   - headTaskDigest set: an envelope MUST be supplied (else ErrTaskEnvelopeMissing);
//     its canonical digest MUST equal headTaskDigest (else digest mismatch); its
//     signature + expiry MUST verify via taskenv against the requester key resolved
//     through the gate's trust lookup (else the taskenv error). On success the verified
//     envelope digest (== headTaskDigest) is returned to be bound.
//
// Any refusal names CheckTaskEnvelope. It performs NO key op.
func (g *Gate) verifyTaskEnvelope(headTaskDigest, envelopeBody []byte, now time.Time) verifyResult {
	if len(headTaskDigest) == 0 {
		// No record references a task envelope: the extension is inert. (If a stray
		// envelope was supplied without a reference, it is simply ignored -- there is no
		// record commitment to verify it against, and binding an unreferenced envelope
		// would be meaningless. The reference is what makes it load-bearing.)
		return verifyResult{}
	}
	if len(envelopeBody) == 0 {
		return refusal(CheckTaskEnvelope, -1, ErrTaskEnvelopeMissing.Error())
	}
	env, err := decodeTaskEnvelope(envelopeBody)
	if err != nil {
		return refusal(CheckTaskEnvelope, -1, err.Error())
	}
	// The referenced digest MUST equal the supplied envelope's canonical digest: a
	// substituted (even validly-signed) envelope cannot be bound in place of the one the
	// signed record committed to.
	envDigest, err := env.Digest()
	if err != nil {
		return refusal(CheckTaskEnvelope, -1, "task envelope digest computation failed")
	}
	if !bytesEqual(envDigest, headTaskDigest) {
		return refusal(CheckTaskEnvelope, -1, ErrTaskEnvelopeDigestMismatch.Error())
	}
	// Signature + expiry verified inside the boundary (claim 2). The requester key is
	// resolved through the gate's trust lookup; a gate with no lookup cannot verify a
	// referenced envelope and fails closed.
	if g.cfg.TaskEnvelopeTrust == nil {
		return refusal(CheckTaskEnvelope, -1, ErrNoTaskEnvelopeTrust.Error())
	}
	if err := taskenv.VerifySignatureAndExpiry(env, now, taskenv.TrustLookup(g.cfg.TaskEnvelopeTrust)); err != nil {
		return refusal(CheckTaskEnvelope, -1, err.Error())
	}
	// The verified envelope digest (== the record's reference) is what the credential
	// binds, alongside the chain-head + agent-stack representation.
	return verifyResult{chainHead: append([]byte(nil), envDigest...)}
}

// headTaskDigest returns the TaskDigest the chain head references, or nil when the chain
// is empty or the head references no envelope. The head is the last (leaf) hop -- the
// record the credential is being issued for. Only the head's reference gates issuance:
// an ancestor's own task envelope (if any) governed that ancestor's issuance, not this
// leaf's.
func headTaskDigest(chain []RecordEnvelope) []byte {
	if len(chain) == 0 {
		return nil
	}
	return chain[len(chain)-1].Record.TaskDigest
}
