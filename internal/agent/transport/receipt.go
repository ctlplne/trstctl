// SPDX-License-Identifier: BUSL-1.1

package transport

import (
	"errors"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/custody"
)

// The canonical job receipt statement (epic A1).
//
// A signature is only as good as the agreement on what was signed. If the two
// sides build the bytes differently — one joins with a comma, the other with a
// newline; one includes the attempt, the other forgot — every signature fails
// and the failure looks like an attack. So the statement is built HERE, once,
// by both sides, from the same function.
//
// What goes in is chosen by one rule: the server must already know the value,
// independently of the report. The tenant and the agent name come from the
// certificate the caller authenticated with, never from a request field. That
// is what makes the signature a binding rather than a decoration — an attacker
// who could name the tenant in the statement could sign for any tenant they
// liked with their own valid agent key.
//
// Free-text detail is included as a DIGEST, not as text. The statement stays
// bounded regardless of how much an agent has to say about a failure, and the
// text is still committed to: an operator reading a receipt can prove the
// failure message they are looking at is the one the agent signed.

// receiptStatementVersion prefixes every statement. A future change to the
// field set changes this line, so an old signature can never be mistaken for a
// new statement's — it simply fails to verify, which is the correct outcome.
const (
	receiptStatementVersionV1 = "trstctl-agent-job-receipt/v1"
	receiptStatementVersionV2 = "trstctl-agent-job-receipt/v2"
	// v3 adds the adopted pre-trstctl predecessor a host agent retained on its
	// first deploy to a target (A45). Absent, the v1/v2 bytes are unchanged.
	receiptStatementVersionV3 = "trstctl-agent-job-receipt/v3"
)

// JobReceiptStatement is everything a receipt commits to.
type JobReceiptStatement struct {
	// TenantID and AgentCommonName come from the peer certificate on the
	// server side and from the agent's own identity on the agent side. They are
	// never taken from the request body.
	TenantID        string
	AgentCommonName string
	JobID           int64
	// Attempt is the claim generation. Without it, a receipt for attempt 1
	// could be replayed against attempt 2 of the same job after a lease lapse
	// and a requeue — the same job id, a different piece of work.
	Attempt int
	Outcome string
	// EvidenceDigest binds the receipt to whatever transcript the agent kept.
	EvidenceDigest string
	// DetailDigest commits to the operator-facing text without carrying it.
	DetailDigest string
	// CredentialFingerprint and Custody turn a successful agent-generated
	// issuance into a per-certificate custody attestation (B5). They are absent
	// on every non-issuance job, preserving the v1 statement byte-for-byte.
	CredentialFingerprint string
	Custody               custody.Record
	// AdoptedPredecessorFingerprint names the pair the agent found installed
	// before its first deploy to the target and retained as the rollback
	// predecessor (A45). Signed, so the control plane's rollback evidence
	// rests on the agent's attestation rather than on an unsigned body field.
	AdoptedPredecessorFingerprint string
	// IssuedAtUnix is when the agent signed. The server bounds it against its
	// own clock so an old signed receipt cannot be held and replayed later.
	IssuedAtUnix int64
}

// Canonical renders the statement as the exact bytes that get signed.
//
// One field per line, in a fixed order, each written as name=value. Line-based
// rather than JSON on purpose: JSON has more than one correct rendering of the
// same value (key order, integer formatting, escaping), and "more than one
// correct rendering" is how canonicalization bugs become signature failures
// nobody can reproduce.
//
// Values cannot contain a newline — Validate refuses them — so a value can
// never fake a field boundary.
func (s JobReceiptStatement) Canonical() []byte {
	var b strings.Builder
	b.WriteString(s.version())
	b.WriteByte('\n')
	write := func(name, value string) {
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(value)
		b.WriteByte('\n')
	}
	write("tenant", s.TenantID)
	write("agent", s.AgentCommonName)
	write("job", strconv.FormatInt(s.JobID, 10))
	write("attempt", strconv.Itoa(s.Attempt))
	write("outcome", s.Outcome)
	write("evidence", s.EvidenceDigest)
	write("detail", s.DetailDigest)
	if s.hasCustody() {
		write("credential_fingerprint", s.CredentialFingerprint)
		write("key_origin", string(s.Custody.Origin))
		write("key_storage", string(s.Custody.Storage))
		write("key_exportable", string(s.Custody.Exportable))
		write("key_generated_by", s.Custody.GeneratedBy)
	}
	if s.AdoptedPredecessorFingerprint != "" {
		write("adopted_predecessor", s.AdoptedPredecessorFingerprint)
	}
	write("issued_at", strconv.FormatInt(s.IssuedAtUnix, 10))
	return []byte(b.String())
}

// ErrReceiptStatementInvalid is returned for a statement that cannot be
// canonicalized unambiguously.
var ErrReceiptStatementInvalid = errors.New("transport: job receipt statement is not canonicalizable")

// Validate refuses a statement whose fields would make the canonical form
// ambiguous or empty.
//
// The newline check is the one that matters: a tenant id containing a newline
// could otherwise write its own "outcome=executed" line into the statement, and
// the signature would be perfectly valid over bytes that mean something other
// than what the struct says.
func (s JobReceiptStatement) Validate() error {
	if strings.TrimSpace(s.TenantID) == "" {
		return errors.New("transport: receipt statement has no tenant")
	}
	if strings.TrimSpace(s.AgentCommonName) == "" {
		return errors.New("transport: receipt statement has no agent")
	}
	if s.JobID <= 0 {
		return errors.New("transport: receipt statement has no job")
	}
	if strings.TrimSpace(s.Outcome) == "" {
		return errors.New("transport: receipt statement has no outcome")
	}
	if s.hasCustody() {
		if strings.TrimSpace(s.CredentialFingerprint) == "" || !s.Custody.Complete() ||
			!custody.ValidOrigin(s.Custody.Origin) || !custody.ValidStorage(s.Custody.Storage) ||
			!custody.ValidExportability(s.Custody.Exportable) {
			return errors.New("transport: receipt statement has incomplete credential custody")
		}
	}
	if s.AdoptedPredecessorFingerprint != "" && !validLowerHexFingerprint(s.AdoptedPredecessorFingerprint) {
		return errors.New("transport: receipt statement's adopted predecessor is not a SHA-256 fingerprint")
	}
	for _, v := range []string{
		s.TenantID, s.AgentCommonName, s.Outcome, s.EvidenceDigest, s.DetailDigest,
		s.CredentialFingerprint, string(s.Custody.Origin), string(s.Custody.Storage),
		string(s.Custody.Exportable), s.Custody.GeneratedBy, s.AdoptedPredecessorFingerprint,
	} {
		if strings.ContainsAny(v, "\n\r") {
			return ErrReceiptStatementInvalid
		}
	}
	return nil
}

func (s JobReceiptStatement) hasCustody() bool {
	return s.CredentialFingerprint != "" || s.Custody.Recorded() || s.Custody.GeneratedBy != ""
}

func (s JobReceiptStatement) version() string {
	if s.AdoptedPredecessorFingerprint != "" {
		return receiptStatementVersionV3
	}
	if s.hasCustody() {
		return receiptStatementVersionV2
	}
	return receiptStatementVersionV1
}

func validLowerHexFingerprint(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, r := range v {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// DetailDigest is the commitment to a report's operator-facing text.
//
// Empty detail digests to the empty string rather than to the hash of nothing:
// "the agent said nothing" and "the agent said something that happens to hash
// to e3b0c442..." should not render identically in a receipt an operator reads.
//
// Hashing goes through internal/crypto like every other hash in this codebase
// (AN-3) — there is no such thing as a hash that is too small to belong behind
// the boundary, because the boundary is what makes the inventory of primitives
// complete.
func DetailDigest(detail string) string {
	if detail == "" {
		return ""
	}
	return crypto.SHA256Hex([]byte(detail))
}

// Closed-set rollback failure reasons (epic D4).
//
// A relay's failure detail is not free text — it is one of these — because the
// control plane classifies it into a served status, and a status must never
// claim more than happened. The specific thing that must not be claimed is
// CONTACT: five of these reasons are refusals the relay makes before it opens a
// socket, and recording them as "the attempt ran against the target" would tell
// an operator the appliance rejected something it never heard about.
//
// The set lives here, in the wire contract, for the same reason the canonical
// receipt statement does: the side that emits these and the side that
// interprets them cannot be allowed to drift.
const (
	// Refusals made locally, before any connection to the target.
	RollbackRefusedBadPayload               = "job payload is not a rollback intent"
	RollbackRefusedNotExecutable            = "connector is not executable by this agent"
	RollbackRefusedCannotRebind             = "this connector cannot roll back by re-binding"
	RollbackRefusedNoPredecessor            = "no predecessor is recorded for this target"
	RollbackRefusedNoCredential             = "credential redemption was not granted" // #nosec G101 -- an operator-facing refusal phrase matching the secret-name heuristic; no credential value present (CWE-798)
	RollbackRefusedNoLockedMemory           = "redeemed material could not be taken into locked memory"
	RollbackRefusedNoHostRestore            = "this host connector has no local restore runner"
	RollbackRefusedNoHostState              = "this agent has no host predecessor store configured"
	RollbackRefusedNoHostProfile            = "this agent has no host exec profile configured for restore and reload"
	RollbackRefusedHostPredecessorMissing   = "the requested predecessor is not retained on this host agent"
	RollbackRefusedHostStateUnavailable     = "host predecessor state could not be opened on this agent"
	RollbackRefusedAuthorization            = "control plane no longer authorizes this rollback attempt"
	RollbackRefusedAuthorizationUnavailable = "current rollback authorization could not be checked"
	// A denied capability means the sandbox blocked the operation — including,
	// for a network connector, the dial itself. It is classified as no-contact
	// because claiming contact on a blocked dial would be the same lie.
	RollbackRefusedCapability = "connector attempted an operation outside its declared capabilities"

	// Failures that happened AGAINST the target: the relay reached it.
	RollbackFailedPredecessorGone = "the predecessor certificate is no longer installed on the target"
	RollbackFailedAtTarget        = "connector rollback failed against the target"
)

// RollbackExecutedLegacyObject is the executed-report detail a relay sends when
// no fingerprint-named predecessor existed and the re-bind went to the object
// installed under the target-derived name from before fingerprint naming
// (A45). Its contents were not re-read; the listener must be verified.
const RollbackExecutedLegacyObject = "re-bound to the legacy target-named object; its contents were not re-read"

// Right-size refusals and failures (A64) follow the same contact discipline:
// the first three are decided before the entitlement endpoint is contacted.
const (
	RightSizeRefusedBadPayload   = "job payload is not a right-size intent"
	RightSizeRefusedNoCredential = "entitlement credential redemption was not granted" // #nosec G101 -- an operator-facing refusal phrase matching the secret-name heuristic; no credential value present (CWE-798)
	RightSizeRefusedNoEndpoint   = "no entitlement endpoint was redeemed for this attempt"
	RightSizeFailedAtEndpoint    = "entitlement mutation or readback failed at the endpoint"
)

// Takedown refusals and failures (A43) follow the same contact discipline.
const (
	TakedownRefusedBadPayload    = "job payload is not a takedown intent"
	TakedownRefusedUnsupported   = "this connector cannot remove an installed object by name"
	TakedownRefusedNoFingerprint = "no fingerprint names the object to remove"
	TakedownFailedAtTarget       = "connector takedown failed against the target"
)

// TakedownReasonContactedTarget reports whether a takedown failure reason
// means the relay actually reached the appliance. Unknown reasons answer
// false, the fail-closed direction.
func TakedownReasonContactedTarget(reason string) bool {
	return reason == TakedownFailedAtTarget
}

// RollbackReasonContactedTarget reports whether a rollback failure reason means
// the relay actually reached the appliance.
//
// An unrecognized reason answers FALSE. That is the fail-closed direction: an
// unknown phrase from a newer or older agent must not cause the control plane to
// assert contact it cannot substantiate.
func RollbackReasonContactedTarget(reason string) bool {
	switch reason {
	case RollbackFailedPredecessorGone, RollbackFailedAtTarget:
		return true
	default:
		return false
	}
}

// RollbackReasonIsPermanent reports whether a rollback failure will fail the same
// way on every future attempt.
//
// The claim path has no attempts predicate, so work that is requeued is retried
// on every poll — and each rollback attempt redeems an appliance credential out
// of the seal. A failure that can never succeed must therefore leave the queue,
// or the system holds credential material outside the seal forever in service of
// an operation that cannot complete.
//
// An unrecognized reason answers FALSE: retrying costs a poll cycle, whereas
// wrongly retiring work that would have succeeded loses it silently.
func RollbackReasonIsPermanent(reason string) bool {
	switch reason {
	case RollbackFailedPredecessorGone,
		RollbackRefusedBadPayload,
		RollbackRefusedNotExecutable,
		RollbackRefusedCannotRebind,
		RollbackRefusedNoPredecessor,
		RollbackRefusedNoHostRestore,
		RollbackRefusedNoHostState,
		RollbackRefusedAuthorization,
		RollbackRefusedHostPredecessorMissing:
		return true
	default:
		// Not permanent: a credential that was not granted may be granted, a
		// locked-memory failure may pass, a capability denial may be a
		// misconfiguration an operator fixes, and a failure at the target may
		// be transient.
		return false
	}
}
