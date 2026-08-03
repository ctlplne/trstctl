// SPDX-License-Identifier: MPL-2.0

package transport

import (
	"errors"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
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
const receiptStatementVersion = "trstctl-agent-job-receipt/v1"

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
	b.WriteString(receiptStatementVersion)
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
	for _, v := range []string{s.TenantID, s.AgentCommonName, s.Outcome, s.EvidenceDigest, s.DetailDigest} {
		if strings.ContainsAny(v, "\n\r") {
			return ErrReceiptStatementInvalid
		}
	}
	return nil
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
