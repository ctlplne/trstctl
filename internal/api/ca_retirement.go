// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
)

// The CA-key retirement checklist (epic H4).
//
// The VDEC engine under internal/decommission already refuses to destroy a key while
// any dependent is unaccounted for, and mints an offline-verifiable destruction
// record when they are. What it had no way to do was TELL anyone: an operator
// asking "why can I not retire this key" had to read logs, and one asking "is it
// safe yet" had no surface at all.
//
// That gap matters more than a missing screen usually would. A retirement gate
// nobody can see is a gate people route around — they raise a ticket, someone
// with signer access destroys the key by hand, and the evidence chain the whole
// feature exists to produce never gets written. The checklist is what makes the
// refusal legible enough to be worth respecting.

// RetirementDependent is one thing still standing between a key and destruction.
type RetirementDependent struct {
	// Kind and Ref identify the dependent in the operator's own vocabulary —
	// a certificate fingerprint, an identity, a trust store — so the checklist
	// reads as a to-do list rather than as opaque ids.
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
	// Detail says what would resolve it.
	Detail string `json:"detail,omitempty"`
}

// RetirementChecklist is the served answer to "can this key be destroyed yet".
type RetirementChecklist struct {
	KeyID string `json:"key_id"`
	// Blocked is the headline, and it is stated as a fact rather than a score.
	// A key is destroyable or it is not; a readiness percentage would invite
	// somebody to decide that 98% is close enough for an irreversible act.
	Blocked bool `json:"blocked"`
	// Outstanding are the dependents with no re-protection or release evidence.
	Outstanding []RetirementDependent `json:"outstanding"`
	// Accounted is how many dependents have evidence, so the checklist shows
	// progress without implying the remainder is optional.
	Accounted int `json:"accounted"`
	Total     int `json:"total"`
	// DestructionRecord is present only once destruction has happened. Its
	// absence is not a failure state — most keys are alive.
	DestructionRecord string `json:"destruction_record,omitempty"`
	// RetirementStatus is pending, refused, or destroyed once an explicitly
	// authorized command exists. RefusalRecord is the signer's public signed
	// proof that the frozen dependency set was not empty.
	RetirementStatus string `json:"retirement_status,omitempty"`
	RefusalRecord    string `json:"refusal_record,omitempty"`
	Guidance         string `json:"guidance"`
}

// RetirementChecklistSource is the licensed seam that answers the checklist.
//
// An interface rather than a direct call because internal/api is MPL core and
// may never import ee/ (AN-9). Nil means the licensed feature is not attached,
// and the route then refuses rather than reporting an empty checklist — an
// unlicensed deployment showing "0 outstanding dependents" would read as
// permission to destroy a key, which is the worst possible way for a licence
// check to fail.
type RetirementChecklistSource interface {
	RetirementChecklist(r *http.Request, tenantID, keyID string) (RetirementChecklist, error)
}

const retirementGuidance = "This key cannot be destroyed while any dependent lacks evidence that it " +
	"was re-protected under a successor or deliberately released. Destruction is irreversible and the " +
	"refusal is enforced in the isolated signer, not here — this page explains it. Each outstanding " +
	"row is something to migrate, revoke, or release; when the list is empty the signer will mint a " +
	"destruction record binding the key id, the final epoch, the evidence digest and the audit-chain " +
	"head, verifiable offline without this system."

// getCARetirementChecklist serves the outstanding dependents for a CA key.
func (a *API) getCARetirementChecklist(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if reason, unavailable := retirementUnavailable(a.retirementChecklist); unavailable {
		a.writeError(w, errStatus(http.StatusNotImplemented, reason))
		return
	}
	keyID := r.PathValue("id")
	if keyID == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "key id is required"))
		return
	}
	list, err := a.retirementChecklist.RetirementChecklist(r, tenantID, keyID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if list.Outstanding == nil {
		list.Outstanding = []RetirementDependent{}
	}
	list.KeyID = keyID
	list.Blocked = len(list.Outstanding) > 0
	list.Guidance = retirementGuidance
	a.writeJSON(w, http.StatusOK, list)
}

// retirementUnavailable reports whether the checklist can be produced at all.
//
// Split out so the failure DIRECTION is testable without standing up a server:
// it is the only property of this surface that really matters. An unlicensed
// deployment must refuse rather than return an empty outstanding list, because
// an empty list reads as "this key has no dependents" — permission to perform an
// irreversible act on evidence that was never gathered.
func retirementUnavailable(src RetirementChecklistSource) (string, bool) {
	if src != nil {
		return "", false
	}
	return "verifiable decommission is not licensed on this deployment, so no retirement " +
		"checklist can be produced; this is not a statement that the key has no dependents", true
}
